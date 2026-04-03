"""
src/sentinel/rag/knowledge_base.py

RAG (Retrieval-Augmented Generation) pipeline for agent knowledge bases.
Provides vector-based retrieval of attack techniques and defense patterns
to inject into agent prompts as grounded context.

Supports two backends:
  - ChromaDB (preferred, if installed)
  - Fallback: TF-IDF with scikit-learn (always available)
"""

import json
import logging
import os
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Check available backends
_CHROMA_AVAILABLE = False
try:
    import chromadb
    from chromadb.config import Settings
    _CHROMA_AVAILABLE = True
except ImportError:
    pass

_SKLEARN_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    pass


@dataclass
class RetrievedDocument:
    """A document retrieved from the knowledge base."""
    content: str
    metadata: Dict[str, Any]
    relevance_score: float
    source: str


class KnowledgeBase:
    """
    Vector-backed knowledge base for security intelligence.
    
    Stores and retrieves attack techniques, defense patterns,
    and security documentation for agent context enrichment.
    """

    def __init__(
        self,
        name: str,
        persist_dir: Optional[str] = None,
        backend: str = 'auto'
    ):
        """
        Initialize knowledge base.

        Args:
            name: Name of this KB (e.g., 'red_agent', 'blue_agent')
            persist_dir: Directory to persist the vector store
            backend: 'chroma', 'tfidf', or 'auto' (try chroma first)
        """
        self.name = name
        self.persist_dir = persist_dir or f"data/rag/{name}"
        self.documents: List[Dict[str, Any]] = []
        self.backend_type = self._select_backend(backend)

        if self.backend_type == 'chroma':
            self._init_chroma()
        elif self.backend_type == 'tfidf':
            self._init_tfidf()
        else:
            logger.error("No vector backend available. Install chromadb or scikit-learn.")
            self.backend_type = 'none'

        logger.info(f"KnowledgeBase '{name}' initialized with {self.backend_type} backend")

    def _select_backend(self, preference: str) -> str:
        if preference == 'chroma' and _CHROMA_AVAILABLE:
            return 'chroma'
        elif preference == 'tfidf' and _SKLEARN_AVAILABLE:
            return 'tfidf'
        elif preference == 'auto':
            if _CHROMA_AVAILABLE:
                return 'chroma'
            elif _SKLEARN_AVAILABLE:
                return 'tfidf'
        return 'none'

    def _init_chroma(self):
        """Initialize ChromaDB backend."""
        os.makedirs(self.persist_dir, exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(
            path=self.persist_dir,
            settings=Settings(anonymized_telemetry=False)
        )
        self.collection = self.chroma_client.get_or_create_collection(
            name=self.name,
            metadata={"hnsw:space": "cosine"}
        )

    def _init_tfidf(self):
        """Initialize TF-IDF fallback backend."""
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words='english',
            ngram_range=(1, 2),
        )
        self.tfidf_matrix = None
        self.tfidf_docs: List[Dict[str, Any]] = []
        self._tfidf_fitted = False

    def ingest_documents(self, documents: List[Dict[str, Any]]) -> int:
        """
        Ingest documents into the knowledge base.

        Each document should have:
          - 'content': str — the text content
          - 'metadata': dict — metadata (vulnerability_type, source, etc.)

        Args:
            documents: List of document dicts

        Returns:
            Number of documents ingested
        """
        count = 0

        for doc in documents:
            content = doc.get('content', '')
            metadata = doc.get('metadata', {})

            if not content.strip():
                continue

            doc_id = hashlib.md5(content.encode()).hexdigest()

            if self.backend_type == 'chroma':
                try:
                    self.collection.upsert(
                        ids=[doc_id],
                        documents=[content],
                        metadatas=[metadata],
                    )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to ingest document: {e}")

            elif self.backend_type == 'tfidf':
                self.tfidf_docs.append({
                    'id': doc_id,
                    'content': content,
                    'metadata': metadata,
                })
                count += 1

        # Refit TF-IDF after ingestion
        if self.backend_type == 'tfidf' and self.tfidf_docs:
            texts = [d['content'] for d in self.tfidf_docs]
            self.tfidf_matrix = self.vectorizer.fit_transform(texts)
            self._tfidf_fitted = True

        self.documents.extend(documents)
        logger.info(f"Ingested {count} documents into '{self.name}' KB")
        return count

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, str]] = None
    ) -> List[RetrievedDocument]:
        """
        Retrieve most relevant documents for a query.

        Args:
            query: Search query (vulnerability description, code context, etc.)
            top_k: Number of results to return
            filter_metadata: Optional metadata filter (e.g., {'vulnerability_type': 'sql_injection'})

        Returns:
            List of RetrievedDocument sorted by relevance
        """
        if self.backend_type == 'chroma':
            return self._retrieve_chroma(query, top_k, filter_metadata)
        elif self.backend_type == 'tfidf':
            return self._retrieve_tfidf(query, top_k, filter_metadata)
        else:
            return []

    def _retrieve_chroma(
        self, query: str, top_k: int, filter_metadata: Optional[Dict]
    ) -> List[RetrievedDocument]:
        """Retrieve using ChromaDB."""
        try:
            kwargs = {
                'query_texts': [query],
                'n_results': top_k,
            }
            if filter_metadata:
                kwargs['where'] = filter_metadata

            results = self.collection.query(**kwargs)

            retrieved = []
            for i in range(len(results['documents'][0])):
                distance = results['distances'][0][i] if results.get('distances') else 0.0
                # ChromaDB returns distances; convert to similarity
                score = 1.0 - min(distance, 1.0)

                retrieved.append(RetrievedDocument(
                    content=results['documents'][0][i],
                    metadata=results['metadatas'][0][i] if results.get('metadatas') else {},
                    relevance_score=score,
                    source=self.name,
                ))

            return retrieved

        except Exception as e:
            logger.error(f"ChromaDB retrieval failed: {e}")
            return []

    def _retrieve_tfidf(
        self, query: str, top_k: int, filter_metadata: Optional[Dict]
    ) -> List[RetrievedDocument]:
        """Retrieve using TF-IDF similarity."""
        if not self._tfidf_fitted or self.tfidf_matrix is None:
            return []

        try:
            # Filter documents by metadata if specified
            if filter_metadata:
                indices = []
                for i, doc in enumerate(self.tfidf_docs):
                    match = all(
                        doc['metadata'].get(k) == v
                        for k, v in filter_metadata.items()
                    )
                    if match:
                        indices.append(i)

                if not indices:
                    return []

                filtered_matrix = self.tfidf_matrix[indices]
                filtered_docs = [self.tfidf_docs[i] for i in indices]
            else:
                filtered_matrix = self.tfidf_matrix
                filtered_docs = self.tfidf_docs

            # Transform query
            query_vec = self.vectorizer.transform([query])

            # Compute similarities
            similarities = cosine_similarity(query_vec, filtered_matrix)[0]

            # Get top-k indices
            top_indices = np.argsort(similarities)[::-1][:top_k]

            retrieved = []
            for idx in top_indices:
                if similarities[idx] > 0.0:
                    retrieved.append(RetrievedDocument(
                        content=filtered_docs[idx]['content'],
                        metadata=filtered_docs[idx]['metadata'],
                        relevance_score=float(similarities[idx]),
                        source=self.name,
                    ))

            return retrieved

        except Exception as e:
            logger.error(f"TF-IDF retrieval failed: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        if self.backend_type == 'chroma':
            count = self.collection.count()
        elif self.backend_type == 'tfidf':
            count = len(self.tfidf_docs)
        else:
            count = 0

        return {
            'name': self.name,
            'backend': self.backend_type,
            'document_count': count,
        }


class RAGRetriever:
    """
    High-level RAG retriever that manages both Red and Blue agent knowledge bases
    and provides formatted context for prompt injection.
    """

    def __init__(self, data_dir: Optional[str] = None, backend: str = 'auto'):
        """
        Initialize RAG retriever with both agent knowledge bases.

        Args:
            data_dir: Base directory for knowledge base data files
            backend: Vector backend preference
        """
        self.data_dir = data_dir or os.path.join(
            os.path.dirname(__file__), 'data'
        )

        self.red_kb = KnowledgeBase('red_agent', backend=backend)
        self.blue_kb = KnowledgeBase('blue_agent', backend=backend)

        # Load knowledge bases from data files
        self._load_data()

    def _load_data(self):
        """Load knowledge base data from JSON files."""
        red_data_path = os.path.join(self.data_dir, 'red_agent', 'attack_knowledge.json')
        blue_data_path = os.path.join(self.data_dir, 'blue_agent', 'defense_knowledge.json')

        if os.path.exists(red_data_path):
            with open(red_data_path, 'r') as f:
                red_docs = json.load(f)
            self.red_kb.ingest_documents(red_docs)
        else:
            logger.warning(f"Red agent knowledge base not found at {red_data_path}")

        if os.path.exists(blue_data_path):
            with open(blue_data_path, 'r') as f:
                blue_docs = json.load(f)
            self.blue_kb.ingest_documents(blue_docs)
        else:
            logger.warning(f"Blue agent knowledge base not found at {blue_data_path}")

    def get_attack_context(
        self,
        code: str,
        vulnerability_type: str,
        top_k: int = 5
    ) -> str:
        """
        Retrieve relevant attack techniques for the Red Agent.

        Args:
            code: Vulnerable code being analyzed
            vulnerability_type: Type of vulnerability

        Returns:
            Formatted string to inject into Red Agent's prompt
        """
        query = f"{vulnerability_type} attack techniques for code: {code[:200]}"

        docs = self.red_kb.retrieve(
            query=query,
            top_k=top_k,
            filter_metadata={'vulnerability_type': vulnerability_type}
        )

        # Fallback: try without filter
        if not docs:
            docs = self.red_kb.retrieve(query=query, top_k=top_k)

        if not docs:
            return ""

        context_parts = [
            "=== ATTACK INTELLIGENCE (from knowledge base) ===",
        ]
        for i, doc in enumerate(docs, 1):
            context_parts.append(f"\n--- Reference {i} (relevance: {doc.relevance_score:.2f}) ---")
            context_parts.append(doc.content)

        context_parts.append("\n=== END ATTACK INTELLIGENCE ===")
        return "\n".join(context_parts)

    def get_defense_context(
        self,
        code: str,
        vulnerability_type: str,
        attack_payload: Optional[str] = None,
        top_k: int = 5
    ) -> str:
        """
        Retrieve relevant defense patterns for the Blue Agent.

        Args:
            code: Vulnerable code to patch
            vulnerability_type: Type of vulnerability
            attack_payload: The attack that succeeded (if available)

        Returns:
            Formatted string to inject into Blue Agent's prompt
        """
        query = f"{vulnerability_type} secure coding fix for: {code[:200]}"
        if attack_payload:
            query += f" blocking attack: {attack_payload[:100]}"

        docs = self.blue_kb.retrieve(
            query=query,
            top_k=top_k,
            filter_metadata={'vulnerability_type': vulnerability_type}
        )

        if not docs:
            docs = self.blue_kb.retrieve(query=query, top_k=top_k)

        if not docs:
            return ""

        context_parts = [
            "=== DEFENSE INTELLIGENCE (from knowledge base) ===",
        ]
        for i, doc in enumerate(docs, 1):
            context_parts.append(f"\n--- Reference {i} (relevance: {doc.relevance_score:.2f}) ---")
            context_parts.append(doc.content)

        context_parts.append("\n=== END DEFENSE INTELLIGENCE ===")
        return "\n".join(context_parts)

    def get_stats(self) -> Dict[str, Any]:
        """Get stats for both knowledge bases."""
        return {
            'red_agent': self.red_kb.get_stats(),
            'blue_agent': self.blue_kb.get_stats(),
        }
