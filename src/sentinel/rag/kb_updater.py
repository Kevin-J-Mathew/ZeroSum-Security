"""
src/sentinel/rag/kb_updater.py

Automated data ingestion tool to radically expand the Red and Blue Agent 
knowledge bases by dynamically downloading and chunking real-world datasets 
(e.g., SecLists for Red, CWE database for Blue).
"""

import os
import sys
import csv
import io
import json
import logging
import requests
import zipfile
from typing import Dict, List, Any

# Ensure we can import the sentinel packages
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.sentinel.rag.knowledge_base import KnowledgeBase

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("kb_updater")

# --- DATA SOURCES ---

RED_SOURCES = {
    'sql_injection': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt',
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt',
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt',
    ],
    'xss': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-RSNAKE.txt',
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt',
    ],
    'command_injection': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt',
    ],
    'path_traversal': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt',
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt',
    ],
    'xxe': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Fuzzing.txt',
    ],
    'ssrf': [
        'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md',
    ],
    'nosql_injection': [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/NoSQL.txt',
    ],
    'ssti': [
        'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md',
    ],
}

# The official MITRE CWE CSV archive (Contains descriptions and mitigations)
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"


class KnowledgeBaseUpdater:
    def __init__(self):
        self.red_kb = KnowledgeBase('red_agent', backend='chroma')
        self.blue_kb = KnowledgeBase('blue_agent', backend='chroma')

    def fetch_and_chunk_text(self, url: str, chunk_size: int = 50) -> List[str]:
        """Fetch a raw text file from URL and chunk it into blocks of lines."""
        try:
            logger.info(f"Downloading {url}...")
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                logger.error(f"Failed to fetch {url}: {response.status_code}")
                return []
            
            lines = [line.strip() for line in response.text.split('\n') if line.strip()]
            
            # Chunking to prevent making 10,000 tiny documents. 
            # We want ChromaDB to return clusters of payloads.
            chunks = []
            for i in range(0, len(lines), chunk_size):
                chunk = "\n".join(lines[i:i + chunk_size])
                chunks.append(chunk)
                
            return chunks
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return []

    def update_red_agent(self):
        """Download SecLists payloads and ingest into Red Agent KB."""
        logger.info("=== Starting Red Agent KB Expansion (SecLists) ===")
        documents = []
        
        for vuln_type, urls in RED_SOURCES.items():
            for url in urls:
                chunks = self.fetch_and_chunk_text(url, chunk_size=30)
                for idx, chunk in enumerate(chunks):
                    documents.append({
                        "content": f"Categorized {vuln_type} payloads (Cluster {idx+1}):\n{chunk}",
                        "metadata": {
                            "vulnerability_type": vuln_type,
                            "source": "SecLists_GitHub",
                            "url": url
                        }
                    })
        
        if documents:
            logger.info(f"Ingesting {len(documents)} new payload clusters into Red Agent Vector DB...")
            self.red_kb.ingest_documents(documents)
            logger.info("Red Agent KB update complete.")
        else:
            logger.warning("No documents to ingest for Red Agent.")

    def update_blue_agent(self):
        """Download MITRE CWE database and ingest mitigations into Blue Agent KB."""
        logger.info("=== Starting Blue Agent KB Expansion (MITRE CWE) ===")
        documents = []
        
        try:
            logger.info("Downloading MITRE CWE DB Archive...")
            response = requests.get(CWE_CSV_URL, timeout=15)
            
            if response.status_code == 200:
                # Open zip file from memory
                with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                    # Find the CSV file inside the zip (usually just 1000.csv)
                    csv_filename = archive.namelist()[0]
                    with archive.open(csv_filename) as f:
                        content = f.read().decode('utf-8')
                        
                        # Parse CSV
                        reader = csv.DictReader(io.StringIO(content))
                        for row in reader:
                            cwe_id = row.get('CWE-ID')
                            name = row.get('Name')
                            description = row.get('Description')
                            mitigation = row.get('Potential Mitigations')
                            
                            # We only care if there is actionable mitigation data
                            if mitigation and description and len(mitigation) > 10:
                                doc_content = f"CWE-{cwe_id}: {name}\n\n"
                                doc_content += f"DESCRIPTION:\n{description}\n\n"
                                doc_content += f"POTENTIAL SECURE MITIGATION:\n{mitigation}"
                                
                                # Attempt crude mapping to our vulnerability types for better metadata filtering
                                mapped_type = "unknown"
                                name_lower = name.lower() if name else ""
                                if 'sql' in name_lower: mapped_type = 'sql_injection'
                                elif 'cross-site scripting' in name_lower or 'xss' in name_lower: mapped_type = 'xss'
                                elif 'command' in name_lower and 'injection' in name_lower: mapped_type = 'command_injection'
                                elif 'path' in name_lower or 'directory' in name_lower: mapped_type = 'path_traversal'
                                elif 'deserialization' in name_lower: mapped_type = 'deserialization'
                                elif 'template' in name_lower: mapped_type = 'ssti'
                                elif 'redirect' in name_lower: mapped_type = 'open_redirect'
                                
                                documents.append({
                                    "content": doc_content,
                                    "metadata": {
                                        "vulnerability_type": mapped_type,
                                        "source": "MITRE_CWE",
                                        "cwe_id": f"CWE-{cwe_id}"
                                    }
                                })
                                
        except Exception as e:
            logger.error(f"Error processing MITRE CWE database: {e}")

        if documents:
            logger.info(f"Ingesting {len(documents)} CWE records with mitigations into Blue Agent Vector DB...")
            self.blue_kb.ingest_documents(documents)
            logger.info("Blue Agent KB update complete.")
        else:
            logger.warning("No documents to ingest for Blue Agent.")

    def run_all(self):
        self.update_red_agent()
        self.update_blue_agent()
        
        red_stats = self.red_kb.get_stats()
        blue_stats = self.blue_kb.get_stats()
        
        logger.info("\n=== FINAL KNOWLEDGE BASE STATS ===")
        logger.info(f"Red Agent (Attack Vectors): {red_stats['document_count']} document clusters")
        logger.info(f"Blue Agent (Defense Patterns): {blue_stats['document_count']} document clusters")


if __name__ == "__main__":
    updater = KnowledgeBaseUpdater()
    updater.run_all()
