"""
src/sentinel/agents/blue_agent.py

Blue Agent (Defender) - Generates patches to fix vulnerabilities.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .base_agent import BaseLLMAgent, AgentResponse

logger = logging.getLogger(__name__)


@dataclass
class Patch:
    """Structured patch information."""
    original_code: str
    fixed_code: str
    vulnerability_type: str
    patch_strategy: str
    explanation: str
    confidence: float
    imports_needed: List[str]


class BlueAgent(BaseLLMAgent):
    """
    Blue Agent (Defender) - Learns to patch vulnerabilities and defend code.
    """
    
    def _get_agent_config(self) -> Dict[str, Any]:
        """Get Blue Agent specific configuration."""
        return self.config.get('agents', {}).get('blue_agent', {})
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Blue Agent."""
        super().__init__(config)
        
        self.patch_strategies = self.agent_config.get('patch_strategies', [
            'input_validation',
            'parameterization',
            'sanitization',
            'safe_api_replacement',
        ])
        
        self.max_patch_lines = self.agent_config.get('max_patch_lines', 50)
        self.test_required = self.agent_config.get('test_required', True)
        
        # Secure coding patterns
        self.secure_patterns = self._load_secure_patterns()
        
        logger.info(f"Blue Agent initialized with {len(self.patch_strategies)} strategies")
    
    def _load_secure_patterns(self) -> Dict[str, Dict[str, str]]:
        """Load secure coding patterns for common vulnerabilities."""
        return {
            'sql_injection': {
                'pattern': 'Use parameterized queries',
                'example_python': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'libraries': ['sqlite3', 'psycopg2', 'sqlalchemy'],
            },
            'xss': {
                'pattern': 'Escape user input before rendering',
                'example_python': 'from markupsafe import escape\nrendered = escape(user_input)',
                'libraries': ['markupsafe', 'html'],
            },
            'command_injection': {
                'pattern': 'Use subprocess with list arguments, avoid shell=True',
                'example_python': 'subprocess.run(["ls", directory], check=True)',
                'libraries': ['subprocess'],
            },
            'path_traversal': {
                'pattern': 'Validate and sanitize file paths',
                'example_python': 'safe_path = os.path.abspath(os.path.join(base_dir, user_path))\nif not safe_path.startswith(base_dir): raise ValueError("Invalid path")',
                'libraries': ['os', 'pathlib'],
            },
            'xxe': {
                'pattern': 'Disable external entity processing',
                'example_python': 'parser = etree.XMLParser(resolve_entities=False)',
                'libraries': ['lxml', 'xml.etree.ElementTree'],
            },
            'ssrf': {
                'pattern': 'Validate and whitelist URLs',
                'example_python': 'allowed_domains = ["api.example.com"]\nif urlparse(url).netloc not in allowed_domains: raise ValueError("Invalid URL")',
                'libraries': ['urllib.parse'],
            },
        }
    
    def act(self, observation: Dict[str, Any]) -> AgentResponse:
        """
        Generate a patch based on the vulnerability observation.
        
        Args:
            observation: Contains 'code', 'vulnerability_type', 'attack' (optional)
            
        Returns:
            AgentResponse with patch details
        """
        code = observation.get('code', '')
        vuln_type = observation.get('vulnerability_type', 'unknown')
        attack = observation.get('attack', None)
        language = observation.get('language', 'python')
        
        # Generate patch
        patch = self._generate_llm_patch(code, vuln_type, attack, language)
        
        # Log the patch
        self.add_to_history({
            'action': 'patch',
            'vulnerability_type': vuln_type,
            'strategy': patch.patch_strategy,
            'confidence': patch.confidence,
        })
        
        return AgentResponse(
            content=patch.fixed_code,
            confidence=patch.confidence,
            reasoning=patch.explanation,
            metadata={
                'vulnerability_type': vuln_type,
                'patch_strategy': patch.patch_strategy,
                'imports_needed': patch.imports_needed,
            }
        )
    
    def _generate_llm_patch(
        self, 
        code: str, 
        vuln_type: str, 
        attack: Optional[Dict[str, Any]], 
        language: str
    ) -> Patch:
        """Generate patch using LLM."""
        
        # Get secure pattern for this vulnerability type
        secure_info = self.secure_patterns.get(vuln_type, {})
        
        system_prompt = """You are an expert security engineer specializing in secure code remediation.

Your goal is to fix security vulnerabilities while:
1. Preserving all functionality
2. Following OWASP secure coding guidelines
3. Using industry-standard security libraries
4. Writing clean, maintainable code

CRITICAL RULES:
- For SQL: ALWAYS use parameterized queries (?, placeholders)
- For XSS: ALWAYS escape/sanitize output
- For Command Injection: NEVER use shell=True, use list arguments
- For Path Traversal: ALWAYS validate paths against base directory
- Add proper error handling
- Include type hints when possible

Return ONLY the fixed code, no explanations unless asked."""

        attack_info = ""
        if attack:
            attack_info = f"""
Red Agent's Attack:
- Type: {attack.get('attack_type', 'unknown')}
- Payload: {attack.get('payload', 'N/A')}
- Target: {attack.get('target_function', 'N/A')}

Your patch MUST block this specific attack.
"""

        secure_pattern_info = ""
        if secure_info:
            secure_pattern_info = f"""
Recommended Approach:
- Strategy: {secure_info.get('pattern', 'N/A')}
- Example: {secure_info.get('example_python', 'N/A')}
- Libraries: {', '.join(secure_info.get('libraries', []))}
"""

        user_prompt = f"""Fix this security vulnerability in {language} code:

VULNERABLE CODE:
```{language}
{code}
```

VULNERABILITY TYPE: {vuln_type}

{attack_info}

{secure_pattern_info}

REQUIREMENTS:
1. Fix the {vuln_type} vulnerability completely
2. Preserve ALL existing functionality
3. Ensure the code still passes all tests
4. Use secure coding best practices
5. Add necessary imports at the top

Return your response as VALID JSON (no control characters, properly escaped strings):
{{
    "fixed_code": "the complete fixed code here",
    "patch_strategy": "input_validation|parameterization|sanitization|safe_api_replacement",
    "explanation": "brief explanation of the fix",
    "confidence": 0.95,
    "imports_needed": ["library1", "library2"]
}}

IMPORTANT: Escape all special characters in fixed_code (newlines as \\n, tabs as \\t, quotes as \\").
The fixed_code should be production-ready and directly usable."""

        try:
            response = self._call_llm(user_prompt, system_prompt)
            
            # Ultra-aggressive cleaning: remove ALL non-ASCII and control characters
            # Keep only: letters, digits, spaces, newlines, tabs, basic punctuation
            import string
            allowed_chars = set(string.ascii_letters + string.digits + string.punctuation + ' \n\t\r')
            response = ''.join(char for char in response if char in allowed_chars)
            
            # Parse JSON response
            if '```json' in response:
                response = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                response = response.split('```')[1].split('```')[0]
            
            try:
                patch_data = json.loads(response.strip())
            except json.JSONDecodeError as json_err:
                # LLM returned invalid JSON even after aggressive cleaning
                logger.error(f"LLM patch generation failed: {json_err}")
                logger.debug(f"Cleaned response was: {response[:200]}...")
                # Fallback to safe passthrough
                return self._generate_fallback_patch(code, vuln_type)
            
            fixed_code = patch_data.get('fixed_code', '')
            
            # Clean up the fixed code (remove markdown if present)
            if '```python' in fixed_code:
                fixed_code = fixed_code.split('```python')[1].split('```')[0]
            elif '```' in fixed_code:
                fixed_code = fixed_code.split('```')[1].split('```')[0]
            
            fixed_code = fixed_code.strip()
            
            # Limit patch size
            lines = fixed_code.split('\n')
            if len(lines) > self.max_patch_lines:
                logger.warning(f"Patch too large ({len(lines)} lines), truncating")
                fixed_code = '\n'.join(lines[:self.max_patch_lines])
            
            return Patch(
                original_code=code,
                fixed_code=fixed_code,
                vulnerability_type=vuln_type,
                patch_strategy=patch_data.get('patch_strategy', 'unknown'),
                explanation=patch_data.get('explanation', ''),
                confidence=patch_data.get('confidence', 0.5),
                imports_needed=patch_data.get('imports_needed', []),
            )
            
        except Exception as e:
            logger.error(f"LLM patch generation failed: {e}")
            # Return a defensive fallback patch
            return self._generate_fallback_patch(code, vuln_type)
    
    def _generate_fallback_patch(self, code: str, vuln_type: str) -> Patch:
        """Generate a simple safe fallback - just return original code with comment."""
        
        # Safe fallback: return original code with security warning comment
        # This is better than creating syntactically invalid patches
        fixed_code = f"# SECURITY WARNING: {vuln_type} vulnerability detected but auto-patch failed\n"
        fixed_code += f"# TODO: Manually review and fix this {vuln_type} issue\n"
        fixed_code += code
        
        return Patch(
            original_code=code,
            fixed_code=fixed_code,
            vulnerability_type=vuln_type,
            patch_strategy='manual_review_required',
            explanation=f'Automatic patching failed. Manual review needed for {vuln_type}.',
            confidence=0.1,
            imports_needed=[],
        )
    
    def validate_patch(
        self, 
        original_code: str, 
        patched_code: str, 
        vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Validate that a patch is syntactically correct and doesn't introduce new issues.
        
        Args:
            original_code: Original vulnerable code
            patched_code: Patched code
            vulnerability_type: Type of vulnerability being fixed
            
        Returns:
            Validation results
        """
        results = {
            'syntax_valid': False,
            'imports_valid': False,
            'likely_secure': False,
            'issues': [],
        }
        
        # 1. Syntax check
        try:
            compile(patched_code, '<string>', 'exec')
            results['syntax_valid'] = True
        except SyntaxError as e:
            results['issues'].append(f"Syntax error: {e}")
        
        # 2. Check for required imports
        required_modules = {
            'sql_injection': ['sqlite3', 'psycopg2', 'sqlalchemy'],
            'xss': ['markupsafe', 'html'],
            'command_injection': ['subprocess'],
            'path_traversal': ['os', 'pathlib'],
        }
        
        if vulnerability_type in required_modules:
            has_import = any(
                f'import {mod}' in patched_code or f'from {mod}' in patched_code
                for mod in required_modules[vulnerability_type]
            )
            results['imports_valid'] = has_import
            if not has_import:
                results['issues'].append(f"Missing required import for {vulnerability_type}")
        else:
            results['imports_valid'] = True
        
        # 3. Heuristic security check
        insecure_patterns = {
            'sql_injection': [r'f".*SELECT.*{', r"f'.*SELECT.*{"],
            'command_injection': ['shell=True', r'os\.system\('],
            'xss': [r'f"<.*{.*}"', r"f'<.*{.*}'"],
        }
        
        if vulnerability_type in insecure_patterns:
            found_insecure = any(
                re.search(pattern, patched_code)
                for pattern in insecure_patterns[vulnerability_type]
            )
            results['likely_secure'] = not found_insecure
            if found_insecure:
                results['issues'].append(f"Insecure pattern still present")
        else:
            results['likely_secure'] = True
        
        return results
