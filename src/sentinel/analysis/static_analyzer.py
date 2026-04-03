"""
src/sentinel/analysis/static_analyzer.py

Static analysis integration using Bandit and Semgrep.
Runs tools via subprocess on temporary files and parses results.
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single static analysis finding."""
    tool: str  # 'bandit' or 'semgrep'
    rule_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: str  # LOW, MEDIUM, HIGH
    message: str
    line_number: int
    cwe_id: Optional[str] = None
    code_snippet: str = ""


@dataclass
class AnalysisResult:
    """Combined result from all static analysis tools."""
    findings: List[Finding] = field(default_factory=list)
    bandit_available: bool = False
    semgrep_available: bool = False
    error: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ('HIGH', 'CRITICAL'))

    @property
    def finding_types(self) -> List[str]:
        return list(set(f.rule_id for f in self.findings))


class StaticAnalyzer:
    """
    Runs Bandit and Semgrep static analysis on code strings.
    
    Uses subprocess to call CLI tools — does NOT require them as Python imports.
    Gracefully degrades if tools are not installed.
    """

    def __init__(self):
        """Initialize and detect available tools."""
        self.bandit_available = self._check_tool('bandit')
        self.semgrep_available = self._check_tool('semgrep')

        if self.bandit_available:
            logger.info("Bandit static analyzer available")
        else:
            logger.warning("Bandit not installed — run: pip install bandit")

        if self.semgrep_available:
            logger.info("Semgrep static analyzer available")
        else:
            logger.warning("Semgrep not installed — run: pip install semgrep")

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a CLI tool is available."""
        try:
            subprocess.run(
                [tool_name, '--version'],
                capture_output=True,
                timeout=10
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(self, code: str, language: str = 'python') -> AnalysisResult:
        """
        Run all available static analyzers on code.

        Args:
            code: Source code string to analyze
            language: Programming language

        Returns:
            AnalysisResult with combined findings
        """
        result = AnalysisResult(
            bandit_available=self.bandit_available,
            semgrep_available=self.semgrep_available,
        )

        if language != 'python':
            logger.debug(f"Static analysis for {language} — only Semgrep supported")

        # Write code to temp file
        suffix = '.py' if language == 'python' else f'.{language}'
        try:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix=suffix, delete=False
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            # Run Bandit (Python only)
            if self.bandit_available and language == 'python':
                bandit_findings = self._run_bandit(tmp_path)
                result.findings.extend(bandit_findings)

            # Run Semgrep (multi-language)
            if self.semgrep_available:
                semgrep_findings = self._run_semgrep(tmp_path, language)
                result.findings.extend(semgrep_findings)

        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            result.error = str(e)
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except (OSError, UnboundLocalError):
                pass

        return result

    def _run_bandit(self, filepath: str) -> List[Finding]:
        """Run Bandit on a Python file and parse JSON output."""
        findings = []
        try:
            proc = subprocess.run(
                [
                    'bandit',
                    '-f', 'json',      # JSON output
                    '-ll',             # Medium+ severity
                    '-q',              # Quiet (no progress)
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Bandit returns exit code 1 if findings exist — that's expected
            output = proc.stdout
            if not output:
                return findings

            data = json.loads(output)

            for result in data.get('results', []):
                cwe_id = None
                if result.get('issue_cwe', {}).get('id'):
                    cwe_id = f"CWE-{result['issue_cwe']['id']}"

                findings.append(Finding(
                    tool='bandit',
                    rule_id=result.get('test_id', 'unknown'),
                    severity=result.get('issue_severity', 'MEDIUM').upper(),
                    confidence=result.get('issue_confidence', 'MEDIUM').upper(),
                    message=result.get('issue_text', ''),
                    line_number=result.get('line_number', 0),
                    cwe_id=cwe_id,
                    code_snippet=result.get('code', ''),
                ))

            logger.debug(f"Bandit found {len(findings)} issues")

        except subprocess.TimeoutExpired:
            logger.warning("Bandit timed out")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Bandit output: {e}")
        except Exception as e:
            logger.error(f"Bandit execution failed: {e}")

        return findings

    def _run_semgrep(self, filepath: str, language: str) -> List[Finding]:
        """Run Semgrep with security rules and parse JSON output."""
        findings = []

        # Select ruleset based on language
        ruleset_map = {
            'python': 'p/python',
            'javascript': 'p/javascript',
            'java': 'p/java',
            'go': 'p/golang',
        }
        ruleset = ruleset_map.get(language, 'p/default')

        try:
            proc = subprocess.run(
                [
                    'semgrep',
                    '--config', ruleset,
                    '--json',
                    '--quiet',
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            output = proc.stdout
            if not output:
                return findings

            data = json.loads(output)

            for result in data.get('results', []):
                severity_map = {
                    'ERROR': 'HIGH',
                    'WARNING': 'MEDIUM',
                    'INFO': 'LOW',
                }

                findings.append(Finding(
                    tool='semgrep',
                    rule_id=result.get('check_id', 'unknown'),
                    severity=severity_map.get(
                        result.get('extra', {}).get('severity', 'WARNING'),
                        'MEDIUM'
                    ),
                    confidence='HIGH',  # Semgrep rules are pattern-based
                    message=result.get('extra', {}).get('message', ''),
                    line_number=result.get('start', {}).get('line', 0),
                    cwe_id=None,
                    code_snippet=result.get('extra', {}).get('lines', ''),
                ))

            logger.debug(f"Semgrep found {len(findings)} issues")

        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Semgrep output: {e}")
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}")

        return findings

    def is_caught_by_static(self, code: str, vulnerability_type: str) -> bool:
        """
        Quick check: would this code's vulnerability be caught by static analysis?

        Used in reward calculation — if Red Agent's attack uses patterns that
        Bandit/Semgrep would flag, the attack is "too obvious" and gets penalized.

        Args:
            code: Code containing the vulnerability
            vulnerability_type: Type of vulnerability

        Returns:
            True if static analysis finds relevant issues
        """
        if not (self.bandit_available or self.semgrep_available):
            return False

        result = self.analyze(code)

        if not result.has_findings:
            return False

        # Map vulnerability types to relevant Bandit test IDs and keywords
        vuln_to_rules = {
            'sql_injection': ['B608', 'B610', 'sql'],
            'command_injection': ['B602', 'B603', 'B604', 'B605', 'B607', 'subprocess', 'os.system'],
            'xss': ['B701', 'xss', 'cross-site'],
            'path_traversal': ['B310', 'path', 'traversal'],
            'xxe': ['B314', 'B320', 'xml', 'xxe'],
            'ssrf': ['B310', 'ssrf', 'request'],
            'deserialization': ['B301', 'B302', 'pickle', 'deseriali'],
            'ssti': ['B702', 'template'],
        }

        relevant_rules = vuln_to_rules.get(vulnerability_type, [])

        for finding in result.findings:
            rule_lower = finding.rule_id.lower()
            msg_lower = finding.message.lower()

            for rule in relevant_rules:
                if rule.lower() in rule_lower or rule.lower() in msg_lower:
                    return True

        return False

    def analyze_patch_quality(
        self,
        original_code: str,
        patched_code: str,
        language: str = 'python'
    ) -> Dict[str, Any]:
        """
        Compare static analysis results between original and patched code.

        Returns:
            Dict with:
            - original_findings: count of findings in original
            - patched_findings: count of findings in patched
            - fixed_findings: findings removed by patch
            - new_findings: findings introduced by patch
            - improvement_score: float from -1.0 (worse) to 1.0 (perfect)
        """
        original_result = self.analyze(original_code, language)
        patched_result = self.analyze(patched_code, language)

        original_rules = set(f.rule_id for f in original_result.findings)
        patched_rules = set(f.rule_id for f in patched_result.findings)

        fixed = original_rules - patched_rules
        new_issues = patched_rules - original_rules

        # Score: +1 for each fix, -2 for each new issue (introducing bugs is worse)
        if len(original_rules) == 0 and len(new_issues) == 0:
            score = 0.0
        elif len(original_rules) == 0:
            score = -1.0
        else:
            score = (len(fixed) - 2 * len(new_issues)) / max(len(original_rules), 1)
            score = max(-1.0, min(1.0, score))

        return {
            'original_findings': len(original_result.findings),
            'patched_findings': len(patched_result.findings),
            'fixed_findings': list(fixed),
            'new_findings': list(new_issues),
            'improvement_score': score,
        }
