"""
src/sentinel/sandbox/code_wrapper.py

Production-ready code wrapper for safe execution of vulnerable code snippets.
Assembles complete executable programs from code snippets and test harnesses.
"""

import logging
import textwrap
from typing import Optional, List
from dataclasses import dataclass

from .vulnerability_contexts import (
    VulnerabilityContextFactory,
    ExecutionContext
)

logger = logging.getLogger(__name__)


@dataclass
class WrappedCode:
    """Container for wrapped, executable code."""
    complete_code: str
    success_indicators: List[str]
    vulnerability_type: str
    has_test_harness: bool


class CodeWrapper:
    """
    Wraps vulnerable code snippets into complete, executable programs.
    
    This class handles:
    - Adding necessary imports
    - Creating test harnesses
    - Setting up execution environments
    - Capturing output and detecting successful exploits
    """
    
    def __init__(self):
        """Initialize the code wrapper."""
        self.logger = logging.getLogger(__name__)
    
    def wrap(
        self,
        code_snippet: str,
        attack_payload: Optional[str] = None,
        vulnerability_type: str = "unknown",
        include_test_harness: bool = True
    ) -> WrappedCode:
        """
        Wrap a code snippet into a complete executable program.
        
        Args:
            code_snippet: The vulnerable code to wrap
            attack_payload: Optional attack payload to test
            vulnerability_type: Type of vulnerability being tested
            include_test_harness: Whether to include test harness
            
        Returns:
            WrappedCode object with complete executable code
        """
        try:
            if not code_snippet:
                raise ValueError("Code snippet cannot be empty")
            
            # Clean null bytes from input (can come from LLM-generated patches)
            code_snippet = code_snippet.replace('\x00', '')
            if attack_payload:
                attack_payload = attack_payload.replace('\x00', '')
            
            # If no attack payload, just wrap for basic execution
            if not attack_payload or not include_test_harness:
                return self._wrap_basic(code_snippet, vulnerability_type)
            
            # Build vulnerability-specific execution context
            return self._wrap_with_context(
                code_snippet,
                attack_payload,
                vulnerability_type
            )
            
        except Exception as e:
            self.logger.error(f"Failed to wrap code: {e}")
            # Return a minimal wrapper on failure
            return self._wrap_fallback(code_snippet, vulnerability_type)
    
    def _wrap_basic(self, code_snippet: str, vulnerability_type: str) -> WrappedCode:
        """
        Create basic wrapper for code without test harness.
        
        Args:
            code_snippet: Code to wrap
            vulnerability_type: Type of vulnerability
            
        Returns:
            WrappedCode with basic execution wrapper
        """
        wrapper = """
#!/usr/bin/env python3
\"\"\"
Basic execution wrapper for vulnerable code.
\"\"\"

import sys
from io import StringIO

# Capture stdout
output_buffer = StringIO()
original_stdout = sys.stdout
sys.stdout = output_buffer

try:
"""
        
        # Indent the code snippet
        indented_code = textwrap.indent(code_snippet, '    ')
        wrapper += indented_code
        
        wrapper += """

    print("CODE_EXECUTED_SUCCESSFULLY")
    
except Exception as e:
    print(f"EXECUTION_ERROR: {e}")
    import traceback
    traceback.print_exc()

finally:
    # Restore stdout and print captured output
    sys.stdout = original_stdout
    captured = output_buffer.getvalue()
    print(captured)
"""
        
        return WrappedCode(
            complete_code=wrapper,
            success_indicators=["CODE_EXECUTED_SUCCESSFULLY"],
            vulnerability_type=vulnerability_type,
            has_test_harness=False
        )
    
    def _wrap_with_context(
        self,
        code_snippet: str,
        attack_payload: str,
        vulnerability_type: str
    ) -> WrappedCode:
        """
        Create comprehensive wrapper with vulnerability-specific context.
        
        Args:
            code_snippet: Vulnerable code to wrap
            attack_payload: Attack payload to test
            vulnerability_type: Type of vulnerability
            
        Returns:
            WrappedCode with complete test harness
        """
        # Build execution context using factory
        try:
            builder = VulnerabilityContextFactory.create_builder(
                vulnerability_type,
                code_snippet,
                attack_payload
            )
            context = builder.build()
        except Exception as e:
            self.logger.warning(f"Failed to build context for {vulnerability_type}: {e}")
            return self._wrap_fallback(code_snippet, vulnerability_type)
        
        # Assemble complete executable code
        complete_code = self._assemble_code(code_snippet, context)
        
        return WrappedCode(
            complete_code=complete_code,
            success_indicators=context.success_indicators,
            vulnerability_type=vulnerability_type,
            has_test_harness=True
        )
    
    def _assemble_code(
        self,
        code_snippet: str,
        context: ExecutionContext
    ) -> str:
        """
        Assemble complete executable code from components.
        
        Args:
            code_snippet: The vulnerable code
            context: Execution context with all components
            
        Returns:
            Complete executable Python code
        """
        parts = []
        
        # Shebang and docstring
        parts.append("""#!/usr/bin/env python3
\"\"\"
Vulnerability test execution wrapper.
Auto-generated by Sentinel-Adversarial.
\"\"\"
""")
        
        # Imports
        if context.imports:
            parts.append("# Required imports")
            parts.append('\n'.join(context.imports))
            parts.append("")
        
        # Add common imports that vulnerable code might need
        parts.append("""
# Common imports for vulnerable code
import os
import sys
import sqlite3
import subprocess
from io import StringIO
try:
    from flask import Flask, request
except ImportError:
    pass
try:
    import requests
except ImportError:
    pass
""")
        
        # Output capture setup
        # Use repr() to safely embed code_snippet as a string literal
        safe_code_snippet = repr(code_snippet)
        
        parts.append(f"""
# Setup output capture
output_buffer = StringIO()
original_stdout = sys.stdout
sys.stdout = output_buffer

# Store original code snippet for reference
code_snippet = {safe_code_snippet}
""")
        
        # Main execution block
        parts.append("""
try:
    # === DEFINE VULNERABLE CODE IN GLOBAL SCOPE ===
    # Execute code to define functions/classes
    exec(code_snippet, globals())
""")
        
        # Define attack_payload before setup/test harness if we have one
        if hasattr(context, 'code') and context.code:  # Check if this is a vulnerability test
            # Get the attack payload from the code snippet that's stored
            # The payload should be extracted from the builder that created this context
            # For now, we'll let each test harness define it, but put a placeholder
            pass
        
        parts.append("")
        
        # Add setup code (indented)
        if context.setup:
            parts.append("    # === SETUP ===")
            indented_setup = textwrap.indent(context.setup, '    ')
            parts.append(indented_setup)
            parts.append("")
        
        # Add test harness (indented)
        if context.test_harness:
            parts.append("    # === TEST HARNESS ===")
            indented_test = textwrap.indent(context.test_harness, '    ')
            parts.append(indented_test)
            parts.append("")
        
        # Exception handling
        parts.append("""
except Exception as e:
    print(f"EXECUTION_EXCEPTION: {e}")
    import traceback
    sys.stdout = original_stdout  # Restore for traceback
    traceback.print_exc()
    sys.stdout = output_buffer  # Capture traceback

finally:
""")
        
        # Cleanup (indented)
        if context.cleanup:
            parts.append("    # === CLEANUP ===")
            indented_cleanup = textwrap.indent(context.cleanup, '    ')
            parts.append(indented_cleanup)
            parts.append("")
        
        # Final output
        parts.append("""
    # Restore stdout and print captured output
    sys.stdout = original_stdout
    captured_output = output_buffer.getvalue()
    
    # Print all captured output
    if captured_output:
        print(captured_output)
    else:
        print("NO_OUTPUT_CAPTURED")
""")
        
        return '\n'.join(parts)
    
    def _wrap_fallback(
        self,
        code_snippet: str,
        vulnerability_type: str
    ) -> WrappedCode:
        """
        Create minimal fallback wrapper when context building fails.
        
        Args:
            code_snippet: Code to wrap
            vulnerability_type: Type of vulnerability
            
        Returns:
            WrappedCode with minimal wrapper
        """
        self.logger.warning(f"Using fallback wrapper for {vulnerability_type}")
        
        wrapper = f"""
#!/usr/bin/env python3
\"\"\"
Fallback execution wrapper.
\"\"\"

import sys
from io import StringIO

output_buffer = StringIO()
sys.stdout = output_buffer

try:
    # Vulnerable code
{textwrap.indent(code_snippet, '    ')}
    
    print("FALLBACK_EXECUTION_COMPLETED")
    
except Exception as e:
    print(f"FALLBACK_ERROR: {{e}}")

finally:
    sys.stdout = sys.__stdout__
    print(output_buffer.getvalue())
"""
        
        return WrappedCode(
            complete_code=wrapper,
            success_indicators=["FALLBACK_EXECUTION_COMPLETED"],
            vulnerability_type=vulnerability_type,
            has_test_harness=False
        )
    
    def validate_wrapped_code(self, wrapped_code: WrappedCode) -> bool:
        """
        Validate that wrapped code is syntactically correct.
        
        Args:
            wrapped_code: The wrapped code to validate
            
        Returns:
            True if code is valid Python, False otherwise
        """
        try:
            # Clean null bytes that could come from LLM-generated patches
            code_to_validate = wrapped_code.complete_code.replace('\x00', '')
            wrapped_code.complete_code = code_to_validate
            
            # Compile check
            compile(code_to_validate, '<wrapped>', 'exec')
            
            # Additional validation checks
            if not wrapped_code.complete_code.strip():
                self.logger.error("Wrapped code is empty")
                return False
            
            if len(wrapped_code.complete_code) < 50:
                self.logger.warning("Wrapped code suspiciously short")
                # Still valid, just warning
            
            # Check for required components
            required_patterns = ['try:', 'except', 'finally:']
            if not all(pattern in wrapped_code.complete_code for pattern in required_patterns):
                self.logger.warning("Wrapped code missing error handling patterns")
            
            return True
            
        except SyntaxError as e:
            self.logger.error(f"Wrapped code has syntax error: {e}")
            self.logger.debug(f"Problematic code at line {e.lineno}:")
            if e.lineno:
                lines = wrapped_code.complete_code.split('\n')
                context_start = max(0, e.lineno - 3)
                context_end = min(len(lines), e.lineno + 2)
                for i in range(context_start, context_end):
                    marker = '>>> ' if i == e.lineno - 1 else '    '
                    self.logger.debug(f"{marker}{i+1}: {lines[i]}")
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error validating code: {e}")
            return False


class CodeWrapperFactory:
    """Factory for creating and caching CodeWrapper instances."""
    
    _instance: Optional[CodeWrapper] = None
    
    @classmethod
    def get_wrapper(cls) -> CodeWrapper:
        """
        Get singleton CodeWrapper instance.
        
        Returns:
            CodeWrapper instance
        """
        if cls._instance is None:
            cls._instance = CodeWrapper()
        return cls._instance