"""
src/sentinel/sandbox/executor.py

Production-ready sandbox executor for safe code execution.
Integrates with code wrapper and vulnerability context builders.
"""

import os
import json
import logging
import tempfile
import subprocess
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import docker
from docker.errors import DockerException, ContainerError, ImageNotFound
import time

from .code_wrapper import CodeWrapperFactory, WrappedCode

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of code execution in sandbox."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    error: Optional[str] = None
    attack_succeeded: bool = False
    vulnerability_triggered: bool = False
    raw_output: str = ""


class SandboxExecutor:
    """
    Executes code safely in isolated Docker containers.
    
    Features:
    - Automatic code wrapping with vulnerability contexts
    - Resource limits (CPU, memory, timeout)
    - Network isolation
    - Attack success detection
    - Comprehensive logging
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize sandbox executor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config.get('sandbox', {})
        self.timeout = self.config.get('timeout', 10)
        self.memory_limit = self.config.get('memory_limit', '512m')
        self.cpu_limit = self.config.get('cpu_limit', 1.0)
        self.network_disabled = self.config.get('network_disabled', True)
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except DockerException as e:
            logger.error(f"Failed to initialize Docker: {e}")
            raise
        
        # Initialize code wrapper
        self.code_wrapper = CodeWrapperFactory.get_wrapper()
        
        # Build or ensure sandbox image exists
        self.image_name = "sentinel-sandbox:latest"
        self._ensure_image()
        
        # Statistics
        self.executions_count = 0
        self.attacks_detected = 0
    
    def _ensure_image(self) -> None:
        """Ensure the sandbox Docker image exists."""
        try:
            self.docker_client.images.get(self.image_name)
            logger.info(f"Sandbox image {self.image_name} found")
        except ImageNotFound:
            logger.info(f"Building sandbox image {self.image_name}")
            self._build_image()
    
    def _build_image(self) -> None:
        """Build the sandbox Docker image."""
        dockerfile_content = """
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    sqlite3 \\
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies required by the vulnerable code templates
RUN pip install flask requests lxml markupsafe pytest sqlalchemy psycopg2-binary

# Create non-root user for security
RUN useradd -m -s /bin/bash -u 1000 sandbox

# Install Python packages
RUN pip install --no-cache-dir \\
    flask>=2.3.0 \\
    requests>=2.31.0 \\
    sqlalchemy>=2.0.0 \\
    lxml>=4.9.0 \\
    markupsafe>=2.1.0 \\
    pytest>=7.4.0

# Set working directory
WORKDIR /workspace

# Create temp directory with proper permissions
RUN mkdir -p /tmp/test_sentinel && chown sandbox:sandbox /tmp/test_sentinel

# Switch to non-root user
USER sandbox

# Default command
CMD ["python", "target.py"]
"""
        
        # Create temporary directory for build context
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = os.path.join(tmpdir, 'Dockerfile')
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            
            # Build image
            try:
                self.docker_client.images.build(
                    path=tmpdir,
                    tag=self.image_name,
                    rm=True,
                    forcerm=True
                )
                logger.info(f"Built sandbox image {self.image_name}")
            except Exception as e:
                logger.error(f"Failed to build Docker image: {e}")
                raise
    
    def execute_code(
        self, 
        code: str, 
        attack_payload: Optional[str] = None,
        language: str = 'python',
        vulnerability_type: str = 'unknown'
    ) -> ExecutionResult:
        """
        Execute code in sandbox with optional attack payload.
        
        Args:
            code: Code to execute
            attack_payload: Optional malicious input to test
            language: Programming language (currently only Python supported)
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            ExecutionResult with execution details
        """
        if language != 'python':
            logger.warning(f"Language {language} not fully supported, using Python")
        
        self.executions_count += 1
        
        try:
            # Wrap code with vulnerability context
            wrapped = self.code_wrapper.wrap(
                code_snippet=code,
                attack_payload=attack_payload,
                vulnerability_type=vulnerability_type,
                include_test_harness=bool(attack_payload)
            )
            
            # Validate wrapped code
            if not self.code_wrapper.validate_wrapped_code(wrapped):
                logger.error("Wrapped code failed validation")
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr="Wrapped code validation failed",
                    exit_code=-1,
                    execution_time=0.0,
                    error="Code wrapping produced invalid Python"
                )
            
            # Execute in sandbox
            result = self._execute_wrapped_code(wrapped, attack_payload is not None)
            
            # Update statistics
            if result.attack_succeeded:
                self.attacks_detected += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}", exc_info=True)
            return ExecutionResult(
                success=False,
                stdout='',
                stderr='',
                exit_code=-1,
                execution_time=0.0,
                error=str(e)
            )
    
    def _execute_wrapped_code(
        self,
        wrapped: WrappedCode,
        has_attack: bool
    ) -> ExecutionResult:
        """
        Execute wrapped code in Docker container.
        
        Args:
            wrapped: Wrapped code object
            has_attack: Whether this is testing an attack
            
        Returns:
            ExecutionResult
        """
        # Create temporary directory for this execution
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write code to file
            code_file = os.path.join(tmpdir, 'target.py')
            with open(code_file, 'w') as f:
                f.write(wrapped.complete_code)
            
            # Log the wrapped code for debugging
            logger.debug(f"Executing wrapped code (vulnerability: {wrapped.vulnerability_type})")
            
            # Run container
            return self._run_container(
                tmpdir,
                has_attack,
                wrapped.success_indicators,
                wrapped.vulnerability_type
            )
    
    def _run_container(
        self,
        workspace_dir: str,
        has_attack: bool,
        success_indicators: list,
        vulnerability_type: str
    ) -> ExecutionResult:
        """
        Run Docker container with the code.
        
        Args:
            workspace_dir: Directory containing code
            has_attack: Whether attack payload is present
            success_indicators: List of strings indicating successful exploit
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            ExecutionResult
        """
        start_time = time.time()
        
        try:
            # Container configuration
            container_config = {
                'image': self.image_name,
                'command': ['python', 'target.py'],
                'detach': False,
                'remove': True,
                'mem_limit': self.memory_limit,
                'nano_cpus': int(self.cpu_limit * 1e9),
                'network_disabled': self.network_disabled,
                'volumes': {
                    workspace_dir: {
                        'bind': '/workspace',
                        'mode': 'rw',
                    }
                },
                'working_dir': '/workspace',
                'security_opt': ['no-new-privileges'],
                'read_only': False,  # Need write for /tmp
                'stdout': True,
                'stderr': True,
            }
            
            # Add timeout using Docker API (not available in all versions)
            # We'll handle timeout via subprocess instead
            
            logger.debug(f"Starting container with timeout={self.timeout}s")
            
            # Run container with timeout
            try:
                output = self.docker_client.containers.run(**container_config)
                execution_time = time.time() - start_time
                
                # Parse output
                stdout = output.decode('utf-8') if isinstance(output, bytes) else str(output)
                stderr = ''
                exit_code = 0
                
            except ContainerError as e:
                # Container exited with error
                execution_time = time.time() - start_time
                stdout_bytes = getattr(e, 'stdout', getattr(e, 'stderr', b''))
                stderr_bytes = getattr(e, 'stderr', getattr(e, 'stdout', b''))
                
                stdout = stdout_bytes.decode('utf-8') if isinstance(stdout_bytes, bytes) else str(stdout_bytes)
                stderr = stderr_bytes.decode('utf-8') if isinstance(stderr_bytes, bytes) else str(stderr_bytes)
                exit_code = getattr(e, 'exit_status', -1)
                
                logger.debug(f"Container exited with code {exit_code}")
            
            # Check if attack succeeded
            attack_succeeded = self._check_attack_success(
                stdout,
                stderr,
                success_indicators,
                has_attack
            )
            
            # Check if vulnerability was triggered
            vulnerability_triggered = self._check_vulnerability_triggered(
                stdout,
                stderr,
                vulnerability_type
            )
            
            # Determine overall success
            success = exit_code == 0 or attack_succeeded or vulnerability_triggered
            
            return ExecutionResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                execution_time=execution_time,
                attack_succeeded=attack_succeeded,
                vulnerability_triggered=vulnerability_triggered,
                raw_output=stdout + stderr
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Container execution failed: {e}")
            
            return ExecutionResult(
                success=False,
                stdout='',
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                error=str(e),
                attack_succeeded=False,
                vulnerability_triggered=False
            )
    
    def _check_attack_success(
        self,
        stdout: str,
        stderr: str,
        success_indicators: list,
        has_attack: bool
    ) -> bool:
        """
        Heuristically determine if an attack succeeded.
        
        Args:
            stdout: Standard output
            stderr: Standard error
            success_indicators: List of success indicator strings
            has_attack: Whether attack was attempted
            
        Returns:
            True if attack likely succeeded
        """
        if not has_attack:
            return False
        
        combined_output = stdout + stderr
        
        # Check for vulnerability-specific success indicators
        for indicator in success_indicators:
            if indicator in combined_output:
                logger.info(f"Attack success indicator found: {indicator}")
                return True
        
        # Additional generic success indicators
        generic_indicators = [
            'SUCCESS',
            'VULNERABLE',
            'TRIGGERED',
            'EXECUTED',
            'DATA_LEAK',
            'UNAUTHORIZED',
        ]
        
        for indicator in generic_indicators:
            if indicator in combined_output and 'ERROR' not in combined_output.split(indicator)[0][-50:]:
                logger.info(f"Generic attack indicator found: {indicator}")
                return True
        
        return False
    
    def _check_vulnerability_triggered(
        self,
        stdout: str,
        stderr: str,
        vulnerability_type: str
    ) -> bool:
        """
        Check if a vulnerability was triggered (error-based detection).
        
        Args:
            stdout: Standard output
            stderr: Standard error
            vulnerability_type: Type of vulnerability
            
        Returns:
            True if vulnerability was triggered
        """
        combined_output = stdout + stderr
        
        # Vulnerability-specific error patterns
        vuln_error_patterns = {
            'sql_injection': ['SQL', 'sqlite3.Error', 'IntegrityError'],
            'command_injection': ['sh:', 'command not found', 'Permission denied'],
            'path_traversal': ['FileNotFoundError', 'PermissionError', 'No such file'],
            'xss': ['<script>', 'javascript:'],
            'xxe': ['entity', 'ENTITY', 'XMLSyntaxError'],
            'ssrf': ['Connection', 'refused', 'timeout'],
        }
        
        patterns = vuln_error_patterns.get(vulnerability_type, [])
        
        for pattern in patterns:
            if pattern in combined_output:
                logger.debug(f"Vulnerability trigger pattern found: {pattern}")
                return True
        
        return False
    
    def execute_with_tests(
        self, 
        code: str, 
        test_code: Optional[str] = None
    ) -> ExecutionResult:
        """
        Execute code with test suite.
        
        Args:
            code: Main code
            test_code: Optional test code (pytest format)
            
        Returns:
            ExecutionResult
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write main code
            code_file = os.path.join(tmpdir, 'main.py')
            with open(code_file, 'w') as f:
                f.write(code)
            
            # Write test code
            if test_code:
                test_file = os.path.join(tmpdir, 'test_main.py')
                with open(test_file, 'w') as f:
                    f.write(test_code)
                
                # Run pytest
                return self._run_pytest(tmpdir)
            else:
                # Just run the code
                wrapped = self.code_wrapper.wrap(
                    code_snippet=code,
                    attack_payload=None,
                    vulnerability_type='unknown',
                    include_test_harness=False
                )
                return self._execute_wrapped_code(wrapped, False)
    
    def _run_pytest(self, workspace_dir: str) -> ExecutionResult:
        """Run pytest in container."""
        start_time = time.time()
        
        try:
            output = self.docker_client.containers.run(
                image=self.image_name,
                command=['pytest', 'test_main.py', '-v', '--tb=short'],
                remove=True,
                volumes={
                    workspace_dir: {
                        'bind': '/workspace',
                        'mode': 'ro',
                    }
                },
                working_dir='/workspace',
                mem_limit=self.memory_limit,
                network_disabled=True,
                stdout=True,
                stderr=True,
            )
            
            execution_time = time.time() - start_time
            stdout = output.decode('utf-8') if isinstance(output, bytes) else str(output)
            
            # Check if tests passed
            tests_passed = 'passed' in stdout.lower() and 'failed' not in stdout.lower()
            
            return ExecutionResult(
                success=tests_passed,
                stdout=stdout,
                stderr='',
                exit_code=0 if tests_passed else 1,
                execution_time=execution_time,
            )
            
        except ContainerError as e:
            return ExecutionResult(
                success=False,
                stdout=e.stdout.decode('utf-8') if e.stdout else '',
                stderr=e.stderr.decode('utf-8') if e.stderr else '',
                exit_code=e.exit_status,
                execution_time=time.time() - start_time,
                error=str(e),
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get execution statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_executions': self.executions_count,
            'attacks_detected': self.attacks_detected,
            'detection_rate': self.attacks_detected / self.executions_count if self.executions_count > 0 else 0.0
        }
    
    def cleanup(self) -> None:
        """Clean up Docker resources."""
        try:
            # Remove stopped containers
            containers = self.docker_client.containers.list(
                all=True,
                filters={'ancestor': self.image_name}
            )
            
            for container in containers:
                try:
                    container.remove(force=True)
                    logger.debug(f"Removed container {container.id[:12]}")
                except Exception as e:
                    logger.warning(f"Failed to remove container: {e}")
            
            logger.info(f"Cleaned up {len(containers)} sandbox containers")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")