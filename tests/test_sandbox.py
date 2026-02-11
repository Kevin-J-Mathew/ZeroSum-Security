"""
tests/test_sandbox.py

Comprehensive unit tests for the sandbox execution system.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock

from src.sentinel.sandbox.vulnerability_contexts import (
    VulnerabilityContextFactory,
    VulnerabilityType,
    SQLInjectionContextBuilder,
    XSSContextBuilder,
    CommandInjectionContextBuilder
)
from src.sentinel.sandbox.code_wrapper import CodeWrapper, WrappedCode
from src.sentinel.sandbox.executor import SandboxExecutor


class TestVulnerabilityContextBuilders:
    """Test vulnerability context builders."""
    
    def test_sql_injection_context_builder(self):
        """Test SQL injection context builder."""
        code = "def login(user, pwd):\n    query = f\"SELECT * FROM users WHERE user='{user}'\"\n    cursor.execute(query)"
        payload = "' OR '1'='1"
        
        builder = SQLInjectionContextBuilder(code, payload)
        context = builder.build()
        
        assert context is not None
        assert len(context.imports) > 0
        assert 'sqlite3' in ' '.join(context.imports)
        assert len(context.setup) > 0
        assert 'CREATE TABLE' in context.setup
        assert len(context.test_harness) > 0
        assert len(context.success_indicators) > 0
        assert 'SQL_INJECTION_SUCCESS' in context.success_indicators
    
    def test_xss_context_builder(self):
        """Test XSS context builder."""
        code = "def show_comment(text):\n    return f\"<div>{text}</div>\""
        payload = "<script>alert('XSS')</script>"
        
        builder = XSSContextBuilder(code, payload)
        context = builder.build()
        
        assert context is not None
        assert 'flask' in ' '.join(context.imports).lower()
        assert len(context.test_harness) > 0
        assert 'XSS_SUCCESS' in context.success_indicators
    
    def test_command_injection_context_builder(self):
        """Test command injection context builder."""
        code = "def ping(host):\n    os.system(f'ping {host}')"
        payload = "; cat /etc/passwd"
        
        builder = CommandInjectionContextBuilder(code, payload)
        context = builder.build()
        
        assert context is not None
        assert 'os' in ' '.join(context.imports) or 'subprocess' in ' '.join(context.imports)
        assert len(context.test_harness) > 0
        assert any('COMMAND_INJECTION' in ind for ind in context.success_indicators)
    
    def test_factory_creates_correct_builder(self):
        """Test factory creates correct builder type."""
        code = "test code"
        payload = "test payload"
        
        # Test SQL injection
        builder = VulnerabilityContextFactory.create_builder(
            'sql_injection', code, payload
        )
        assert isinstance(builder, SQLInjectionContextBuilder)
        
        # Test XSS
        builder = VulnerabilityContextFactory.create_builder(
            'xss', code, payload
        )
        assert isinstance(builder, XSSContextBuilder)
        
        # Test unknown type (should not raise)
        builder = VulnerabilityContextFactory.create_builder(
            'unknown_type', code, payload
        )
        assert builder is not None


class TestCodeWrapper:
    """Test code wrapper functionality."""
    
    def test_basic_wrap_without_attack(self):
        """Test basic wrapping without attack payload."""
        wrapper = CodeWrapper()
        code = "print('Hello World')"
        
        wrapped = wrapper.wrap(code, attack_payload=None, include_test_harness=False)
        
        assert isinstance(wrapped, WrappedCode)
        assert code in wrapped.complete_code
        assert len(wrapped.success_indicators) > 0
        assert not wrapped.has_test_harness
    
    def test_wrap_with_sql_injection_attack(self):
        """Test wrapping with SQL injection attack."""
        wrapper = CodeWrapper()
        code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
        payload = "admin' --"
        
        wrapped = wrapper.wrap(
            code_snippet=code,
            attack_payload=payload,
            vulnerability_type='sql_injection',
            include_test_harness=True
        )
        
        assert isinstance(wrapped, WrappedCode)
        assert wrapped.has_test_harness
        assert 'sql_injection' in wrapped.vulnerability_type
        assert len(wrapped.success_indicators) > 0
        assert any('SQL_INJECTION' in ind for ind in wrapped.success_indicators)
    
    def test_wrap_validates_syntax(self):
        """Test that wrapped code is syntactically valid."""
        wrapper = CodeWrapper()
        code = "def test():\n    return 42"
        
        wrapped = wrapper.wrap(code, attack_payload=None, include_test_harness=False)
        
        # Should compile without error
        is_valid = wrapper.validate_wrapped_code(wrapped)
        assert is_valid
    
    def test_wrap_handles_empty_code(self):
        """Test handling of empty code."""
        wrapper = CodeWrapper()
        
        with pytest.raises(ValueError):
            wrapper.wrap("", attack_payload="test")
    
    def test_fallback_wrapper_on_error(self):
        """Test fallback wrapper is used when context building fails."""
        wrapper = CodeWrapper()
        
        # Use invalid vulnerability type to trigger fallback
        code = "print('test')"
        wrapped = wrapper.wrap(
            code_snippet=code,
            attack_payload="test",
            vulnerability_type='invalid_type_xyz',
            include_test_harness=True
        )
        
        # Should still produce valid wrapped code
        assert isinstance(wrapped, WrappedCode)
        assert code in wrapped.complete_code


class TestSandboxExecutor:
    """Test sandbox executor."""
    
    @pytest.fixture
    def mock_docker_client(self):
        """Create mock Docker client."""
        client = MagicMock()
        client.images.get.return_value = MagicMock()  # Image exists
        return client
    
    @pytest.fixture
    def executor_with_mock(self, mock_docker_client):
        """Create executor with mocked Docker client."""
        config = {
            'sandbox': {
                'timeout': 10,
                'memory_limit': '512m',
                'cpu_limit': 1.0,
                'network_disabled': True
            }
        }
        
        with patch('docker.from_env', return_value=mock_docker_client):
            executor = SandboxExecutor(config)
        
        return executor
    
    def test_executor_initialization(self, executor_with_mock):
        """Test executor initializes correctly."""
        assert executor_with_mock is not None
        assert executor_with_mock.timeout == 10
        assert executor_with_mock.memory_limit == '512m'
        assert executor_with_mock.network_disabled is True
    
    def test_execute_code_wraps_correctly(self, executor_with_mock):
        """Test that execute_code wraps code correctly."""
        code = "print('test')"
        
        # Mock container run to avoid actual execution
        executor_with_mock.docker_client.containers.run = MagicMock(
            return_value=b"CODE_EXECUTED_SUCCESSFULLY\n"
        )
        
        result = executor_with_mock.execute_code(
            code=code,
            attack_payload=None,
            vulnerability_type='unknown'
        )
        
        assert result is not None
        assert result.success or result.stdout != ''
    
    def test_attack_success_detection(self, executor_with_mock):
        """Test attack success detection logic."""
        # Test with success indicator present
        is_success = executor_with_mock._check_attack_success(
            stdout="SQL_INJECTION_SUCCESS: Attack worked",
            stderr="",
            success_indicators=["SQL_INJECTION_SUCCESS"],
            has_attack=True
        )
        assert is_success
        
        # Test with no indicators
        is_success = executor_with_mock._check_attack_success(
            stdout="Normal output",
            stderr="",
            success_indicators=["SQL_INJECTION_SUCCESS"],
            has_attack=True
        )
        assert not is_success
    
    def test_vulnerability_trigger_detection(self, executor_with_mock):
        """Test vulnerability trigger detection."""
        # SQL error should trigger SQL injection detection
        is_triggered = executor_with_mock._check_vulnerability_triggered(
            stdout="",
            stderr="sqlite3.Error: SQL syntax error",
            vulnerability_type='sql_injection'
        )
        assert is_triggered
        
        # Generic output should not trigger
        is_triggered = executor_with_mock._check_vulnerability_triggered(
            stdout="Normal execution",
            stderr="",
            vulnerability_type='sql_injection'
        )
        assert not is_triggered
    
    def test_statistics_tracking(self, executor_with_mock):
        """Test that statistics are tracked correctly."""
        initial_stats = executor_with_mock.get_statistics()
        assert initial_stats['total_executions'] == 0
        
        executor_with_mock.executions_count = 10
        executor_with_mock.attacks_detected = 3
        
        stats = executor_with_mock.get_statistics()
        assert stats['total_executions'] == 10
        assert stats['attacks_detected'] == 3
        assert stats['detection_rate'] == 0.3


class TestIntegration:
    """Integration tests for the complete system."""
    
    @pytest.mark.integration
    @pytest.mark.skip(reason="Requires Docker")
    def test_full_sql_injection_detection(self):
        """Integration test: Full SQL injection detection."""
        config = {
            'sandbox': {
                'timeout': 15,
                'memory_limit': '512m'
            }
        }
        
        executor = SandboxExecutor(config)
        
        vulnerable_code = """
def login(username, password):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
        
        attack_payload = "admin' OR '1'='1"
        
        result = executor.execute_code(
            code=vulnerable_code,
            attack_payload=attack_payload,
            vulnerability_type='sql_injection'
        )
        
        assert result.success or result.attack_succeeded or result.vulnerability_triggered
        
        # Cleanup
        executor.cleanup()
    
    @pytest.mark.integration
    @pytest.mark.skip(reason="Requires Docker")
    def test_full_command_injection_detection(self):
        """Integration test: Full command injection detection."""
        config = {'sandbox': {}}
        executor = SandboxExecutor(config)
        
        vulnerable_code = """
import os

def ping_host(hostname):
    command = f"ping -c 1 {hostname}"
    os.system(command)
"""
        
        attack_payload = "localhost; ls -la"
        
        result = executor.execute_code(
            code=vulnerable_code,
            attack_payload=attack_payload,
            vulnerability_type='command_injection'
        )
        
        assert result.success or result.attack_succeeded or result.vulnerability_triggered
        
        executor.cleanup()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring Docker"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])