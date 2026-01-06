"""
Unit tests for the Scanner class.

This module contains basic functionality tests for the Scanner methods:
- scan_chatbot
- scan_api  
- scan_function

Tests focus on ensuring methods can be called without errors and return expected types.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Any, Dict, Optional

# Import the classes we want to test
from hydroxai.compliance.scanner import Scanner
from hydroxai.compliance.types import ScanResult, VulnerabilityStatus, StandardTestResult, PromptResponsePair


@pytest.fixture
def mock_scan_result():
    """Create a mock ScanResult for testing."""
    return ScanResult(
        model_name="test_model",
        overall_status=VulnerabilityStatus.NOT_VULNERABLE,
        test_results=[
            StandardTestResult(
                test_type="injection",
                vulnerability_status=VulnerabilityStatus.NOT_VULNERABLE,
                attack_method="prompt_injection",
                interactions=[
                    PromptResponsePair(
                        prompt="test prompt",
                        response="test response",
                        prompt_type="attack"
                    )
                ],
                test_id="test_1"
            )
        ],
        summary="Mock scan completed successfully",
        metadata={"test": "data"}
    )


class TestScanner:
    """Test cases for the Scanner class."""
    
    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.scanner = Scanner(timeout=30.0)
    
    def test_scanner_initialization(self):
        """Test Scanner can be initialized with default and custom timeout."""
        # Test default initialization
        default_scanner = Scanner()
        assert -1e-6 < default_scanner.timeout - 60.0 < 1e-6
        
        # Test custom timeout
        custom_scanner = Scanner(timeout=45.0)
        assert  -1e-6 < custom_scanner.timeout - 45.0 < 1e-6
    
    @patch('hydroxai.compliance.chatbot.executor.execute_chatbot_scan')
    def test_scan_chatbot_basic_call(self, mock_execute, sample_url, mock_scan_result):
        """Test scan_chatbot method can be called without errors."""
        # Setup mock
        mock_result = ScanResult(
            model_name=f"chatbot:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan completed",
            metadata={"url": sample_url}
        )
        mock_execute.return_value = mock_result
        
        # Act
        result = self.scanner.scan_chatbot(sample_url)
        
        # Assert
        assert isinstance(result, ScanResult)
        assert "chatbot:" in result.model_name
        assert result.overall_status in [VulnerabilityStatus.NOT_VULNERABLE, VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.UNCERTAIN]
        assert isinstance(result.test_results, list)
        assert "scan" in result.summary.lower()
        assert result.metadata is not None
        assert result.metadata["url"] == sample_url
    
    @patch('hydroxai.compliance.chatbot.executor.execute_chatbot_scan')
    def test_scan_chatbot_with_different_urls(self, mock_execute):
        """Test scan_chatbot with various URL formats."""
        test_urls = [
            "https://example.com/chat",
            "http://localhost:8080/api/chat",
            "https://api.openai.com/v1/chat/completions"
        ]
        
        for url in test_urls:
            mock_result = ScanResult(
                model_name=f"chatbot:{url}",
                overall_status=VulnerabilityStatus.NOT_VULNERABLE,
                test_results=[],
                summary="Mock scan",
                metadata={"url": url}
            )
            mock_execute.return_value = mock_result
            
            result = self.scanner.scan_chatbot(url)
            assert isinstance(result, ScanResult)
            assert result.metadata["url"] == url
    
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    def test_scan_api_basic_call(self, mock_execute, sample_url, sample_headers, sample_api_body):
        """Test scan_api method can be called without errors."""
        # Setup mock
        mock_result = ScanResult(
            model_name=f"api:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock API scan completed",
            metadata={"endpoint": sample_url, "method": "POST"}
        )
        mock_execute.return_value = mock_result
        
        # Act
        result = self.scanner.scan_api(
            endpoint=sample_url,
            method="POST", 
            headers=sample_headers,
            body=sample_api_body
        )
        
        # Assert
        assert isinstance(result, ScanResult)
        assert "api:" in result.model_name
        assert result.overall_status in [VulnerabilityStatus.NOT_VULNERABLE, VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.UNCERTAIN]
        assert isinstance(result.test_results, list)
        assert "scan" in result.summary.lower()
        assert result.metadata is not None
        assert result.metadata["endpoint"] == sample_url
        assert result.metadata["method"] == "POST"
    
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    def test_scan_api_with_different_methods(self, mock_execute, sample_url):
        """Test scan_api with different HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        
        for method in methods:
            mock_result = ScanResult(
                model_name=f"api:{sample_url}",
                overall_status=VulnerabilityStatus.NOT_VULNERABLE,
                test_results=[],
                summary="Mock scan",
                metadata={"endpoint": sample_url, "method": method}
            )
            mock_execute.return_value = mock_result
            
            result = self.scanner.scan_api(endpoint=sample_url, method=method)
            assert isinstance(result, ScanResult)
            assert result.metadata["method"] == method
    
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    def test_scan_api_minimal_parameters(self, mock_execute, sample_url):
        """Test scan_api with minimal required parameters."""
        # Setup mock
        mock_result = ScanResult(
            model_name=f"api:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan",
            metadata={"endpoint": sample_url, "method": "POST"}
        )
        mock_execute.return_value = mock_result
        
        # Only endpoint is required, others should have defaults
        result = self.scanner.scan_api(endpoint=sample_url)
        
        assert isinstance(result, ScanResult)
        assert result.metadata["endpoint"] == sample_url
        assert result.metadata["method"] == "POST"  # default method
    
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    def test_scan_api_with_none_headers(self, mock_execute, sample_url):
        """Test scan_api handles None headers correctly."""
        mock_result = ScanResult(
            model_name=f"api:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan",
            metadata={"endpoint": sample_url, "method": "POST"}
        )
        mock_execute.return_value = mock_result
        
        result = self.scanner.scan_api(endpoint=sample_url, headers=None)
        
        assert isinstance(result, ScanResult)
    
    @patch('hydroxai.compliance.function.executor.execute_function_scan')
    def test_scan_function_basic_call(self, mock_execute, sample_function_params, sample_function_code):
        """Test scan_function method can be called without errors."""
        # Create a simple test function
        def test_function(input_text: str) -> str:
            return f"Processed: {input_text}"
        
        # Setup mock
        mock_result = ScanResult(
            model_name=f"function:test_function",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Function test_function scan completed",
            metadata={"main_param": "input_text"}
        )
        mock_execute.return_value = mock_result
        
        # Act
        result = self.scanner.scan_function(
            function=test_function,
            main_param="input_text"
        )
        
        # Assert
        assert isinstance(result, ScanResult)
        assert "function:" in result.model_name
        assert result.overall_status in [VulnerabilityStatus.NOT_VULNERABLE, VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.UNCERTAIN]
        assert isinstance(result.test_results, list)
        assert "test_function" in result.summary or "function" in result.summary.lower()
        assert result.metadata is not None
        assert result.metadata["main_param"] == "input_text"
    
    @patch('hydroxai.compliance.function.executor.execute_function_scan')
    def test_scan_function_with_different_params(self, mock_execute):
        """Test scan_function with various parameter types."""
        def test_func1(arg1: str) -> str:
            return f"Result: {arg1}"
        
        def test_func2(items: list) -> str:
            return f"Items: {items}"
        
        def test_func3(number: int) -> int:
            return number * 2
        
        test_cases = [
            (test_func1, "arg1"),
            (test_func2, "items"),
            (test_func3, "number"),
        ]
        
        for func, main_param in test_cases:
            mock_result = ScanResult(
                model_name=f"function:{func.__name__}",
                overall_status=VulnerabilityStatus.NOT_VULNERABLE,
                test_results=[],
                summary=f"Function {func.__name__} scan completed",
                metadata={"main_param": main_param}
            )
            mock_execute.return_value = mock_result
            
            result = self.scanner.scan_function(function=func, main_param=main_param)
            assert isinstance(result, ScanResult)
            assert result.metadata["main_param"] == main_param
    
    @patch('hydroxai.compliance.function.executor.execute_function_scan')
    def test_scan_function_with_complex_code(self, mock_execute):
        """Test scan_function with more complex function code."""
        def fibonacci(n: int) -> int:
            if n <= 1:
                return n
            return fibonacci(n-1) + fibonacci(n-2)
        
        mock_result = ScanResult(
            model_name=f"function:fibonacci",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Function fibonacci scan completed",
            metadata={"main_param": "n"}
        )
        mock_execute.return_value = mock_result
        
        result = self.scanner.scan_function(function=fibonacci, main_param="n")
        assert isinstance(result, ScanResult)
        assert result.metadata["main_param"] == "n"
    
    @patch('hydroxai.compliance.chatbot.executor.execute_chatbot_scan')
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    @patch('hydroxai.compliance.function.executor.execute_function_scan')
    def test_all_scan_methods_return_scan_result(self, mock_func, mock_api, mock_chatbot, sample_url, sample_function_code):
        """Test that all scan methods return ScanResult objects."""
        # Setup mocks
        mock_chatbot.return_value = ScanResult(
            model_name=f"chatbot:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock chatbot scan",
            metadata={"url": sample_url}
        )
        
        mock_api.return_value = ScanResult(
            model_name=f"api:{sample_url}",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock API scan",
            metadata={"endpoint": sample_url, "method": "POST"}
        )
        
        def test_func(test_param: str) -> str:
            return f"Result: {test_param}"
        
        mock_func.return_value = ScanResult(
            model_name=f"function:test_func",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock function scan",
            metadata={"main_param": "test_param"}
        )
        
        # Test scan_chatbot
        chatbot_result = self.scanner.scan_chatbot(sample_url)
        assert isinstance(chatbot_result, ScanResult)
        
        # Test scan_api
        api_result = self.scanner.scan_api(endpoint=sample_url)
        assert isinstance(api_result, ScanResult)
        
        # Test scan_function
        function_result = self.scanner.scan_function(
            function=test_func, 
            main_param="test_param"
        )
        assert isinstance(function_result, ScanResult)
    
    @patch('hydroxai.compliance.chatbot.executor.execute_chatbot_scan')
    def test_scan_result_structure(self, mock_execute, sample_url, mock_scan_result):
        """Test that ScanResult has expected structure and methods."""
        mock_execute.return_value = mock_scan_result
        result = self.scanner.scan_chatbot(sample_url)
        
        # Check required attributes
        assert hasattr(result, 'model_name')
        assert hasattr(result, 'overall_status')
        assert hasattr(result, 'test_results')
        assert hasattr(result, 'summary')
        assert hasattr(result, 'metadata')
        
        # Check methods exist
        assert hasattr(result, 'get_results_by_type')
        assert hasattr(result, 'get_vulnerable_tests')
        assert hasattr(result, 'get_attack_methods_used')
        
        # Test method calls don't error - but only if test_results are proper objects
        if result.test_results and hasattr(result.test_results[0], 'vulnerability_status'):
            assert isinstance(result.get_vulnerable_tests(), list)
            assert isinstance(result.get_attack_methods_used(), list)


class TestScannerEdgeCases:
    """Test edge cases and error conditions for Scanner."""
    
    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.scanner = Scanner()
    
    @patch('hydroxai.compliance.chatbot.executor.execute_chatbot_scan')
    def test_scan_chatbot_with_empty_string_url(self, mock_execute):
        """Test scan_chatbot with empty string URL."""
        mock_result = ScanResult(
            model_name="chatbot:",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan",
            metadata={"url": ""}
        )
        mock_execute.return_value = mock_result
        
        result = self.scanner.scan_chatbot("")
        assert isinstance(result, ScanResult)
        assert result.metadata["url"] == ""
    
    @patch('hydroxai.compliance.api.executor.execute_api_scan_sync')
    def test_scan_api_with_empty_string_url(self, mock_execute):
        """Test scan_api with empty string URL."""
        mock_result = ScanResult(
            model_name="api:",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan",
            metadata={"endpoint": "", "method": "POST"}
        )
        mock_execute.return_value = mock_result
        
        result = self.scanner.scan_api(endpoint="")
        assert isinstance(result, ScanResult)
        assert result.metadata["endpoint"] == ""
    
    @patch('hydroxai.compliance.function.executor.execute_function_scan')
    def test_scan_function_with_empty_code(self, mock_execute):
        """Test scan_function with empty function code."""
        def empty_func(param: str) -> str:
            return ""
        
        mock_result = ScanResult(
            model_name="function:empty_func",
            overall_status=VulnerabilityStatus.NOT_VULNERABLE,
            test_results=[],
            summary="Mock scan",
            metadata={"main_param": "param"}
        )
        mock_execute.return_value = mock_result
        
        result = self.scanner.scan_function(function=empty_func, main_param="param")
        assert isinstance(result, ScanResult)
        assert result.metadata["main_param"] == "param"
    
    def test_scanner_timeout_property(self):
        """Test that timeout property is set correctly."""
        timeout_val = 123.45
        scanner = Scanner(timeout=timeout_val)
        assert scanner.timeout == timeout_val


if __name__ == "__main__":
    # Allow running tests directly with python test_scanner.py
    pytest.main([__file__])
