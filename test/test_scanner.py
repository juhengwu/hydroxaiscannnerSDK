"""
Unit tests for the Scanner class.

This module contains basic functionality tests for the Scanner methods:
- scan_chatbot
- scan_api  
- scan_function

Tests focus on ensuring methods can be called without errors and return expected types.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Any, Dict, Optional

# Import the classes we want to test
from hydroxai.compliance.scanner import Scanner
from hydroxai.compliance.types import ScanResult, VulnerabilityStatus


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
    
    def test_scan_chatbot_basic_call(self, sample_url):
        """Test scan_chatbot method can be called without errors."""
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
    
    def test_scan_chatbot_with_different_urls(self):
        """Test scan_chatbot with various URL formats."""
        test_urls = [
            "https://example.com/chat",
            "http://localhost:8080/api/chat",
            "https://api.openai.com/v1/chat/completions"
        ]
        
        for url in test_urls:
            result = self.scanner.scan_chatbot(url)
            assert isinstance(result, ScanResult)
            assert result.metadata["url"] == url
    
    def test_scan_api_basic_call(self, sample_url, sample_headers, sample_api_body):
        """Test scan_api method can be called without errors."""
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
    
    def test_scan_api_with_different_methods(self, sample_url):
        """Test scan_api with different HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        
        for method in methods:
            result = self.scanner.scan_api(endpoint=sample_url, method=method)
            assert isinstance(result, ScanResult)
            assert result.metadata["method"] == method
    
    def test_scan_api_minimal_parameters(self, sample_url):
        """Test scan_api with minimal required parameters."""
        # Only endpoint is required, others should have defaults
        result = self.scanner.scan_api(endpoint=sample_url)
        
        assert isinstance(result, ScanResult)
        assert result.metadata["endpoint"] == sample_url
        assert result.metadata["method"] == "POST"  # default method
    
    def test_scan_api_with_none_headers(self, sample_url):
        """Test scan_api handles None headers correctly."""
        result = self.scanner.scan_api(endpoint=sample_url, headers=None)
        
        assert isinstance(result, ScanResult)
    
    def test_scan_function_basic_call(self, sample_function_params, sample_function_code):
        """Test scan_function method can be called without errors."""
        # Create a simple test function
        def test_function(input_text: str) -> str:
            return f"Processed: {input_text}"
        
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
    
    def test_scan_function_with_different_params(self):
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
            result = self.scanner.scan_function(function=func, main_param=main_param)
            assert isinstance(result, ScanResult)
            assert result.metadata["main_param"] == main_param
    
    def test_scan_function_with_complex_code(self):
        """Test scan_function with more complex function code."""
        def fibonacci(n: int) -> int:
            if n <= 1:
                return n
            return fibonacci(n-1) + fibonacci(n-2)
        
        result = self.scanner.scan_function(function=fibonacci, main_param="n")
        assert isinstance(result, ScanResult)
        assert result.metadata["main_param"] == "n"
    
    def test_all_scan_methods_return_scan_result(self, sample_url, sample_function_code):
        """Test that all scan methods return ScanResult objects."""
        # Test scan_chatbot
        chatbot_result = self.scanner.scan_chatbot(sample_url)
        assert isinstance(chatbot_result, ScanResult)
        
        # Test scan_api
        api_result = self.scanner.scan_api(endpoint=sample_url)
        assert isinstance(api_result, ScanResult)
        
        # Test scan_function
        # Test scan_function
        def test_func(test_param: str) -> str:
            return f"Result: {test_param}"
        
        function_result = self.scanner.scan_function(
            function=test_func, 
            main_param="test_param"
        )
        assert isinstance(function_result, ScanResult)
    
    def test_scan_result_structure(self, sample_url):
        """Test that ScanResult has expected structure and methods."""
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
    
    def test_scan_chatbot_with_empty_string_url(self):
        """Test scan_chatbot with empty string URL."""
        result = self.scanner.scan_chatbot("")
        assert isinstance(result, ScanResult)
        assert result.metadata["url"] == ""
    
    def test_scan_api_with_empty_string_url(self):
        """Test scan_api with empty string URL."""
        result = self.scanner.scan_api(endpoint="")
        assert isinstance(result, ScanResult)
        assert result.metadata["endpoint"] == ""
    
    def test_scan_function_with_empty_code(self):
        """Test scan_function with empty function code."""
        def empty_func(param: str) -> str:
            return ""
        
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
