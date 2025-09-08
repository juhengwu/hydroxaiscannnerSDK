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
        assert result.model_name == "unknown"
        assert result.overall_status == VulnerabilityStatus.NOT_VULNERABLE
        assert isinstance(result.test_results, list)
        assert result.summary == f"Scanned chatbot at {sample_url}"
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
            url=sample_url,
            method="POST", 
            headers=sample_headers,
            body=sample_api_body
        )
        
        # Assert
        assert isinstance(result, ScanResult)
        assert result.model_name == "unknown"
        assert result.overall_status == VulnerabilityStatus.NOT_VULNERABLE
        assert isinstance(result.test_results, list)
        assert result.summary == f"Scanned API POST {sample_url}"
        assert result.metadata is not None
        assert result.metadata["url"] == sample_url
        assert result.metadata["method"] == "POST"
        assert result.metadata["headers"] == sample_headers
        assert result.metadata["body"] == sample_api_body
    
    def test_scan_api_with_different_methods(self, sample_url):
        """Test scan_api with different HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        
        for method in methods:
            result = self.scanner.scan_api(url=sample_url, method=method)
            assert isinstance(result, ScanResult)
            assert result.metadata["method"] == method
            assert method.upper() in result.summary
    
    def test_scan_api_minimal_parameters(self, sample_url):
        """Test scan_api with minimal required parameters."""
        # Only URL is required, others should have defaults
        result = self.scanner.scan_api(url=sample_url)
        
        assert isinstance(result, ScanResult)
        assert result.metadata["url"] == sample_url
        assert result.metadata["method"] == "POST"  # default method
        assert result.metadata["headers"] == {}  # empty dict for None headers
        assert result.metadata["body"] is None
    
    def test_scan_api_with_none_headers(self, sample_url):
        """Test scan_api handles None headers correctly."""
        result = self.scanner.scan_api(url=sample_url, headers=None)
        
        assert isinstance(result, ScanResult)
        assert result.metadata["headers"] == {}
    
    def test_scan_function_basic_call(self, sample_function_params, sample_function_code):
        """Test scan_function method can be called without errors."""
        # Act
        result = self.scanner.scan_function(
            main_params=sample_function_params,
            function_code=sample_function_code
        )
        
        # Assert
        assert isinstance(result, ScanResult)
        assert result.model_name == "unknown"
        assert result.overall_status == VulnerabilityStatus.NOT_VULNERABLE
        assert isinstance(result.test_results, list)
        assert result.summary == f"Scanned function {sample_function_code}"
        assert result.metadata is not None
        assert result.metadata["params"] == sample_function_params
        assert result.metadata["function_code"] == sample_function_code
    
    def test_scan_function_with_different_params(self):
        """Test scan_function with various parameter types."""
        test_cases = [
            ({"arg1": "value1"}, "def test1(): pass"),
            (["item1", "item2"], "def test2(items): return items"),
            (42, "def test3(number): return number * 2"),
            (None, "def test4(): return None"),
        ]
        
        for params, code in test_cases:
            result = self.scanner.scan_function(main_params=params, function_code=code)
            assert isinstance(result, ScanResult)
            assert result.metadata["params"] == params
            assert result.metadata["function_code"] == code
    
    def test_scan_function_with_complex_code(self):
        """Test scan_function with more complex function code."""
        complex_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""
        params = {"n": 10}
        
        result = self.scanner.scan_function(main_params=params, function_code=complex_code)
        assert isinstance(result, ScanResult)
        assert result.metadata["function_code"] == complex_code
    
    def test_all_scan_methods_return_scan_result(self, sample_url, sample_function_code):
        """Test that all scan methods return ScanResult objects."""
        # Test scan_chatbot
        chatbot_result = self.scanner.scan_chatbot(sample_url)
        assert isinstance(chatbot_result, ScanResult)
        
        # Test scan_api
        api_result = self.scanner.scan_api(url=sample_url)
        assert isinstance(api_result, ScanResult)
        
        # Test scan_function
        function_result = self.scanner.scan_function(
            main_params={"test": True}, 
            function_code=sample_function_code
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
        
        # Test method calls don't error
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
        result = self.scanner.scan_api(url="")
        assert isinstance(result, ScanResult)
        assert result.metadata["url"] == ""
    
    def test_scan_function_with_empty_code(self):
        """Test scan_function with empty function code."""
        result = self.scanner.scan_function(main_params={}, function_code="")
        assert isinstance(result, ScanResult)
        assert result.metadata["function_code"] == ""
    
    def test_scanner_timeout_property(self):
        """Test that timeout property is set correctly."""
        timeout_val = 123.45
        scanner = Scanner(timeout=timeout_val)
        assert scanner.timeout == timeout_val


if __name__ == "__main__":
    # Allow running tests directly with python test_scanner.py
    pytest.main([__file__])
