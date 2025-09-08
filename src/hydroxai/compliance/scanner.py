from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from .chatbot.executor import execute_chatbot_scan
from .api.executor import execute_api_scan_sync
from .types import ScanResult, VulnerabilityStatus


class Scanner:
    """
    Main scanner class for testing AI models and chatbots for security vulnerabilities.
    
    This class provides a unified interface for scanning different types of AI systems
    including web-based chatbots, APIs, functions, agents, and MCP servers.
    """
    
    def __init__(self, *, timeout: float = 60.0) -> None:
        """
        Initialize the scanner.
        
        Args:
            timeout: Default timeout for scan operations in seconds.
        """
        self.timeout = timeout
        
        
        

    def scan_chatbot(self, url: str, *, headless: bool = False, tests_per_category: int = 3, categories: Optional[List[str]] = None, verbose: bool = False) -> ScanResult:
        """
        Scan a web-based chatbot for security vulnerabilities.
        
        This method performs automated security testing on web chatbots using
        predefined test payloads to detect potential vulnerabilities in content
        filtering and safety mechanisms.
        
        Args:
            url: The URL of the chatbot to scan (e.g., "https://chatgpt.com").
            headless: Whether to run the browser in headless mode. Default is False
                     for better debugging and monitoring during security tests.
            tests_per_category: Number of tests to run per category (default: 3, max: 100).
            categories: List of categories to test. Available: ["hate_speech", "sexual_content"].
                       If None, all categories will be tested.
            verbose: Whether to display detailed progress and results in terminal with colors.
                    Default is False. When True, shows real-time test results similar to pytest.
        
        Returns:
            ScanResult containing vulnerability assessment and detailed test results.
            
        Example:
            >>> scanner = Scanner()
            >>> result = scanner.scan_chatbot("https://chatgpt.com")
            >>> print(f"Risk level: {result.metadata['risk_level']}")
            >>> print(f"Vulnerabilities found: {result.metadata['vulnerable_count']}")
            
            >>> # Test only hate_speech category with 5 tests
            >>> result = scanner.scan_chatbot("https://chatgpt.com", categories=["hate_speech"], tests_per_category=5)
        """
        # Validate tests_per_category
        if tests_per_category < 1:
            tests_per_category = 3
        elif tests_per_category > 100:
            tests_per_category = 100
            
        return execute_chatbot_scan(url, headless=headless, timeout=self.timeout, tests_per_category=tests_per_category, categories=categories, verbose=verbose)







    def scan_api(
        self,
        *,
        endpoint: str,
        method: str = "POST",
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Any] = None,
        tests_per_category: int = 3,
        categories: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> ScanResult:
        """
        Scan an API endpoint for security vulnerabilities.
        
        This method performs automated security testing on LLM API endpoints by
        sending predefined attack prompts and analyzing responses for potential
        vulnerabilities in content filtering and safety mechanisms.
        
        Args:
            endpoint: The API endpoint HTTP URL to scan (e.g., "https://api.openai.com/v1/chat/completions").
            method: HTTP method to use (default: "POST").
            headers: Optional HTTP headers to include in requests. Can be a dictionary or JSON string.
            body: Optional request body data. Can be a dictionary or JSON string.
            tests_per_category: Number of tests to run per category (default: 3, max: 100).
            categories: List of categories to test. Available: ["hate_speech", "sexual_content"].
                       If None, all categories will be tested.
            verbose: Whether to display detailed progress and results in terminal with colors.
                    Default is False. When True, shows real-time test results similar to pytest.
            
        Returns:
            ScanResult containing comprehensive API vulnerability assessment with detailed
            test results for each attack prompt tested.
            
        Example:
            >>> scanner = Scanner()
            >>> result = scanner.scan_api(
            ...     endpoint="https://api.openai.com/v1/chat/completions",
            ...     method="POST",
            ...     headers={
            ...                 "Content-Type": "application/json",
            ...                 "Authorization": "Bearer sk-your-api-key"
            ...             }
            ...     body={
            ...                 "model": "gpt-4o-mini",
            ...                 "messages": [
            ...                             { "role": "user", "content": "What is the capital of France?" }
            ...                 ]
            ...          }
            ... )
            >>> print(f"Risk level: {result.metadata['risk_level']}")
            >>> print(f"Vulnerabilities found: {result.metadata['vulnerable_count']}")
            
            >>> # Test only sexual_content category with 5 tests
            >>> result = scanner.scan_api(endpoint="...", categories=["sexual_content"], tests_per_category=5)
        """
        
        if tests_per_category < 1:
            tests_per_category = 3
        elif tests_per_category > 100:
            tests_per_category = 100
            
        return execute_api_scan_sync(
            endpoint=endpoint,
            method=method,
            headers=headers,
            body=body,
            timeout=self.timeout,
            tests_per_category=tests_per_category,
            categories=categories,
            verbose=verbose
        )



    def scan_function(
        self, 
        function: Callable[..., Any], 
        main_param: str,
        *args, 
        tests_per_category: int = 3,
        categories: Optional[List[str]] = None,
        verbose: bool = False,
        **kwargs
    ) -> ScanResult:
        """
        Scan a function for security vulnerabilities by injecting malicious prompts.
        
        This method tests functions that call LLM APIs by replacing the specified main parameter
        with malicious prompts to detect potential vulnerabilities in content filtering and
        safety mechanisms.
        
        Args:
            function: The callable function to analyze (e.g., generate_recipe).
            main_param: The name of the main input parameter to replace with malicious prompts
                       (e.g., "ingredients" for a recipe generator function).
            *args: Positional arguments to pass to the function.
            tests_per_category: Number of tests to run per category (default: 3, max: 100).
            categories: List of categories to test. Available: ["hate_speech", "sexual_content"].
                       If None, all categories will be tested.
            verbose: Whether to display detailed progress and results in terminal with colors.
                    Default is False. When True, shows real-time test results similar to pytest.
            **kwargs: Keyword arguments to pass to the function.
            
        Returns:
            ScanResult containing function vulnerability assessment and detailed test results.
            
        Example:
            >>> def generate_recipe(ingredients: List[str]) -> str:
            ...     # Function that calls LLM API
            ...     return llm_call(f"Make recipe with {ingredients}")
            >>> scanner = Scanner()
            >>> result = scanner.scan_function(generate_recipe, main_param="ingredients")
            >>> print(f"Risk level: {result.metadata['risk_level']}")
            >>> print(f"Vulnerabilities found: {result.metadata['vulnerable_count']}")
            
            >>> # Test only hate_speech category with 5 tests
            >>> result = scanner.scan_function(func, "param", categories=["hate_speech"], tests_per_category=5)
        """
        
        from .function.executor import execute_function_scan
        
        if tests_per_category < 1:
            tests_per_category = 3
        elif tests_per_category > 100:
            tests_per_category = 100
        
        return execute_function_scan(
            function=function,
            main_param=main_param,
            timeout=self.timeout,
            tests_per_category=tests_per_category,
            categories=categories,
            verbose=verbose,
            *args,
            **kwargs
        )




    def scan_agent(self) -> ScanResult:
        """
        Scan an AI agent for security vulnerabilities.
        
        Returns:
            ScanResult containing agent vulnerability assessment.
            
        Note:
            This method is not yet implemented and returns a placeholder result.
        """
        return ScanResult(
            model_name="agent:unknown",
            overall_status=VulnerabilityStatus.UNCERTAIN,
            test_results=[],
            summary="Agent scanning not yet implemented",
            metadata={"implementation_status": "pending"}
        )




    def scan_mcp(self) -> ScanResult:
        """
        Scan a Model Context Protocol (MCP) server for security vulnerabilities.
        
        Returns:
            ScanResult containing MCP vulnerability assessment.
            
        Note:
            This method is not yet implemented and returns a placeholder result.
        """
        return ScanResult(
            model_name="mcp:unknown",
            overall_status=VulnerabilityStatus.UNCERTAIN,
            test_results=[],
            summary="MCP server scanning not yet implemented",
            metadata={"implementation_status": "pending"}
        )

