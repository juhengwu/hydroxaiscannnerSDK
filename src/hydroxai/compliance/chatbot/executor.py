"""Chatbot execution engine for async/sync integration.

This module handles the execution of chatbot tests and manages the async/sync
boundary to provide a clean synchronous interface for users.
"""

import asyncio
import concurrent.futures
import sys
from typing import Dict, List, Any, Optional

from .interaction import scan_chatbot as _scan_chatbot_async
from .executor_jupyter import is_jupyter_environment, execute_chatbot_scan_jupyter
from ..types import ScanResult, VulnerabilityStatus


def _setup_jupyter_event_loop():
    """Setup event loop policy for Jupyter compatibility on Windows."""
    if sys.platform == 'win32' and is_jupyter_environment():
        # Use SelectorEventLoop instead of ProactorEventLoop for Jupyter compatibility
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def execute_chatbot_scan(url: str, *, headless: bool = False, timeout: float = 60.0, tests_per_category: int = 3, categories: Optional[List[str]] = None, verbose: bool = False) -> ScanResult:
    """Execute chatbot scan with proper async/sync handling.
    
    This function manages the asyncio event loop handling and converts
    async results to the expected ScanResult format.
    
    Args:
        url: The URL of the chatbot to scan.
        headless: Whether to run browser in headless mode.
        timeout: Timeout for the scan operation in seconds.
        tests_per_category: Number of tests to run per category (default: 3, max: 100).
        categories: List of categories to test. Available: ["hate_speech", "sexual_content"].
                   If None, all categories will be tested.
        verbose: Whether to display detailed progress and results in terminal with colors.
        
    Returns:
        ScanResult containing vulnerability assessment and test results.
        
    Raises:
        Exception: If the scan fails due to network, browser, or other issues.
    """
    # Setup Jupyter-compatible event loop if needed
    _setup_jupyter_event_loop()
    
    try:
        # Special handling for Jupyter environment
        if is_jupyter_environment():
            return execute_chatbot_scan_jupyter(url, headless=headless, timeout=timeout, tests_per_category=tests_per_category, categories=categories, verbose=verbose)
        
        # Standard handling for regular Python environments
        try:
            # Check if we're in an existing event loop
            loop = asyncio.get_running_loop()
            
            # Use thread pool for existing loop environments
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    lambda: asyncio.run(_scan_chatbot_async(url, headless=headless, timeout=timeout, tests_per_category=tests_per_category, categories=categories, verbose=verbose))
                )
                result = future.result(timeout=timeout + 30)  # Add buffer for safety
                    
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            result = asyncio.run(_scan_chatbot_async(url, headless=headless, timeout=timeout, tests_per_category=tests_per_category, categories=categories, verbose=verbose))
        
        return _convert_to_scan_result(url, result)
        
    except Exception as e:
        return ScanResult(
            model_name=f"chatbot:{url}",
            overall_status=VulnerabilityStatus.ERROR,
            test_results=[],
            summary=f"Failed to scan chatbot at {url}: {str(e)}",
            metadata={"url": url, "error": str(e)}
        )


def _convert_to_scan_result(url: str, async_result: Dict[str, Any]) -> ScanResult:
    """Convert async scan result to ScanResult format.
    
    Args:
        url: The chatbot URL that was scanned.
        async_result: Raw result from the async scan function.
        
    Returns:
        Formatted ScanResult object.
    """
   
    overall_status = (
        VulnerabilityStatus.VULNERABLE 
        if async_result.get('vulnerable', False) 
        else VulnerabilityStatus.NOT_VULNERABLE
    )
    
    test_results = []
    for test in async_result.get('results', []):
        test_results.append({
            "test_id": test.get('test_id'),
            "category": test.get('category', 'SEXUAL_CONTENT'),
            "attack_method": test.get('attack_method', ''),
            "prompt": test.get('prompt', ''),
            "response": test.get('response', ''),
            "vulnerable": test.get('vulnerable', False),
            "status": test.get('status', 'unknown')
        })
    
    summary = (
        f"Chatbot security scan completed for {url}. "
        f"Risk level: {async_result.get('risk_level', 'unknown').upper()}. "
        f"Found {async_result.get('vulnerable_count', 0)} vulnerabilities "
        f"in {async_result.get('total_tests', 0)} tests."
    )
    
    return ScanResult(
        model_name=f"chatbot:{url}",
        overall_status=overall_status,
        test_results=test_results,
        summary=summary,
        metadata={
            "url": url,
            "test_type": async_result.get('test_type', 'sexual_content_security'),
            "total_tests": async_result.get('total_tests', 0),
            "successful_tests": async_result.get('successful_tests', 0),
            "vulnerable_count": async_result.get('vulnerable_count', 0),
            "risk_level": async_result.get('risk_level', 'unknown'),
            "vulnerable": async_result.get('vulnerable', False),
            "scan_summary": async_result.get('summary', '')
        }
    )
