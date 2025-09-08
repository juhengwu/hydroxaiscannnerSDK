"""Jupyter-specific execution engine for chatbot scanning.

This module provides Jupyter Notebook compatible execution methods
that avoid the asyncio subprocess creation issues in Jupyter environments.
"""

import subprocess
import sys
import tempfile
import json
import os
from typing import Dict, Any, List, Optional

from ..types import ScanResult, VulnerabilityStatus


def is_jupyter_environment() -> bool:
    """Check if running in Jupyter environment."""
    return hasattr(sys, 'ps1') or 'ipykernel' in sys.modules or 'IPython' in sys.modules


def execute_chatbot_scan_jupyter(url: str, *, headless: bool = False, timeout: float = 60.0, tests_per_category: int = 3, categories: Optional[List[str]] = None, verbose: bool = False) -> ScanResult:
    """Execute chatbot scan in Jupyter environment using subprocess isolation.
    
    This function runs the scan in a separate Python process to avoid
    asyncio event loop conflicts in Jupyter environments.
    
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
        
    Note:
        This function is specifically designed for Jupyter environments
        where the standard asyncio approach fails due to event loop conflicts.
    """
    try:
        # Get the package root directory
        package_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        
        # Create a temporary Python script that will run the scan in a separate process
        script_content = f'''import asyncio
import json
import sys
import os

# Add the hydroxai package to the path
sys.path.insert(0, r"{package_root}")

from hydroxai.compliance.chatbot.interaction import scan_chatbot

async def main():
    try:
        result = await scan_chatbot("{url}", headless={headless}, timeout={timeout}, tests_per_category={tests_per_category}, categories={categories}, verbose={verbose})
        print("SCAN_RESULT_START")
        print(json.dumps(result))
        print("SCAN_RESULT_END")
    except Exception as e:
        print("SCAN_ERROR_START")
        print(json.dumps({{"error": str(e), "type": type(e).__name__}}))
        print("SCAN_ERROR_END")

if __name__ == "__main__":
    # Set event loop policy for Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())
'''
        
        # Write the script to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            script_path = f.name
        
        try:
            # Run the script in a separate process
            proc_result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                cwd=os.path.dirname(__file__)
            )
            
            # Parse the output
            output = proc_result.stdout
            
            if "SCAN_RESULT_START" in output and "SCAN_RESULT_END" in output:
                # Extract the JSON result
                start_idx = output.find("SCAN_RESULT_START") + len("SCAN_RESULT_START") + 1
                end_idx = output.find("SCAN_RESULT_END")
                json_str = output[start_idx:end_idx].strip()
                
                try:
                    scan_result = json.loads(json_str)
                    return _convert_to_scan_result(url, scan_result)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Failed to parse scan result JSON: {e}")
            
            elif "SCAN_ERROR_START" in output and "SCAN_ERROR_END" in output:
                # Extract the error
                start_idx = output.find("SCAN_ERROR_START") + len("SCAN_ERROR_START") + 1
                end_idx = output.find("SCAN_ERROR_END")
                json_str = output[start_idx:end_idx].strip()
                
                try:
                    error_info = json.loads(json_str)
                    raise RuntimeError(f"Scan failed: {error_info['error']}")
                except json.JSONDecodeError:
                    raise RuntimeError(f"Scan failed with unknown error")
            
            else:
                # Check for subprocess errors
                if proc_result.returncode != 0:
                    error_msg = proc_result.stderr or "Unknown subprocess error"
                    raise RuntimeError(f"Subprocess failed: {error_msg}")
                else:
                    raise RuntimeError("Unexpected output format from scan subprocess")
        
        finally:
            # Clean up the temporary file
            try:
                os.unlink(script_path)
            except OSError:
                pass  # Ignore cleanup errors
                
    except subprocess.TimeoutExpired:
        return ScanResult(
            model_name=f"chatbot:{url}",
            overall_status=VulnerabilityStatus.ERROR,
            test_results=[],
            summary=f"Scan timed out after {timeout} seconds",
            metadata={"url": url, "error": "timeout", "jupyter_mode": True}
        )
    except Exception as e:
        return ScanResult(
            model_name=f"chatbot:{url}",
            overall_status=VulnerabilityStatus.ERROR,
            test_results=[],
            summary=f"Failed to scan chatbot in Jupyter environment: {str(e)}",
            metadata={"url": url, "error": str(e), "jupyter_mode": True}
        )


def _convert_to_scan_result(url: str, async_result: Dict[str, Any]) -> ScanResult:
    """Convert async scan result to ScanResult format.
    
    Args:
        url: The chatbot URL that was scanned.
        async_result: Raw result from the async scan function.
        
    Returns:
        Formatted ScanResult object.
    """
    from ..types import StandardTestResult, PromptResponsePair
    
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
            "vulnerable": test.get('vulnerable', False),
            "scan_summary": test.get('summary', '')
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
            "scan_summary": async_result.get('summary', ''),
            "jupyter_mode": True
        }
    )
