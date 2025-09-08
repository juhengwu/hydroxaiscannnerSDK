#!/usr/bin/env python3
"""
Test script for the enhanced scanner with immediate judge model integration.
Tests that judge model assessment happens immediately after each test.
"""

import asyncio
from src.hydroxai.compliance.scanner import Scanner
from src.hydroxai.compliance.utils.judge_integration import is_judge_model_available

def test_function(user_input: str) -> str:
    """Simple test function that returns user input."""
    return f"You said: {user_input}"

async def test_chatbot_scanner():
    """Test chatbot scanner with immediate judge model integration."""
    print("=== Testing Chatbot Scanner ===")
    
    if is_judge_model_available():
        print("✓ Judge model is available (OPENAI_API_KEY found)")
    else:
        print("⚠ Judge model unavailable (OPENAI_API_KEY not found)")
    
    scanner = Scanner()
    
    # Test a simple chatbot URL (this will likely fail but should show the workflow)
    try:
        result = scanner.scan_chatbot(
            url="https://example.com",  # This will fail but shows the process
            tests_per_category=2,
            categories=["sexual_content"],
            verbose=True,
            headless=True
        )
        print(f"Scan completed with status: {result.overall_status}")
    except Exception as e:
        print(f"Chatbot scan failed (expected): {e}")

def test_function_scanner():
    """Test function scanner with immediate judge model integration."""
    print("\n=== Testing Function Scanner ===")
    
    if is_judge_model_available():
        print("✓ Judge model is available (OPENAI_API_KEY found)")
    else:
        print("⚠ Judge model unavailable (OPENAI_API_KEY not found)")
    
    scanner = Scanner()
    
    # Test function scanner
    try:
        result = scanner.scan_function(
            function=test_function,
            main_param="user_input",
            tests_per_category=2,
            categories=["sexual_content"],
            verbose=True
        )
        print(f"Function scan completed with status: {result.overall_status}")
        print(f"Summary: {result.summary}")
        
        # Print analysis from enhanced results
        for test_result in result.test_results:
            analysis = test_result.metadata.get('analysis', '')
            if analysis:
                print(f"Analysis for {test_result.test_id}: {analysis}")
                
    except Exception as e:
        print(f"Function scan failed: {e}")

async def test_api_scanner():
    """Test API scanner with immediate judge model integration."""
    print("\n=== Testing API Scanner ===")
    
    if is_judge_model_available():
        print("✓ Judge model is available (OPENAI_API_KEY found)")
    else:
        print("⚠ Judge model unavailable (OPENAI_API_KEY not found)")
    
    scanner = Scanner()
    
    # Test API scanner with a mock endpoint
    try:
        result = scanner.scan_api(
            endpoint="https://httpbin.org/post",  # This should work for testing
            method="POST",
            headers={"Content-Type": "application/json"},
            body={"message": "test"},
            tests_per_category=2,
            categories=["sexual_content"],
            verbose=True
        )
        print(f"API scan completed with status: {result.overall_status}")
        print(f"Summary: {result.summary}")
        
        # Print analysis from enhanced results
        for test_result in result.test_results:
            analysis = test_result.metadata.get('analysis', '')
            if analysis:
                print(f"Analysis for {test_result.test_id}: {analysis}")
                
    except Exception as e:
        print(f"API scan failed: {e}")

async def main():
    """Run all tests."""
    print("Testing Enhanced Scanner with Immediate Judge Model Integration")
    print("=" * 70)
    
    # Test function scanner (synchronous)
    test_function_scanner()
    
    # Test chatbot scanner (asynchronous)
    await test_chatbot_scanner()
    
    # Test API scanner (asynchronous)
    await test_api_scanner()
    
    print("\n" + "=" * 70)
    print("All tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
