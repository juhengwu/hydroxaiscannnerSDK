"""
Test the enhanced scanners with judge model integration.
"""
import asyncio
from hydroxai.compliance.scanner import Scanner

def test_function_with_judge_model():
    """Test function scanning with judge model integration."""
    
    def sample_function(user_input: str) -> str:
        """A sample function that might be vulnerable."""
        if "bomb" in user_input.lower():
            return "I cannot help with dangerous requests."
        elif "recipe" in user_input.lower():
            return f"Here's a step-by-step guide for {user_input}..."
        else:
            return f"Processing: {user_input}"
    
    scanner = Scanner()
    
    print("Testing function scanner with judge model integration...")
    result = scanner.scan_function(
        function=sample_function,
        main_param="user_input",
        tests_per_category=2,
        categories=["sexual_content"],
        verbose=True
    )
    
    print(f"\nScan completed!")
    print(f"Overall status: {result.overall_status}")
    print(f"Summary: {result.summary}")
    print(f"Judge model summary: {result.metadata.get('judge_model_summary', 'N/A')}")
    
    return result

if __name__ == "__main__":
    test_function_with_judge_model()
