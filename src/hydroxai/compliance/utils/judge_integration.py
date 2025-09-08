"""
Judge model integration utility for enhanced vulnerability assessment.

This module provides a unified interface for integrating judge model assessments
into all scanner types while maintaining fallback to basic judge functions.
"""

import os
from typing import Dict, Any, List, Optional

from ..judge.judge_model import judge_response_vulnerability, batch_judge_responses


def is_judge_model_available() -> bool:
    """
    Check if judge model can be used (OPENAI_API_KEY is available).
    
    Returns:
        bool: True if judge model can be used, False otherwise.
    """
    return bool(os.getenv('OPENAI_API_KEY'))


async def enhance_result_with_judge_model(
    result: Dict[str, Any],
    category: str,
    base_prompt: Optional[str] = None,
    base_response: Optional[str] = None
) -> Dict[str, Any]:
    """
    Enhance a single test result with judge model assessment.
    
    Args:
        result: Test result dictionary containing prompt and response
        category: The safety category being tested
        base_prompt: Optional base prompt for comparison
        base_response: Optional base response for comparison
        
    Returns:
        Enhanced result dictionary with judge model analysis
    """
    if not is_judge_model_available():
        return result
    
    try:
        prompt = result.get('prompt', '')
        response = result.get('response', '')
        
        if not prompt or not response:
            return result
        
        # Get judge model assessment
        judgment = await judge_response_vulnerability(
            prompt=prompt,
            response=response,
            category=category,
            base_prompt=base_prompt or "",
            base_response=base_response or ""
        )
        
        # Update result with judge model findings
        if judgment.get('status') == 'success':
            # Override basic judge with judge model assessment
            result.update({
                'vulnerable': judgment.get('vulnerable', result.get('vulnerable', False)),
                'confidence': judgment.get('confidence', 0.0),
                'analysis': judgment.get('analysis', ''),
                'risk_factors': judgment.get('risk_factors', []),
                'vulnerability_type': judgment.get('vulnerability_type', 'unknown'),
                'base_response_status': judgment.get('base_response_status', 'unknown'),
                'attack_response_status': judgment.get('attack_response_status', 'unknown'),
                'judge_model_used': True,
                'judge_model_status': 'success'
            })
        else:
            # Judge model failed, keep original assessment but add error info
            result.update({
                'judge_model_used': True,
                'judge_model_status': 'failed',
                'judge_model_error': judgment.get('error', 'Unknown error'),
                'analysis': judgment.get('analysis', 'Judge model assessment failed, using fallback method')
            })
    
    except Exception as e:
        # Judge model failed completely, keep original assessment
        result.update({
            'judge_model_used': True,
            'judge_model_status': 'error',
            'judge_model_error': str(e),
            'analysis': f'Judge model assessment failed: {str(e)}'
        })
    
    return result


async def enhance_results_with_judge_model(
    results: List[Dict[str, Any]],
    category: str,
    base_prompt: Optional[str] = None,
    base_response: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Enhance a batch of test results with judge model assessments.
    
    Args:
        results: List of test result dictionaries
        category: The safety category being tested
        base_prompt: Optional base prompt for comparison
        base_response: Optional base response for comparison
        
    Returns:
        List of enhanced result dictionaries with judge model analysis
    """
    if not is_judge_model_available():
        # Add fallback analysis for each result when judge model is not available
        for result in results:
            result.update({
                'judge_model_used': False,
                'judge_model_status': 'unavailable',
                'analysis': 'Judge model unavailable (OPENAI_API_KEY not found), using basic fallback assessment'
            })
        return results
    
    enhanced_results = []
    
    for result in results:
        enhanced_result = await enhance_result_with_judge_model(
            result=result,
            category=category,
            base_prompt=base_prompt,
            base_response=base_response
        )
        enhanced_results.append(enhanced_result)
    
    return enhanced_results


def update_vulnerability_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Update vulnerability counts based on judge model assessments.
    
    Args:
        results: List of enhanced test results
        
    Returns:
        Dictionary with updated counts
    """
    vulnerable_count = 0
    judge_model_used_count = 0
    judge_model_success_count = 0
    
    for result in results:
        if result.get('vulnerable', False):
            vulnerable_count += 1
        
        if result.get('judge_model_used', False):
            judge_model_used_count += 1
            
            if result.get('judge_model_status') == 'success':
                judge_model_success_count += 1
    
    return {
        'vulnerable_count': vulnerable_count,
        'judge_model_used_count': judge_model_used_count,
        'judge_model_success_count': judge_model_success_count,
        'total_count': len(results)
    }


def get_judge_model_summary(results: List[Dict[str, Any]]) -> str:
    """
    Generate a summary of judge model usage and results.
    
    Args:
        results: List of enhanced test results
        
    Returns:
        Summary string for judge model usage
    """
    counts = update_vulnerability_counts(results)
    
    if not is_judge_model_available():
        return "Judge model unavailable (OPENAI_API_KEY not found). Using basic fallback assessments."
    
    if counts['judge_model_used_count'] == 0:
        return "Judge model was not used for any tests."
    
    success_rate = (counts['judge_model_success_count'] / counts['judge_model_used_count']) * 100
    
    return (
        f"Judge model used for {counts['judge_model_used_count']}/{counts['total_count']} tests "
        f"(success rate: {success_rate:.1f}%). "
        f"Enhanced assessments found {counts['vulnerable_count']} vulnerabilities."
    )
