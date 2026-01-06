from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Union
from abc import ABC, abstractmethod
from enum import Enum
import sys


class VulnerabilityStatus(Enum):
    """Vulnerability status enumeration."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNCERTAIN = "uncertain"
    ERROR = "error"


# Use slots=True only for Python 3.10+
_dataclass_kwargs = {"slots": True} if sys.version_info >= (3, 10) else {}


@dataclass(**_dataclass_kwargs)
class PromptResponsePair:
    """A single prompt-response interaction pair.
    
    Args:
        prompt: The input prompt text
        response: The model's response text
        prompt_type: Type of prompt (e.g., "base", "attack", "benign")
        metadata: Additional metadata for this interaction
    """
    prompt: str
    response: str
    prompt_type: str = "base"
    metadata: Optional[Dict[str, Any]] = None


@dataclass(**_dataclass_kwargs)
class JudgeAnalysis:
    """Analysis result from a judge model.
    
    Args:
        judge_model: Name or identifier of the judge model
        verdict: The judge's verdict/decision
        confidence: Confidence score (0.0 to 1.0)
        reasoning: Detailed reasoning for the verdict
        metadata: Additional analysis metadata
    """
    judge_model: str
    verdict: str
    confidence: float
    reasoning: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass(**_dataclass_kwargs)
class BaseTestResult(ABC):
    """Base class for all test result types.
    
    Args:
        test_type: Type of test performed
        vulnerability_status: Whether a vulnerability was found
        attack_method: The attack method used (from payload configuration)
        interactions: List of prompt-response pairs
        test_id: Optional unique identifier for the test
        judge_analysis: Analysis from judge model(s)
        metadata: Additional test metadata
    """
    test_type: str
    vulnerability_status: VulnerabilityStatus
    attack_method: str
    interactions: List[PromptResponsePair]
    test_id: str = ""
    judge_analysis: Optional[List[JudgeAnalysis]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass(**_dataclass_kwargs)
class StandardTestResult(BaseTestResult):
    """Standard test result for prompt injection, jailbreak, etc.
    
    This is used for tests that follow the pattern of:
    base_prompt -> base_response -> attack_prompt -> attack_response -> judge
    """
    pass


@dataclass(**_dataclass_kwargs)
class HallucinationTestResult(BaseTestResult):
    """Specialized test result for hallucination detection.
    
    Args:
        question: The question asked to the model
        ground_truth: The correct/expected answer
        model_response: The actual model response
        has_hallucination: Whether hallucination was detected
        hallucination_details: Specific details about the hallucination
    """
    question: str = ""
    ground_truth: str = ""
    model_response: str = ""
    has_hallucination: bool = False
    hallucination_details: Optional[Dict[str, Any]] = None


@dataclass(**_dataclass_kwargs)
class BiasTestResult(BaseTestResult):
    """Specialized test result for bias detection.
    
    Args:
        demographic_groups: List of demographic groups tested
        bias_scores: Bias scores for each group
        fairness_metrics: Computed fairness metrics
        biased_responses: Responses that showed bias
    """
    demographic_groups: List[str] = None
    bias_scores: Dict[str, float] = None
    fairness_metrics: Dict[str, float] = None
    biased_responses: List[PromptResponsePair] = None
    
    def __post_init__(self):
        if self.demographic_groups is None:
            self.demographic_groups = []
        if self.bias_scores is None:
            self.bias_scores = {}
        if self.fairness_metrics is None:
            self.fairness_metrics = {}
        if self.biased_responses is None:
            self.biased_responses = []


@dataclass(**_dataclass_kwargs)
class ScanResult:
    """Comprehensive scan result containing multiple test results.
    
    Args:
        model_name: Name of the model being tested
        overall_status: Overall vulnerability status across all tests
        test_results: List of individual test results (all inherit from BaseTestResult)
        summary: Summary of the scan results
        metadata: Additional scan metadata
    """
    model_name: str
    overall_status: VulnerabilityStatus
    test_results: List[BaseTestResult]
    summary: str = ""
    metadata: Optional[Dict[str, Any]] = None
    
    def get_results_by_type(self, result_type: type) -> List[BaseTestResult]:
        """Get test results filtered by specific type."""
        return [result for result in self.test_results if isinstance(result, result_type)]
    
    def get_vulnerable_tests(self) -> List[BaseTestResult]:
        """Get all test results that indicate vulnerabilities."""
        return [
            result for result in self.test_results 
            if result.vulnerability_status == VulnerabilityStatus.VULNERABLE
        ]
    
    def get_attack_methods_used(self) -> List[str]:
        """Get list of unique attack methods used in the scan."""
        return list(set(result.attack_method for result in self.test_results))
    
    def get_results_by_status(self, status: VulnerabilityStatus) -> List[BaseTestResult]:
        """Get test results filtered by vulnerability status."""
        return [
            result for result in self.test_results 
            if result.vulnerability_status == status
        ]
    
    def get_test_summary(self) -> Dict[str, int]:
        """Get summary statistics of test results."""
        summary = {
            "total_tests": len(self.test_results),
            "vulnerable": 0,
            "not_vulnerable": 0,
            "uncertain": 0,
            "error": 0
        }
        
        for result in self.test_results:
            if result.vulnerability_status == VulnerabilityStatus.VULNERABLE:
                summary["vulnerable"] += 1
            elif result.vulnerability_status == VulnerabilityStatus.NOT_VULNERABLE:
                summary["not_vulnerable"] += 1
            elif result.vulnerability_status == VulnerabilityStatus.UNCERTAIN:
                summary["uncertain"] += 1
            elif result.vulnerability_status == VulnerabilityStatus.ERROR:
                summary["error"] += 1
        
        return summary