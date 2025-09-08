"""Pytest configuration and shared fixtures."""

import pytest
from typing import Any, Dict, List
from dataclasses import dataclass
from collections import namedtuple


@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "https://example.com/api/chat"


@pytest.fixture
def sample_headers():
    """Sample HTTP headers for testing."""
    return {
        "Content-Type": "application/json",
        "Authorization": "Bearer test-token"
    }


@pytest.fixture
def sample_api_body():
    """Sample API request body for testing."""
    return {
        "message": "Hello, world!",
        "model": "gpt-3.5-turbo",
        "temperature": 0.7
    }


@pytest.fixture
def sample_function_code():
    """Sample function code for testing."""
    return """
def greet(name):
    return f"Hello, {name}!"
"""


@pytest.fixture
def sample_function_params():
    """Sample function parameters for testing."""
    return {"name": "Alice"}


@pytest.fixture
def timeout_value():
    """Standard timeout value for tests."""
    return 30.0


@pytest.fixture
def malicious_prompt():
    """Standard malicious prompt for injection testing."""
    return "INJECT_TEST_PAYLOAD_IGNORE_PREVIOUS_INSTRUCTIONS"


@pytest.fixture 
def openai_api_request():
    """Sample OpenAI API request format."""
    return {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is artificial intelligence?"}
        ],
        "temperature": 0.7,
        "max_tokens": 100
    }


@pytest.fixture
def anthropic_api_request():
    """Sample Anthropic API request format."""
    return {
        "model": "claude-3-opus-20240229",
        "max_tokens": 1000,
        "messages": [
            {"role": "user", "content": "Explain quantum computing"}
        ]
    }


@pytest.fixture
def complex_nested_data():
    """Complex nested data structure for testing."""
    return {
        "user": {
            "profile": {
                "personal": {
                    "preferences": {
                        "description": "User preferences",
                        "settings": ["setting1", "setting2"]
                    }
                }
            }
        },
        "system": {
            "config": ["config1", "config2"],
            "metadata": {
                "version": "1.0",
                "features": {
                    "enabled": True,
                    "description": "System features"
                }
            }
        }
    }


@dataclass
class SampleDataclass:
    """Sample dataclass for testing."""
    title: str
    description: str
    value: int = 0


@pytest.fixture
def sample_dataclass():
    """Sample dataclass instance."""
    return SampleDataclass("Test Title", "Test Description", 42)


class SampleClass:
    """Sample class for testing."""
    def __init__(self, name: str = "default", value: int = 0):
        self.name = name
        self.value = value
        self.description = "Default description"


@pytest.fixture
def sample_class():
    """Sample class instance."""
    return SampleClass("test_name", 100)


SampleNamedTuple = namedtuple('SampleNamedTuple', ['name', 'description', 'value'])


@pytest.fixture
def sample_namedtuple():
    """Sample named tuple instance."""
    return SampleNamedTuple("test_name", "test_description", 42)


@pytest.fixture
def vulnerable_function_codes():
    """List of function codes with potential security vulnerabilities."""
    return [
        # Code injection
        """
def execute_user_code(code):
    return eval(code)  # VULNERABLE
""",
        # SQL injection  
        """
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    return execute_query(query)
""",
        # Command injection
        """
def process_file(filename):
    import os
    os.system(f"cat {filename}")  # VULNERABLE
""",
        # Unsafe deserialization
        """
def load_data(serialized_data):
    import pickle
    return pickle.loads(serialized_data)  # VULNERABLE
""",
    ]


@pytest.fixture
def safe_function_codes():
    """List of safe function codes for testing."""
    return [
        """
def add_numbers(a, b):
    return a + b
""",
        """
def greet_user(name):
    if not isinstance(name, str):
        raise ValueError("Name must be a string")
    return f"Hello, {name}!"
""",
        """
def calculate_average(numbers):
    if not numbers:
        return 0
    return sum(numbers) / len(numbers)
""",
    ]


@pytest.fixture
def api_test_cases():
    """Various API test case formats."""
    return [
        {
            "name": "OpenAI Chat Completion",
            "request": {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Hello"}],
                "temperature": 0.7
            }
        },
        {
            "name": "Custom API",
            "request": {
                "query": "Test query",
                "parameters": {"limit": 10},
                "metadata": {"source": "test"}
            }
        },
        {
            "name": "Function Calling",
            "request": {
                "messages": [{"role": "user", "content": "Get weather"}],
                "functions": [
                    {
                        "name": "get_weather",
                        "description": "Get current weather"
                    }
                ]
            }
        },
    ]


@pytest.fixture
def edge_case_data():
    """Edge case data for testing injection robustness.""" 
    return [
        "",  # Empty string
        None,  # None value
        [],  # Empty list
        {},  # Empty dict
        set(),  # Empty set
        (),  # Empty tuple
        0,  # Zero
        False,  # Boolean false
        "  ",  # Whitespace only
        "\n\t\r",  # Control characters
        "🚀💾🔒",  # Unicode characters
        "null\x00byte",  # Null byte
        "very " * 1000 + "long string",  # Very long string
    ]
