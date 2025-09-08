"""
Comprehensive unit tests for the inject_malicious_prompt function.

This module contains extensive tests for the inject_malicious_prompt function
to ensure it properly handles all common data types and edge cases found in
typical development environments.
"""

import pytest
from dataclasses import dataclass
from typing import NamedTuple, List, Dict, Set, Any, Optional
from collections import namedtuple
from unittest.mock import Mock

# Import the function we want to test
from hydroxai.compliance.function.executor import inject_malicious_prompt


# Test data and custom types for testing
MALICIOUS_PROMPT = "INJECT_TEST_PAYLOAD"


# Custom classes for testing
class SimpleClass:
    def __init__(self, name: str = "default", value: int = 0):
        self.name = name
        self.value = value


class ComplexClass:
    def __init__(self):
        self.description = "original description"
        self.content = "original content"
        self.metadata = {"key": "value"}
        self.items = ["item1", "item2"]
        self.count = 42


@dataclass
class DataclassExample:
    title: str
    description: str
    value: int = 0


@dataclass
class DataclassWithLists:
    messages: List[str]
    tags: Set[str]
    metadata: Dict[str, Any]


class NamedTupleExample(NamedTuple):
    name: str
    description: str
    value: int


class ImmutableClass:
    __slots__ = ['_name', '_value']
    
    def __init__(self, name: str, value: int):
        object.__setattr__(self, '_name', name)
        object.__setattr__(self, '_value', value)
    
    @property
    def name(self):
        return self._name
    
    @property 
    def value(self):
        return self._value


class NestedClass:
    def __init__(self):
        self.simple = SimpleClass("nested", 123)
        self.data = {"nested_key": "nested_value"}


class TestInjectMaliciousPromptBasicTypes:
    """Test inject_malicious_prompt with basic Python types."""
    
    def test_inject_into_string(self):
        """Test injection into string type."""
        original = "original string"
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT
        assert isinstance(result, str)
    
    def test_inject_into_empty_string(self):
        """Test injection into empty string."""
        original = ""
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT
    
    def test_inject_into_none(self):
        """Test injection into None value."""
        original = None
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT
    
    def test_inject_into_integer(self):
        """Test injection into integer - should return malicious prompt."""
        original = 42
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT
    
    def test_inject_into_float(self):
        """Test injection into float - should return malicious prompt."""
        original = 3.14
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT
    
    def test_inject_into_boolean(self):
        """Test injection into boolean - should return malicious prompt."""
        original = True
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == MALICIOUS_PROMPT


class TestInjectMaliciousPromptListTypes:
    """Test inject_malicious_prompt with list types."""
    
    def test_inject_into_empty_list(self):
        """Test injection into empty list."""
        original = []
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == [MALICIOUS_PROMPT]
        assert isinstance(result, list)
    
    def test_inject_into_string_list(self):
        """Test injection into list containing strings."""
        original = ["string1", "string2", "string3"]
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result[0] == MALICIOUS_PROMPT
        assert result[1] == "string2"
        assert result[2] == "string3"
        assert len(result) == 3
    
    def test_inject_into_mixed_list(self):
        """Test injection into list with mixed types."""
        original = [42, "string", 3.14]
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result[0] == 42
        assert result[1] == MALICIOUS_PROMPT
        assert result[2] == 3.14
    
    def test_inject_into_nested_list(self):
        """Test injection into nested list structure."""
        original = [["nested1", "nested2"], ["nested3"]]
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should replace the first element (which is a list) with the malicious prompt
        assert result[0] == MALICIOUS_PROMPT
        assert result[1] == ["nested3"]
    
    def test_inject_into_number_only_list(self):
        """Test injection into list with only numbers."""
        original = [1, 2, 3]
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should replace first element since no strings found
        assert result[0] == MALICIOUS_PROMPT
        assert result[1] == 2
        assert result[2] == 3
    
    def test_inject_into_list_with_objects(self):
        """Test injection into list containing custom objects."""
        obj = SimpleClass("test", 100)
        original = [obj, "string"]
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into the object, not the string
        assert result[0].name == MALICIOUS_PROMPT
        assert result[1] == "string"


class TestInjectMaliciousPromptDictTypes:
    """Test inject_malicious_prompt with dictionary types."""
    
    def test_inject_into_empty_dict(self):
        """Test injection into empty dictionary."""
        original = {}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result["malicious_input"] == MALICIOUS_PROMPT
        assert len(result) == 1
    
    def test_inject_into_string_dict(self):
        """Test injection into dictionary with string values."""
        original = {"key1": "value1", "key2": "value2"}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result["key1"] == MALICIOUS_PROMPT
        assert result["key2"] == "value2"
    
    def test_inject_into_priority_field_dict(self):
        """Test injection into dictionary with priority fields."""
        original = {
            "random_key": "random_value",
            "description": "original description",
            "other_key": "other_value"
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should prioritize 'description' field
        assert result["description"] == MALICIOUS_PROMPT
        assert result["random_key"] == "random_value"
        assert result["other_key"] == "other_value"
    
    def test_inject_into_mixed_type_dict(self):
        """Test injection into dictionary with mixed value types."""
        original = {"number": 42, "text": "string", "flag": True}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result["text"] == MALICIOUS_PROMPT
        assert result["number"] == 42
        assert result["flag"] == True
    
    def test_inject_into_nested_dict(self):
        """Test injection into nested dictionary structure."""
        original = {
            "level1": {
                "level2": {
                    "message": "deep message"
                }
            },
            "simple": "top level"
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into first string found (simple)
        assert result["simple"] == MALICIOUS_PROMPT
        assert result["level1"]["level2"]["message"] == "deep message"
    
    def test_inject_priority_field_order(self):
        """Test that priority fields are correctly ordered."""
        test_cases = [
            {"description": "desc", "content": "cont"},  # description wins
            {"content": "cont", "message": "msg"},       # content wins
            {"message": "msg", "text": "txt"},           # message wins
            {"text": "txt", "query": "qry"},             # text wins
        ]
        
        for original in test_cases:
            result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
            first_key = next(iter(original.keys()))
            assert result[first_key] == MALICIOUS_PROMPT


class TestInjectMaliciousPromptSetTypes:
    """Test inject_malicious_prompt with set types."""
    
    def test_inject_into_empty_set(self):
        """Test injection into empty set."""
        original = set()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert MALICIOUS_PROMPT in result
        assert len(result) == 1
    
    def test_inject_into_string_set(self):
        """Test injection into set containing strings."""
        original = {"string1", "string2", "string3"}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert MALICIOUS_PROMPT in result
        assert len(result) == 3  # One string replaced
        # Check that one string was replaced
        remaining_strings = result - {MALICIOUS_PROMPT}
        assert len(remaining_strings) == 2
    
    def test_inject_into_mixed_set(self):
        """Test injection into set with mixed types."""
        original = {42, "string", 3.14}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert MALICIOUS_PROMPT in result
        assert 42 in result
        assert 3.14 in result
        assert len(result) == 3
    
    def test_inject_into_number_only_set(self):
        """Test injection into set with only numbers."""
        original = {1, 2, 3}
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert MALICIOUS_PROMPT in result
        assert len(result) == 4  # Added to set


class TestInjectMaliciousPromptTupleTypes:
    """Test inject_malicious_prompt with tuple types."""
    
    def test_inject_into_regular_tuple(self):
        """Test injection into regular tuple."""
        original = ("string1", "string2", 42)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, tuple)
        assert result[0] == MALICIOUS_PROMPT
        assert result[1] == "string2"
        assert result[2] == 42
    
    def test_inject_into_empty_tuple(self):
        """Test injection into empty tuple."""
        original = ()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result == (MALICIOUS_PROMPT,)
    
    def test_inject_into_number_tuple(self):
        """Test injection into tuple with only numbers."""
        original = (1, 2, 3)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result[0] == MALICIOUS_PROMPT
        assert result[1] == 2
        assert result[2] == 3
    
    def test_inject_into_namedtuple(self):
        """Test injection into NamedTuple."""
        original = NamedTupleExample("test_name", "test_description", 42)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, NamedTupleExample)
        # Should inject into description (priority field)
        assert result.description == MALICIOUS_PROMPT
        assert result.name == "test_name"
        assert result.value == 42


class TestInjectMaliciousPromptCustomObjects:
    """Test inject_malicious_prompt with custom object types."""
    
    def test_inject_into_simple_class(self):
        """Test injection into simple custom class."""
        original = SimpleClass("original_name", 100)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, SimpleClass)
        assert result.name == MALICIOUS_PROMPT
        assert result.value == 100
    
    def test_inject_into_complex_class(self):
        """Test injection into complex class with priority fields."""
        original = ComplexClass()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, ComplexClass)
        # Should inject into description (priority field)
        assert result.description == MALICIOUS_PROMPT
        assert result.content == "original content"
        assert result.count == 42
    
    def test_inject_into_dataclass(self):
        """Test injection into dataclass."""
        original = DataclassExample("original_title", "original_description", 100)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, DataclassExample)
        # Should inject into description (priority field)
        assert result.description == MALICIOUS_PROMPT
        assert result.title == "original_title"
        assert result.value == 100
    
    def test_inject_into_dataclass_with_collections(self):
        """Test injection into dataclass containing collections."""
        original = DataclassWithLists(
            messages=["msg1", "msg2"],
            tags={"tag1", "tag2"},
            metadata={"key": "value"}
        )
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, DataclassWithLists)
        # Should inject into first string in messages
        assert result.messages[0] == MALICIOUS_PROMPT
        assert result.messages[1] == "msg2"
    
    def test_inject_into_nested_objects(self):
        """Test injection into objects containing nested objects."""
        original = NestedClass()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert isinstance(result, NestedClass)
        # Should inject into nested object
        assert result.simple.name == MALICIOUS_PROMPT
        assert result.simple.value == 123
    
    def test_inject_into_object_without_strings(self):
        """Test injection into object with no string attributes."""
        class NumberOnlyClass:
            def __init__(self):
                self.count = 42
                self.value = 3.14
                self.flag = True
        
        original = NumberOnlyClass()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should add malicious_input attribute
        assert hasattr(result, 'malicious_input')
        assert result.malicious_input == MALICIOUS_PROMPT
        assert result.count == 42


class TestInjectMaliciousPromptEdgeCases:
    """Test inject_malicious_prompt with edge cases and error conditions."""
    
    def test_inject_with_empty_malicious_prompt(self):
        """Test injection with empty malicious prompt."""
        original = "original"
        result = inject_malicious_prompt(original, "")
        assert result == ""
    
    def test_inject_with_none_malicious_prompt(self):
        """Test injection with None malicious prompt."""
        original = "original"
        result = inject_malicious_prompt(original, None)
        assert result is None
    
    def test_inject_into_mock_object(self):
        """Test injection into mock object."""
        original = Mock()
        original.description = "original description"
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Mock objects might not copy properly, so check if injection worked
        # or if function fell back to returning the malicious prompt
        if hasattr(result, 'description') and result.description == MALICIOUS_PROMPT:
            assert result.description == MALICIOUS_PROMPT
        elif result == MALICIOUS_PROMPT:
            assert result == MALICIOUS_PROMPT
        else:
            # Mock object might not be modifiable, which is expected
            assert isinstance(result, Mock)
    
    def test_inject_into_circular_reference(self):
        """Test injection with circular references (should not cause infinite loop)."""
        class CircularClass:
            def __init__(self):
                self.name = "original"
                self.self_ref = self
        
        original = CircularClass()
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        assert result.name == MALICIOUS_PROMPT
    
    def test_inject_with_special_characters(self):
        """Test injection with special characters in malicious prompt."""
        special_prompt = "INJECT<>\"'&\n\t\r"
        original = "original"
        result = inject_malicious_prompt(original, special_prompt)
        assert result == special_prompt
    
    def test_inject_with_unicode_characters(self):
        """Test injection with unicode characters."""
        unicode_prompt = "恶意提示 💀 𝕀𝕟𝕛𝕖𝕔𝕥"
        original = "original"
        result = inject_malicious_prompt(original, unicode_prompt)
        assert result == unicode_prompt
    
    def test_inject_preserve_original_object(self):
        """Test that original object is not modified."""
        original = SimpleClass("original", 100)
        original_name = original.name
        original_value = original.value
        
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        
        # Original should be unchanged
        assert original.name == original_name
        assert original.value == original_value
        # Result should be modified
        assert result.name == MALICIOUS_PROMPT
        assert result.value == 100
    
    def test_inject_into_immutable_like_object(self):
        """Test injection into objects that resist modification."""
        original = ImmutableClass("original", 100)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should return malicious prompt when modification fails
        assert result == MALICIOUS_PROMPT or hasattr(result, 'malicious_input')


class TestInjectMaliciousPromptComplexScenarios:
    """Test inject_malicious_prompt with complex real-world scenarios."""
    
    def test_api_request_like_dict(self):
        """Test injection into API request-like dictionary."""
        original = {
            "method": "POST",
            "url": "https://api.example.com",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "message": "Hello, world!",
                "model": "gpt-3.5-turbo",
                "temperature": 0.7
            }
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into first string field at top level (method)
        assert result["method"] == MALICIOUS_PROMPT
        assert result["url"] == "https://api.example.com"
        assert result["body"]["message"] == "Hello, world!"
    
    def test_function_parameters_dict(self):
        """Test injection into function parameters."""
        original = {
            "args": ["arg1", "arg2"],
            "kwargs": {
                "description": "Process user input",
                "max_length": 100,
                "prompt": "Enter your query:"
            }
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # No string values at top level, should add malicious_input
        assert result["malicious_input"] == MALICIOUS_PROMPT
        assert result["args"] == ["arg1", "arg2"]
        assert result["kwargs"]["description"] == "Process user input"
    
    def test_config_object_injection(self):
        """Test injection into configuration object."""
        @dataclass
        class Config:
            api_key: str
            endpoint: str
            prompt_template: str
            max_tokens: int
        
        original = Config(
            api_key="secret123",
            endpoint="https://api.example.com",
            prompt_template="Answer the question: {question}",
            max_tokens=100
        )
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into prompt_template (priority field)
        assert result.prompt_template == MALICIOUS_PROMPT
        assert result.api_key == "secret123"
    
    def test_nested_structure_injection(self):
        """Test injection into deeply nested structure."""
        original = {
            "user": {
                "profile": {
                    "personal": {
                        "preferences": {
                            "description": "User preferences"
                        }
                    }
                }
            },
            "system": {
                "config": ["setting1", "setting2"]
            }
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # No string values at top level, should add malicious_input
        assert result["malicious_input"] == MALICIOUS_PROMPT
        assert result["system"]["config"] == ["setting1", "setting2"]
        assert result["user"]["profile"]["personal"]["preferences"]["description"] == "User preferences"
    
    def test_machine_learning_data_structure(self):
        """Test injection into ML-like data structure."""
        original = {
            "training_data": [
                {"input": "What is AI?", "output": "AI is..."},
                {"input": "How does ML work?", "output": "ML works by..."}
            ],
            "model_config": {
                "architecture": "transformer",
                "parameters": 175000000000
            }
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # No string values at top level, should add malicious_input
        assert result["malicious_input"] == MALICIOUS_PROMPT
        assert result["training_data"][0]["input"] == "What is AI?"
        assert result["training_data"][1]["input"] == "How does ML work?"


class TestInjectMaliciousPromptRealWorldTypes:
    """Test inject_malicious_prompt with types commonly found in development."""
    
    def test_pydantic_like_model(self):
        """Test injection into Pydantic-like model."""
        class UserModel:
            def __init__(self, name: str, email: str, bio: str):
                self.name = name
                self.email = email  
                self.bio = bio
        
        original = UserModel("John Doe", "john@example.com", "Software developer")
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into name (first string field)
        assert result.name == MALICIOUS_PROMPT
        assert result.email == "john@example.com"
    
    def test_json_like_structure(self):
        """Test injection into JSON-like nested structure."""
        original = {
            "version": "1.0",
            "data": [
                {
                    "id": 1,
                    "content": "Original content",
                    "metadata": {
                        "tags": ["tag1", "tag2"],
                        "description": "Item description"
                    }
                }
            ]
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into first string field at top level (version)
        assert result["version"] == MALICIOUS_PROMPT
        assert result["data"][0]["content"] == "Original content"
    
    def test_exception_like_object(self):
        """Test injection into exception-like object."""
        class CustomError(Exception):
            def __init__(self, message: str, code: int):
                self.message = message
                self.code = code
                super().__init__(message)
        
        original = CustomError("Original error message", 500)
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Check if result is the modified object or fallback to string
        if hasattr(result, 'message'):
            assert result.message == MALICIOUS_PROMPT
            assert result.code == 500
        else:
            # Function might return malicious prompt if copying fails
            assert result == MALICIOUS_PROMPT
    
    def test_database_record_like(self):
        """Test injection into database record-like structure."""
        original = {
            "id": 12345,
            "created_at": "2024-01-01T00:00:00Z",
            "user_input": "Original user input",
            "processed": False,
            "metadata": {
                "source": "web",
                "ip_address": "192.168.1.1"
            }
        }
        result = inject_malicious_prompt(original, MALICIOUS_PROMPT)
        # Should inject into first string field (created_at)
        assert result["created_at"] == MALICIOUS_PROMPT
        assert result["id"] == 12345
        assert result["user_input"] == "Original user input"


if __name__ == "__main__":
    # Allow running tests directly with python test_inject_malicious_prompt.py
    pytest.main([__file__])
