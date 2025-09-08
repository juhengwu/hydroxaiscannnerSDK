"""
API Security Client for testing LLM API endpoints.

This module provides functionality to test API endpoints for security vulnerabilities
by sending predefined attack prompts and analyzing responses.
"""

import json
import requests
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse


class APISecurityClient:
    """
    Client for performing security scans on LLM API endpoints.
    
    This client sends test prompts to API endpoints and evaluates responses
    for potential security vulnerabilities.
    """
    
    def __init__(self, timeout: float = 30.0):
        """
        Initialize the API security client.
        
        Args:
            timeout: Request timeout in seconds. Defaults to 30.0.
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # Default headers for security testing
        self.default_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'HydroxAI-Security-Scanner/1.0'
        }
    
    def validate_endpoint(self, endpoint: str) -> bool:
        """
        Validate that the endpoint URL is properly formatted.
        
        Args:
            endpoint: The API endpoint URL to validate.
            
        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            parsed = urlparse(endpoint)
            return bool(parsed.netloc) and bool(parsed.scheme) and parsed.scheme in ('http', 'https')
        except Exception:
            return False
    
    def prepare_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Prepare request headers by merging default and custom headers.
        
        Args:
            custom_headers: Optional dictionary of custom headers to include.
            
        Returns:
            Dict[str, str]: Merged headers for the request.
        """
        headers = self.default_headers.copy()
        if custom_headers:
            headers.update(custom_headers)
        return headers
    
    def prepare_request_body(self, body: Optional[Dict[str, Any]], test_prompt: str) -> Dict[str, Any]:
        """
        Prepare the request body with the test prompt.
        
        Args:
            body: Optional base request body structure.
            test_prompt: The security test prompt to inject.
            
        Returns:
            Dict[str, Any]: Request body with test prompt injected.
        """
        if not body:
            # Default OpenAI-style format
            return {
                "messages": [
                    {"role": "user", "content": test_prompt}
                ],
                "max_tokens": 1000,
                "temperature": 0.7
            }
        
        # Copy the body to avoid modifying the original
        request_body = body.copy()
        
        # Handle OpenAI-style messages format
        if 'messages' in request_body and isinstance(request_body['messages'], list):
            # Replace or add user message
            user_message_found = False
            for message in request_body['messages']:
                if isinstance(message, dict) and message.get('role') == 'user':
                    message['content'] = test_prompt
                    user_message_found = True
                    break
            
            if not user_message_found:
                request_body['messages'].append({
                    "role": "user", 
                    "content": test_prompt
                })
        
        # Handle simple prompt format
        elif 'prompt' in request_body:
            request_body['prompt'] = test_prompt
        
        # Handle other common formats
        else:
            for field in ['input', 'query', 'text', 'message']:
                if field in request_body:
                    request_body[field] = test_prompt
                    break
            else:
                # If no known field, add as prompt
                request_body['prompt'] = test_prompt
        
        return request_body
    
    def extract_response_content(self, response_data: Any) -> str:
        """
        Extract text content from API response.
        
        Args:
            response_data: The response data from the API.
            
        Returns:
            str: Extracted text content from the response.
        """
        if isinstance(response_data, str):
            return response_data
        
        if not isinstance(response_data, dict):
            return str(response_data)
        
        # Common response field patterns for different APIs
        extraction_patterns = [
            # OpenAI format
            'choices.0.message.content',
            'choices.0.text',
            # Anthropic format
            'content.0.text',
            'completion',
            # Generic formats
            'response',
            'text',
            'output',
            'result',
            'content',
            'message',
            'data.text',
            'data.response',
            'data.content'
        ]
        
        for pattern in extraction_patterns:
            try:
                content = self._get_nested_value(response_data, pattern)
                if content:
                    return str(content)
            except Exception:
                continue
        
        # If no pattern matches, return the full response as JSON
        return json.dumps(response_data, indent=2)
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract nested value from dictionary using dot notation.
        
        Args:
            data: The dictionary to extract from.
            path: Dot-separated path to the value.
            
        Returns:
            Any: The extracted value or None if not found.
        """
        current = data
        for key in path.split('.'):
            if key.isdigit():
                # Array index
                index = int(key)
                if isinstance(current, list) and index < len(current):
                    current = current[index]
                else:
                    return None
            else:
                # Object key
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
        
        return current
    
    def send_test_request(
        self, 
        endpoint: str, 
        method: str, 
        headers: Dict[str, str], 
        body: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Send a test request to the API endpoint.
        
        Args:
            endpoint: The API endpoint URL.
            method: HTTP method to use.
            headers: Request headers.
            body: Request body.
            
        Returns:
            Tuple[bool, str, Dict[str, Any]]: Success status, response content, and metadata.
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=endpoint,
                headers=headers,
                json=body,
                timeout=self.timeout
            )
            
            # Parse response
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                response_data = response.text
            
            # Extract content
            content = self.extract_response_content(response_data)
            
            # Prepare metadata
            metadata = {
                'status_code': response.status_code,
                'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                'content_length': len(content),
                'response_headers': dict(response.headers)
            }
            
            success = 200 <= response.status_code < 300
            
            return success, content, metadata
            
        except requests.exceptions.Timeout:
            return False, "Request timeout", {'error': 'timeout'}
        except requests.exceptions.ConnectionError:
            return False, "Connection error", {'error': 'connection_error'}
        except Exception as e:
            return False, f"Request failed: {str(e)}", {'error': str(e)}
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
