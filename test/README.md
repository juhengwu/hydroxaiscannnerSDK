# Test Configuration

This directory contains the test suite for the HydroxAI SDK.

## Test Structure

- `test_scanner.py` - Unit tests for the Scanner class
- `conftest.py` - Pytest configuration and fixtures
- `__init__.py` - Makes this directory a Python package

## Running Tests

To run all tests:
```bash
pytest
```

To run with coverage:
```bash
pytest --cov=hydroxai
```

To run specific test:
```bash
pytest test_scanner.py::test_scan_chatbot
```

## Test Categories

- **Unit Tests**: Test individual methods and functions
- **Integration Tests**: Test component interactions (future)
- **End-to-End Tests**: Test complete workflows (future)

## Note

Current tests focus on basic functionality validation - ensuring methods can be called without errors. Real URL/API testing will be added in future iterations.
