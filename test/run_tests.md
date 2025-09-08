# Test Scripts

This directory contains scripts to run tests easily.

## Windows (PowerShell)

```powershell
# Install test dependencies
pip install -e ".[test]"

# Run all tests
pytest

# Run tests with coverage
pytest --cov=hydroxai --cov-report=html --cov-report=term

# Run specific test
pytest test/test_scanner.py::TestScanner::test_scan_chatbot_basic_call
```

## Linux/Mac (Bash)

```bash
# Install test dependencies  
pip install -e ".[test]"

# Run all tests
pytest

# Run tests with coverage
pytest --cov=hydroxai --cov-report=html --cov-report=term

# Run specific test
pytest test/test_scanner.py::TestScanner::test_scan_chatbot_basic_call
```
