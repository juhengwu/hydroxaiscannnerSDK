# HydroxAI SDK Testing Documentation

## Overview

This document provides comprehensive information about the testing framework for the HydroxAI SDK, including test coverage, execution instructions, and testing best practices.

## Test Structure

The test suite is organized into the following modules:

### Core Test Files

- **`test_basic.py`** - Basic import and initialization tests
- **`test_scanner.py`** - Core scanner functionality tests
- **`test_inject_malicious_prompt.py`** - Comprehensive injection function tests
- **`test_api_comprehensive.py`** - API scanning and testing functionality
- **`test_function_comprehensive.py`** - Function scanning and analysis tests
- **`test_integration.py`** - End-to-end integration tests
- **`test_performance.py`** - Performance and benchmark tests

### Support Files

- **`conftest.py`** - Pytest configuration and shared fixtures
- **`requirements-test.txt`** - Testing dependencies
- **`README.md`** - This documentation file

## Test Categories

### 1. Unit Tests
Tests individual functions and methods in isolation.

**Coverage includes:**
- `inject_malicious_prompt` function with all data types
- Basic scanner operations
- Type handling and validation
- Error conditions and edge cases

### 2. Integration Tests
Tests interaction between components and end-to-end workflows.

**Coverage includes:**
- Complete scanning workflows (chatbot, API, function)
- Injection followed by scanning
- Multi-component interactions
- Real-world scenario simulations

### 3. API Tests
Tests API-related functionality with various request formats.

**Coverage includes:**
- Different HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Various header configurations
- Different body types (JSON, form data, raw strings)
- Malicious payload handling
- OpenAI, Anthropic, and custom API formats

### 4. Function Tests
Tests function scanning and analysis capabilities.

**Coverage includes:**
- Simple and complex function structures
- Security vulnerability detection
- Code analysis for dangerous patterns
- Parameter injection scenarios
- Real-world function examples

### 5. Performance Tests
Tests performance characteristics and scalability.

**Coverage includes:**
- Injection performance with different data types
- Concurrent operation handling
- Memory usage patterns
- Large dataset processing
- Scalability limits

## Inject Malicious Prompt Testing

The `inject_malicious_prompt` function is extensively tested across multiple scenarios:

### Data Type Coverage

1. **Basic Types**
   - Strings (empty, normal, unicode, special characters)
   - Lists (empty, string lists, mixed types, nested)
   - Dictionaries (empty, string values, priority fields, nested)
   - Sets (empty, string sets, mixed types)
   - Tuples (regular, empty, NamedTuple)

2. **Custom Objects**
   - Simple classes
   - Dataclasses
   - Complex objects with nested structures
   - Objects with priority fields
   - Immutable objects

3. **Real-World Scenarios**
   - API request structures (OpenAI, Anthropic, custom)
   - Configuration objects
   - ML data structures
   - Database records
   - Exception objects

4. **Edge Cases**
   - None values
   - Empty structures
   - Circular references
   - Objects without string attributes
   - Non-serializable objects

### Priority Field Testing

The function prioritizes certain field names for injection:
- `description`, `content`, `message`, `text`
- `query`, `prompt`, `comment`, `note`
- `info`, `details`, `summary`, `news`
- `title`, `name`, `input`, `request`

## Running Tests

### Prerequisites

1. Install testing dependencies:
```bash
pip install -r test/requirements-test.txt
```

2. Ensure the main package is installed:
```bash
pip install -e .
```

### Basic Test Execution

Run all tests:
```bash
pytest
```

Run with verbose output:
```bash
pytest -v
```

Run specific test file:
```bash
pytest test/test_inject_malicious_prompt.py
```

Run specific test class:
```bash
pytest test/test_inject_malicious_prompt.py::TestInjectMaliciousPromptBasicTypes
```

Run specific test method:
```bash
pytest test/test_inject_malicious_prompt.py::TestInjectMaliciousPromptBasicTypes::test_inject_into_string
```

### Coverage Testing

Run tests with coverage report:
```bash
pytest --cov=hydroxai --cov-report=html --cov-report=term
```

Generate coverage report in HTML format:
```bash
pytest --cov=hydroxai --cov-report=html
open htmlcov/index.html
```

### Performance Testing

Run only performance tests:
```bash
pytest -m performance
```

Run performance tests with benchmarking:
```bash
pytest test/test_performance.py -v
```

### Parallel Testing

Run tests in parallel (faster execution):
```bash
pytest -n auto
```

Run with specific number of workers:
```bash
pytest -n 4
```

### Integration Testing

Run only integration tests:
```bash
pytest test/test_integration.py -v
```

Run integration tests with specific markers:
```bash
pytest -m "not slow"  # Skip slow tests
pytest -m "slow"      # Run only slow tests
```

### Test Filtering

Run tests matching pattern:
```bash
pytest -k "inject"  # Run tests with 'inject' in name
pytest -k "not performance"  # Skip performance tests
```

Run tests by markers:
```bash
pytest -m "not slow"
pytest -m "performance"
```

## Test Configuration

### Pytest Markers

The following markers are used to categorize tests:

- `@pytest.mark.slow` - Tests that take longer to execute
- `@pytest.mark.performance` - Performance benchmark tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.unit` - Unit tests

### Fixtures

Common fixtures available across all tests:

- `sample_url` - Standard test URL
- `sample_headers` - HTTP headers for API tests
- `sample_api_body` - API request body
- `malicious_prompt` - Standard malicious prompt for injection
- `openai_api_request` - OpenAI-format API request
- `anthropic_api_request` - Anthropic-format API request
- `complex_nested_data` - Complex nested data structure
- `vulnerable_function_codes` - Functions with security issues
- `safe_function_codes` - Safe function examples

## Test Coverage Goals

### Current Coverage Areas

1. **Injection Function Coverage**: 95%+
   - All supported data types
   - Priority field selection
   - Edge cases and error conditions
   - Type preservation
   - Performance characteristics

2. **API Testing Coverage**: 85%+
   - HTTP method variations
   - Header configurations
   - Body type handling
   - Error conditions
   - Security scenarios

3. **Scanner Coverage**: 80%+
   - Basic scanning operations
   - Result structure validation
   - Error handling
   - Integration scenarios

4. **Integration Coverage**: 75%+
   - End-to-end workflows
   - Component interactions
   - Real-world scenarios
   - Error propagation

### Target Areas for Expansion

1. More chatbot interface testing
2. Advanced security vulnerability detection
3. Compliance framework integration
4. Custom model support
5. Advanced error recovery scenarios

## Best Practices

### Writing New Tests

1. **Follow naming conventions**:
   - Test files: `test_*.py`
   - Test classes: `Test*`
   - Test methods: `test_*`

2. **Use descriptive names**:
   ```python
   def test_inject_into_nested_dict_with_priority_fields(self):
   ```

3. **Include docstrings**:
   ```python
   def test_complex_scenario(self):
       """Test complex scenario with multiple components."""
   ```

4. **Use appropriate fixtures**:
   ```python
   def test_api_request(self, openai_api_request, malicious_prompt):
   ```

5. **Test edge cases**:
   ```python
   # Test empty inputs
   # Test None values
   # Test very large inputs
   # Test malformed inputs
   ```

### Test Organization

1. Group related tests in classes
2. Use setup/teardown methods appropriately
3. Keep tests independent and isolated
4. Use parametrized tests for multiple inputs
5. Mark slow tests appropriately

### Performance Testing

1. Use `@pytest.mark.performance` for benchmark tests
2. Include timing assertions where appropriate
3. Test with realistic data sizes
4. Monitor memory usage in long-running tests
5. Use concurrent testing for scalability validation

## Continuous Integration

### GitHub Actions Integration

The test suite is designed to work with CI/CD pipelines:

```yaml
# Example GitHub Actions configuration
- name: Run tests
  run: |
    pytest --cov=hydroxai --cov-report=xml
    
- name: Upload coverage
  uses: codecov/codecov-action@v1
```

### Test Reports

Generate comprehensive test reports:
```bash
pytest --html=report.html --self-contained-html
```

## Troubleshooting

### Common Issues

1. **Import Errors**:
   - Ensure package is installed: `pip install -e .`
   - Check Python path configuration

2. **Fixture Not Found**:
   - Verify fixture is defined in `conftest.py`
   - Check fixture scope and availability

3. **Performance Test Failures**:
   - Adjust timing thresholds for slower systems
   - Use `@pytest.mark.slow` for longer tests

4. **Mock/Patch Issues**:
   - Ensure correct import paths
   - Verify mock setup and teardown

### Debugging Tests

Run tests with debugging:
```bash
pytest --pdb  # Drop into debugger on failure
pytest --lf   # Run only last failed tests
pytest --tb=long  # Full traceback output
```

## Contributing

When adding new tests:

1. Follow the existing structure and conventions
2. Add appropriate documentation
3. Include both positive and negative test cases
4. Update this documentation if adding new test categories
5. Ensure tests pass in isolation and in full suite

## Reporting Issues

When reporting test-related issues:

1. Include full error output
2. Specify Python version and OS
3. Include test command used
4. Provide minimal reproduction steps
5. Include relevant test file names and line numbers

---

This testing framework ensures comprehensive coverage of the HydroxAI SDK functionality, with particular emphasis on the critical `inject_malicious_prompt` function and API security testing capabilities.
