"""
Basic import and functionality tests.

This module tests that the core modules can be imported and basic functionality works.
"""


def test_import_scanner():
    """Test that Scanner can be imported successfully."""
    try:
        from hydroxai.compliance.scanner import Scanner
        assert Scanner is not None
    except ImportError as e:
        raise AssertionError(f"Failed to import Scanner: {e}")


def test_import_types():
    """Test that types can be imported successfully."""
    try:
        from hydroxai.compliance.types import ScanResult, VulnerabilityStatus
        assert ScanResult is not None
        assert VulnerabilityStatus is not None
    except ImportError as e:
        raise AssertionError(f"Failed to import types: {e}")


def test_vulnerability_status_enum():
    """Test VulnerabilityStatus enum values."""
    from hydroxai.compliance.types import VulnerabilityStatus
    
    # Test enum values exist
    assert VulnerabilityStatus.VULNERABLE
    assert VulnerabilityStatus.NOT_VULNERABLE  
    assert VulnerabilityStatus.UNCERTAIN
    
    # Test enum values are correct
    assert VulnerabilityStatus.VULNERABLE.value == "vulnerable"
    assert VulnerabilityStatus.NOT_VULNERABLE.value == "not_vulnerable"
    assert VulnerabilityStatus.UNCERTAIN.value == "uncertain"


def test_basic_scanner_instantiation():
    """Test Scanner can be instantiated."""
    from hydroxai.compliance.scanner import Scanner
    
    scanner = Scanner()
    assert scanner is not None
    assert hasattr(scanner, 'timeout')
    assert scanner.timeout == 60.0  # default value


if __name__ == "__main__":
    # Simple test runner if pytest is not available
    print("Running basic import tests...")
    
    try:
        test_import_scanner()
        print("✓ Scanner import test passed")
    except Exception as e:
        print(f"✗ Scanner import test failed: {e}")
    
    try:
        test_import_types()
        print("✓ Types import test passed")
    except Exception as e:
        print(f"✗ Types import test failed: {e}")
        
    try:
        test_vulnerability_status_enum()
        print("✓ VulnerabilityStatus enum test passed")
    except Exception as e:
        print(f"✗ VulnerabilityStatus enum test failed: {e}")
        
    try:
        test_basic_scanner_instantiation()
        print("✓ Scanner instantiation test passed")
    except Exception as e:
        print(f"✗ Scanner instantiation test failed: {e}")
    
    print("Basic tests completed.")
