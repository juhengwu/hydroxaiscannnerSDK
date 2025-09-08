#!/usr/bin/env python3
"""
Comprehensive test runner for HydroxAI SDK.

This script provides convenient commands for running different types of tests
and generating reports.
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description=""):
    """Run a shell command and handle errors."""
    if description:
        print(f"\n{'='*60}")
        print(f"Running: {description}")
        print(f"Command: {command}")
        print('='*60)
    
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, 
                              capture_output=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False


def install_dependencies():
    """Install test dependencies."""
    print("Installing test dependencies...")
    return run_command("pip install -r test/requirements-test.txt", 
                      "Installing test dependencies")


def run_basic_tests():
    """Run basic test suite."""
    command = "pytest test/test_basic.py test/test_scanner.py -v"
    return run_command(command, "Running basic tests")


def run_injection_tests():
    """Run comprehensive injection tests."""
    command = "pytest test/test_inject_malicious_prompt.py -v"
    return run_command(command, "Running injection tests")


def run_api_tests():
    """Run API tests."""
    command = "pytest test/test_api_comprehensive.py -v"
    return run_command(command, "Running API tests")


def run_function_tests():
    """Run function tests."""
    command = "pytest test/test_function_comprehensive.py -v"
    return run_command(command, "Running function tests")


def run_integration_tests():
    """Run integration tests."""
    command = "pytest test/test_integration.py -v"
    return run_command(command, "Running integration tests")


def run_performance_tests():
    """Run performance tests."""
    command = "pytest test/test_performance.py -v -m performance"
    return run_command(command, "Running performance tests")


def run_all_tests():
    """Run all tests."""
    command = "pytest test/ -v"
    return run_command(command, "Running all tests")


def run_coverage_tests():
    """Run tests with coverage reporting."""
    commands = [
        "pytest --cov=hydroxai --cov-report=html --cov-report=term test/",
        "echo 'Coverage report generated in htmlcov/index.html'"
    ]
    
    success = True
    for cmd in commands:
        if not run_command(cmd, "Generating coverage report"):
            success = False
    return success


def run_parallel_tests():
    """Run tests in parallel."""
    command = "pytest test/ -v -n auto"
    return run_command(command, "Running tests in parallel")


def run_quick_tests():
    """Run quick tests (excluding slow ones)."""
    command = "pytest test/ -v -m 'not slow and not performance'"
    return run_command(command, "Running quick tests")


def run_slow_tests():
    """Run only slow tests."""
    command = "pytest test/ -v -m 'slow or performance'"
    return run_command(command, "Running slow tests")


def generate_html_report():
    """Generate HTML test report."""
    command = "pytest test/ --html=test_report.html --self-contained-html"
    return run_command(command, "Generating HTML test report")


def run_specific_test(test_pattern):
    """Run tests matching a specific pattern."""
    command = f"pytest test/ -v -k '{test_pattern}'"
    return run_command(command, f"Running tests matching: {test_pattern}")


def lint_tests():
    """Run linting on test files."""
    commands = [
        "flake8 test/ --max-line-length=100",
        "pylint test/ --disable=missing-docstring"
    ]
    
    success = True
    for cmd in commands:
        try:
            run_command(cmd, "Linting test files")
        except:
            print(f"Linting tool not available: {cmd}")
    return success


def clean_test_artifacts():
    """Clean test artifacts and cache files."""
    artifacts = [
        "htmlcov/",
        ".coverage", 
        "test_report.html",
        ".pytest_cache/",
        "__pycache__/",
        "test/__pycache__/",
    ]
    
    for artifact in artifacts:
        if os.path.exists(artifact):
            if os.path.isdir(artifact):
                run_command(f"rm -rf {artifact}", f"Removing {artifact}")
            else:
                run_command(f"rm {artifact}", f"Removing {artifact}")


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="HydroxAI SDK Test Runner")
    parser.add_argument("command", nargs="?", default="all",
                       help="Test command to run")
    parser.add_argument("--pattern", "-k", help="Test pattern to match")
    parser.add_argument("--install-deps", action="store_true",
                       help="Install test dependencies")
    parser.add_argument("--clean", action="store_true",
                       help="Clean test artifacts")
    
    args = parser.parse_args()
    
    # Change to project root directory
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    if args.clean:
        clean_test_artifacts()
        return
    
    if args.install_deps:
        if not install_dependencies():
            sys.exit(1)
    
    # Command mapping
    commands = {
        "basic": run_basic_tests,
        "injection": run_injection_tests,
        "api": run_api_tests,
        "function": run_function_tests,
        "integration": run_integration_tests,
        "performance": run_performance_tests,
        "all": run_all_tests,
        "coverage": run_coverage_tests,
        "parallel": run_parallel_tests,
        "quick": run_quick_tests,
        "slow": run_slow_tests,
        "html": generate_html_report,
        "lint": lint_tests,
    }
    
    if args.pattern:
        success = run_specific_test(args.pattern)
    elif args.command in commands:
        success = commands[args.command]()
    else:
        print(f"Unknown command: {args.command}")
        print(f"Available commands: {', '.join(commands.keys())}")
        sys.exit(1)
    
    if not success:
        sys.exit(1)
    
    print("\n" + "="*60)
    print("Test execution completed successfully!")
    print("="*60)


if __name__ == "__main__":
    main()
