# PowerShell script to run tests for HydroxAI SDK
# Usage: .\run_tests.ps1

Write-Host "Setting up HydroxAI SDK test environment..." -ForegroundColor Green

# Change to the project root directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptPath
Set-Location $projectRoot

Write-Host "Project root: $projectRoot" -ForegroundColor Yellow

# Install the package in development mode with test dependencies
Write-Host "Installing package with test dependencies..." -ForegroundColor Green
pip install -e ".[test]"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install dependencies. Trying alternative method..." -ForegroundColor Yellow
    pip install pytest pytest-cov pytest-mock
    pip install -e .
}

# Run the tests
Write-Host "Running tests..." -ForegroundColor Green
pytest test/ -v

if ($LASTEXITCODE -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed. Check output above." -ForegroundColor Red
}

# Optional: Run with coverage
$runCoverage = Read-Host "Run tests with coverage report? (y/N)"
if ($runCoverage -eq "y" -or $runCoverage -eq "Y") {
    Write-Host "Running tests with coverage..." -ForegroundColor Green
    pytest test/ --cov=hydroxai --cov-report=html --cov-report=term-missing -v
    
    if (Test-Path "htmlcov/index.html") {
        Write-Host "Coverage report generated in htmlcov/index.html" -ForegroundColor Green
        $openReport = Read-Host "Open coverage report in browser? (y/N)"
        if ($openReport -eq "y" -or $openReport -eq "Y") {
            Start-Process "htmlcov/index.html"
        }
    }
}
