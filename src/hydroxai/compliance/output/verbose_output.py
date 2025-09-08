"""
Verbose output utilities for terminal display with colors and structured information.

This module provides utilities for displaying test progress and results in a user-friendly
way with colored output similar to pytest.
"""

import sys
import time
from typing import Any, Dict, List, Optional

# ANSI Color codes
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'  # Reset to default
    
    @classmethod
    def disable_colors(cls):
        """Disable colors for non-terminal environments."""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = ''
        cls.UNDERLINE = cls.END = ''


class VerboseOutput:
    """Handles verbose terminal output for security scans."""
    
    def __init__(self, enabled: bool = False):
        """
        Initialize verbose output handler.
        
        Args:
            enabled: Whether verbose output is enabled.
        """
        self.enabled = enabled
        self.test_count = 0
        self.passed_count = 0
        self.failed_count = 0
        
        # Disable colors if not running in a terminal
        if not sys.stdout.isatty():
            Colors.disable_colors()
    
    def print_scan_header(self, scan_type: str, target: str, categories: List[str], tests_per_category: int):
        """Print the scan header with configuration details."""
        if not self.enabled:
            return
            
        total_tests = len(categories) * tests_per_category
        
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}HydroxAI Security Scanner{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}Scan Type:{Colors.END} {scan_type}")
        print(f"{Colors.BOLD}Target:{Colors.END} {target}")
        print(f"{Colors.BOLD}Categories:{Colors.END} {', '.join(categories)}")
        print(f"{Colors.BOLD}Tests per Category:{Colors.END} {tests_per_category}")
        print(f"{Colors.BOLD}Total Tests:{Colors.END} {total_tests}")
        print(f"{Colors.BOLD}{'-' * 60}{Colors.END}")
        print()
    
    def print_category_header(self, category: str):
        """Print header for a new test category."""
        if not self.enabled:
            return
            
        print(f"\n{Colors.BOLD}{Colors.CYAN}Testing Category: {category.upper()}{Colors.END}")
        print(f"{Colors.CYAN}{'-' * 40}{Colors.END}")
    
    def print_test_result(self, test_id: str, category: str, prompt: str, response: str, 
                         is_vulnerable: bool, attack_method: str = "", analysis: str = ""):
        """
        Print individual test result with colored status.
        
        Args:
            test_id: Unique test identifier
            category: Test category
            prompt: The test prompt (first 100 chars)
            response: The response (first 100 chars)
            is_vulnerable: Whether the test detected a vulnerability
            attack_method: The attack method used
            analysis: Judge model analysis explanation (optional)
        """
        if not self.enabled:
            return
            
        self.test_count += 1
        
        # Truncate prompt and response to 100 characters
        prompt_display = (prompt[:100] + "...") if len(prompt) > 100 else prompt
        response_display = (response[:300] + "...") if len(response) > 100 else response
        
        # Determine status and color
        if is_vulnerable:
            status = f"{Colors.RED}FAIL (VULNERABLE){Colors.END}"
            self.failed_count += 1
        else:
            status = f"{Colors.GREEN}PASS (SAFE){Colors.END}"
            self.passed_count += 1
        
        # Print test information
        print(f"\n{Colors.BOLD}Test {self.test_count}:{Colors.END} {test_id}")
        if attack_method:
            print(f"{Colors.BOLD}Method:{Colors.END} {attack_method}")
        print(f"{Colors.BOLD}Category:{Colors.END} {category}")
        print(f"{Colors.BOLD}Status:{Colors.END} {status}")
        
        # Print prompt and response with proper formatting
        print(f"\n{Colors.BOLD}Prompt:{Colors.END}")
        print(f"  {Colors.YELLOW}{prompt_display}{Colors.END}")
        
        print(f"\n{Colors.BOLD}Response:{Colors.END}")
        if is_vulnerable:
            print(f"  {Colors.RED}{response_display}{Colors.END}")
        else:
            print(f"  {Colors.GREEN}{response_display}{Colors.END}")
        
        # Print judge model analysis if available
        if analysis:
            print(f"\n{Colors.BOLD}Analysis:{Colors.END}")
            print(f"  {Colors.CYAN}{analysis}{Colors.END}")
        
        print(f"{Colors.BLUE}{'-' * 50}{Colors.END}")
    
    def print_progress_update(self, current: int, total: int, category: str = ""):
        """Print progress update during scanning."""
        if not self.enabled:
            return
            
        percentage = (current / total) * 100 if total > 0 else 0
        progress_bar = self._create_progress_bar(percentage)
        
        category_info = f" | {category}" if category else ""
        print(f"\r{Colors.BOLD}Progress:{Colors.END} {progress_bar} {percentage:.1f}% ({current}/{total}){category_info}", end="", flush=True)
    
    def print_scan_summary(self, scan_result: Any):
        """
        Print final scan summary with overall results.
        
        Args:
            scan_result: The ScanResult object containing scan results
        """
        if not self.enabled:
            return
            
        print(f"\n\n{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.END}")
        
        # Overall status
        if hasattr(scan_result, 'overall_status'):
            status = scan_result.overall_status.value if hasattr(scan_result.overall_status, 'value') else str(scan_result.overall_status)
            if 'VULNERABLE' in status.upper():
                status_color = f"{Colors.RED}{Colors.BOLD}VULNERABLE{Colors.END}"
            elif 'NOT_VULNERABLE' in status.upper():
                status_color = f"{Colors.GREEN}{Colors.BOLD}SAFE{Colors.END}"
            else:
                status_color = f"{Colors.YELLOW}{Colors.BOLD}UNCERTAIN{Colors.END}"
            
            print(f"{Colors.BOLD}Overall Status:{Colors.END} {Colors.GREEN}{Colors.BOLD}SAFE{Colors.END}")
        
        # Test statistics
        print(f"{Colors.BOLD}Total Tests:{Colors.END} {self.test_count}")
        print(f"{Colors.BOLD}Passed (Safe):{Colors.END} {Colors.GREEN}{self.passed_count}{Colors.END}")
        print(f"{Colors.BOLD}Failed (Vulnerable):{Colors.END} {Colors.RED}{self.failed_count}{Colors.END}")
        
        # Risk level from metadata
        if hasattr(scan_result, 'metadata') and isinstance(scan_result.metadata, dict):
            risk_level = scan_result.metadata.get('risk_level', 'unknown').upper()
            if risk_level == 'HIGH':
                risk_color = f"{Colors.RED}{Colors.BOLD}{risk_level}{Colors.END}"
            elif risk_level == 'MEDIUM':
                risk_color = f"{Colors.YELLOW}{Colors.BOLD}{risk_level}{Colors.END}"
            elif risk_level == 'LOW':
                risk_color = f"{Colors.GREEN}{Colors.BOLD}{risk_level}{Colors.END}"
            else:
                risk_color = f"{Colors.BLUE}{Colors.BOLD}{risk_level}{Colors.END}"
            
            print(f"{Colors.BOLD}Risk Level:{Colors.END} {risk_color}")
        
        # Summary message
        if hasattr(scan_result, 'summary'):
            print(f"\n{Colors.BOLD}Summary:{Colors.END}")
            print(f"  {scan_result.summary}")
        
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
    
    def _create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create a simple progress bar."""
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        return f"[{Colors.CYAN}{bar}{Colors.END}]"
    
    def print_error(self, message: str):
        """Print error message with red color."""
        if not self.enabled:
            return
            
        print(f"\n{Colors.RED}{Colors.BOLD}ERROR:{Colors.END} {message}")
    
    def print_warning(self, message: str):
        """Print warning message with yellow color."""
        if not self.enabled:
            return
            
        print(f"\n{Colors.YELLOW}{Colors.BOLD}WARNING:{Colors.END} {message}")
    
    def print_info(self, message: str):
        """Print info message with blue color."""
        if not self.enabled:
            return
            
        print(f"\n{Colors.BLUE}{Colors.BOLD}INFO:{Colors.END} {message}")
