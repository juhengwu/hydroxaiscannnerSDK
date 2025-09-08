"""
Unified progress bar utilities for HydroxAI compliance scanning.

This module provides consistent progress bar styling and functionality
across all scanner types (API, Function, Chatbot) following DRY principles.
"""

from typing import Optional, Union
from tqdm import tqdm
from tqdm.asyncio import tqdm as atqdm


class ScanProgressBar:
    """
    Unified progress bar configuration for all HydroxAI scanners.
    
    Provides consistent styling, colors, and behavior across API, Function,
    and Chatbot scanning operations.
    """
    
    GREEN = '\033[32m'  
    RED = '\033[31m'    
    RESET = '\033[0m'   
    
    BAR_FORMAT = "{l_bar}\033[32m{bar:30}\033[0m| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}"
    
    @classmethod
    def create_sync_progress_bar(
        cls,
        total: int,
        desc: str,
        scanner_type: str
    ) -> tqdm:
        """
        Create a synchronous progress bar for API and Function scanners.
        
        Args:
            total: Total number of tests to run
            desc: Base description for the progress bar
            scanner_type: Type of scanner ("API", "Function", "Chatbot")
            
        Returns:
            Configured tqdm progress bar instance
        """
        progress_bar = tqdm(
            total=total,
            desc=f"{cls.GREEN}{desc}{cls.RESET}",
            unit="test",
            bar_format=cls.BAR_FORMAT,
            ncols=120,  # Fixed width to prevent compression
            colour='green'
        )

        progress_bar.set_postfix_str(f"{cls.GREEN}Safe: 0{cls.RESET} {cls.GREEN}Vulnerable: 0{cls.RESET}")
        return progress_bar
    
    @classmethod
    def create_async_progress_bar(
        cls,
        total: int,
        desc: str,
        scanner_type: str
    ) -> atqdm:
        """
        Create an asynchronous progress bar for Chatbot scanner.
        
        Args:
            total: Total number of tests to run
            desc: Base description for the progress bar
            scanner_type: Type of scanner ("API", "Function", "Chatbot")
            
        Returns:
            Configured async tqdm progress bar instance
        """
        progress_bar = atqdm(
            total=total,
            desc=f"{cls.GREEN}{desc}{cls.RESET}",
            unit="test",
            bar_format=cls.BAR_FORMAT,
            ncols=120,  # Fixed width to prevent compression
            colour='green'
        )

        progress_bar.set_postfix_str(f"{cls.GREEN}Safe: 0{cls.RESET} {cls.GREEN}Vulnerable: 0{cls.RESET}")
        return progress_bar
    
    @classmethod
    def format_category_desc(cls, base_desc: str, category: str) -> str:
        """
        Format progress bar description with category information.
        
        Args:
            base_desc: Base description (e.g., "API Security Scan")
            category: Test category (e.g., "hate_speech", "sexual_content")
            
        Returns:
            Formatted description string with colors
        """
        return f"{cls.GREEN}{base_desc} [{category}]{cls.RESET}"
    
    @classmethod
    def format_status_message(cls, message: str, is_safe: bool = True) -> str:
        """
        Format status messages with appropriate colors.
        
        Args:
            message: The message to format
            is_safe: True for safe/successful operations (green), False for vulnerable/failed (red)
            
        Returns:
            Colored message string
        """
        color = cls.GREEN if is_safe else cls.RED
        return f"{color}{message}{cls.RESET}"
    
    @classmethod
    def update_with_status(
        cls, 
        progress_bar: Union[tqdm, atqdm], 
        base_desc: str, 
        category: str,
        current_test: int,
        total_tests: int,
        vulnerable_count: int = 0
    ) -> None:
        """
        Update progress bar with current test status information.
        
        Args:
            progress_bar: The progress bar instance to update
            base_desc: Base description for the scanner
            category: Current test category
            current_test: Current test number
            total_tests: Total number of tests
            vulnerable_count: Number of vulnerable tests found so far
        """
        
        safe_count = current_test - vulnerable_count
        
        safe_text = f"{cls.GREEN}Safe: {safe_count}{cls.RESET}"
        vulnerable_color = cls.RED if vulnerable_count > 0 else cls.GREEN
        vulnerable_text = f"{vulnerable_color}Vulnerable: {vulnerable_count}{cls.RESET}"
        
        desc = f"{cls.GREEN}{base_desc}{cls.RESET} [{category}]"
        progress_bar.set_description(desc)
        
        status_display = f"{safe_text} {vulnerable_text}"
        progress_bar.set_postfix_str(status_display)
        
        progress_bar.update(1)
