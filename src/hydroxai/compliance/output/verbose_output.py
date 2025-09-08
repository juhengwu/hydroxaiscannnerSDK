"""
Verbose output utilities for terminal display with rich formatting and colors.

This module provides utilities for displaying test progress and results in a user-friendly
way with beautiful rich formatting and colors.
"""

import sys
import time
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.text import Text
from rich.rule import Rule
from rich.syntax import Syntax
from rich.tree import Tree
from rich.align import Align
from rich.columns import Columns
from rich import box
from rich.status import Status


class VerboseOutput:
    """Handles verbose terminal output for security scans using rich formatting."""
    
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
        self.test_details = []  # Store test details for summary
        
        # Initialize rich console
        self.console = Console(force_terminal=True if enabled else None)
        self.progress = None
        
    def print_scan_header(self, scan_type: str, target: str, categories: List[str], tests_per_category: int):
        """Print the scan header with configuration details using rich formatting."""
        if not self.enabled:
            return
            
        total_tests = len(categories) * tests_per_category
        
        # Create header panel with unified color scheme
        header_content = f"""
Scan Type: {scan_type}
Target: {target}
Categories: {', '.join(categories)}
Tests per Category: {tests_per_category}
Total Tests: {total_tests}
        """.strip()
        
        header_panel = Panel(
            header_content,
            title="HydroxAI Security Scanner",
            border_style="white",
            padding=(1, 2)
        )
        
        self.console.print()
        self.console.print(header_panel)
        self.console.print()
    
    def print_category_header(self, category: str):
        """Print header for a new test category using rich formatting."""
        if not self.enabled:
            return
            
        self.console.print("\n\n")  # More space from previous content
        self.console.print(Rule(f"Testing Category: {category.upper()}", style="white"))
        self.console.print()  # Less space to following content
    
    def print_test_result(self, test_id: str, category: str, prompt: str, response: str, 
                         is_vulnerable: bool, attack_method: str = "", analysis: str = ""):
        """
        Print individual test result with rich formatting.
        
        Args:
            test_id: Unique test identifier
            category: Test category
            prompt: The test prompt
            response: The response
            is_vulnerable: Whether the test detected a vulnerability
            attack_method: The attack method used
            analysis: Judge model analysis explanation
        """
        if not self.enabled:
            return
            
        self.test_count += 1
        
        # Store test details for summary
        self.test_details.append({
            'category': category,
            'test_number': self.test_count,
            'is_vulnerable': is_vulnerable,
            'attack_method': attack_method
        })
        
        # Determine status and styling
        if is_vulnerable:
            status = "[bold red]FAIL (VULNERABLE)[/bold red]"
            self.failed_count += 1
            border_style = "red"
        else:
            status = "[bold green]PASS (SAFE)[/bold green]"
            self.passed_count += 1
            border_style = "green"
        
        # Create simplified metadata table (no test ID redundancy)
        metadata_table = Table(show_header=False, box=None, padding=(0, 1))
        metadata_table.add_column("Field", style="white", width=15)
        metadata_table.add_column("Value", style="white")
        
        metadata_table.add_row("Category", f"{category}")
        if attack_method:
            metadata_table.add_row("Method", f"{attack_method}")
        metadata_table.add_row("Result", status)
        
        # Create compact test info panel with better hierarchy
        test_panel = Panel(
            metadata_table,
            title=f"Test {self.test_count}",
            border_style=border_style,
            padding=(0, 1)
        )
        
        # Create prompt section
        prompt_display = prompt if len(prompt) <= 500 else prompt[:500] + "..."
        prompt_panel = Panel(
            f"{prompt_display}",
            title="Prompt",
            border_style="white",
            padding=(0, 1)
        )
        
        # Create response section
        response_display = response if len(response) <= 800 else response[:800] + "..."
        response_color = "red" if is_vulnerable else "green"
        response_panel = Panel(
            f"[{response_color}]{response_display}[/{response_color}]",
            title="Response",
            border_style=response_color,
            padding=(0, 1)
        )
        
        # Print with improved spacing and hierarchy
        self.console.print()
        self.console.print(test_panel)
        self.console.print(prompt_panel)
        self.console.print(response_panel)
        
        # Print analysis if available
        if analysis:
            analysis_panel = Panel(
                f"{analysis}",
                title="Analysis",
                border_style="white",
                padding=(0, 1)
            )
            self.console.print(analysis_panel)
        
        # Subtle separator
        self.console.print(Rule(style="dim"))
    
    def print_progress_update(self, current: int, total: int, category: str = ""):
        """Print progress update during scanning using rich progress bar."""
        if not self.enabled:
            return
            
        # Initialize progress bar if not exists
        if self.progress is None:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=self.console,
                transient=True
            )
            self.progress.start()
            self.task_id = self.progress.add_task("Scanning...", total=total)
        
        # Update progress
        category_info = f" | {category}" if category else ""
        self.progress.update(self.task_id, completed=current, description=f"[cyan]Scanning{category_info}[/cyan]")
        
        # Stop progress when completed
        if current >= total:
            self.progress.stop()
            self.progress = None
    
    def print_scan_summary(self, scan_result: Any):
        """
        Print final scan summary with rich formatting.
        
        Args:
            scan_result: The ScanResult object containing scan results
        """
        if not self.enabled:
            return
            
        # Create overall summary table
        summary_table = Table(box=box.ROUNDED)
        summary_table.add_column("Metric", style="white", width=25)
        summary_table.add_column("Value", style="white", justify="left")
        
        # Overall status
        if hasattr(scan_result, 'overall_status'):
            status = scan_result.overall_status.value if hasattr(scan_result.overall_status, 'value') else str(scan_result.overall_status)
            if 'VULNERABLE' in status.upper():
                status_display = "[bold red]VULNERABLE[/bold red]"
            elif 'NOT_VULNERABLE' in status.upper():
                status_display = "[bold green]SAFE[/bold green]"
            else:
                status_display = "[yellow]UNCERTAIN[/yellow]"
        else:
            # Determine status based on test results
            if self.failed_count > 0:
                status_display = "[bold red]VULNERABLE[/bold red]"
            else:
                status_display = "[bold green]SAFE[/bold green]"
        
        summary_table.add_row("Overall Status", status_display)
        summary_table.add_row("", "")  # Separator
        summary_table.add_row("Total Tests", f"{self.test_count}")
        summary_table.add_row("Passed (Safe)", f"[green]{self.passed_count}[/green]")
        summary_table.add_row("Failed (Vulnerable)", f"[red]{self.failed_count}[/red]")
        
        # Calculate success rate
        success_rate = (self.passed_count / self.test_count * 100) if self.test_count > 0 else 0
        success_color = "green" if success_rate >= 90 else "yellow" if success_rate >= 70 else "red"
        summary_table.add_row("Success Rate", f"[{success_color}]{success_rate:.1f}%[/{success_color}]")
        
        # Risk level from metadata
        if hasattr(scan_result, 'metadata') and isinstance(scan_result.metadata, dict):
            risk_level = scan_result.metadata.get('risk_level', 'unknown').upper()
            risk_colors = {
                'HIGH': 'red',
                'MEDIUM': 'yellow', 
                'LOW': 'green',
                'UNKNOWN': 'white'
            }
            risk_color = risk_colors.get(risk_level, 'white')
            summary_table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]")
        
        # Create test details table
        if self.test_details:
            details_table = Table(box=box.SIMPLE)
            details_table.add_column("Test", style="white", width=30)
            details_table.add_column("Status", justify="center", width=15)
            
            for detail in self.test_details:
                test_name = f"{detail['category'].lower()} test{detail['test_number']}"
                if detail['is_vulnerable']:
                    status_text = "[red]FAIL[/red]"
                else:
                    status_text = "[green]PASS[/green]"
                
                details_table.add_row(test_name, status_text)
        
        # Print summary
        self.console.print()
        
        # Create main summary panel
        summary_panel = Panel(
            summary_table,
            title="Scan Results",
            border_style="white",
            padding=(1, 2)
        )
        self.console.print(summary_panel)
        
        # Print test details if available
        if self.test_details:
            details_panel = Panel(
                details_table,
                title="Test Details",
                border_style="white",
                padding=(1, 2)
            )
            self.console.print(details_panel)
        
        # Print summary text if available
        if hasattr(scan_result, 'summary') and scan_result.summary:
            summary_text_panel = Panel(
                f"{scan_result.summary}",
                title="Analysis",
                border_style="white",
                padding=(1, 2)
            )
            self.console.print(summary_text_panel)
        
        self.console.print()
    
    def print_error(self, message: str):
        """Print error message with rich formatting."""
        if not self.enabled:
            return
            
        error_panel = Panel(
            f"[bold red]{message}[/bold red]",
            title="ERROR",
            border_style="red",
            padding=(0, 1)
        )
        self.console.print()
        self.console.print(error_panel)
    
    def print_warning(self, message: str):
        """Print warning message with rich formatting."""
        if not self.enabled:
            return
            
        warning_panel = Panel(
            f"[bold yellow]{message}[/bold yellow]",
            title="WARNING",
            border_style="yellow",
            padding=(0, 1)
        )
        self.console.print()
        self.console.print(warning_panel)
    
    def print_info(self, message: str):
        """Print info message with rich formatting."""
        if not self.enabled:
            return
            
        info_panel = Panel(
            f"{message}",
            title="INFO",
            border_style="white",
            padding=(0, 1)
        )
        self.console.print()
        self.console.print(info_panel)
    
    def print_status(self, message: str, spinner: str = "dots"):
        """Print a status message with spinner."""
        if not self.enabled:
            return
            
        with Status(f"[cyan]{message}[/cyan]", spinner=spinner, console=self.console):
            time.sleep(0.1)  # Brief pause to show the spinner
    
    def create_test_tree(self, categories: List[str], tests_per_category: int) -> Tree:
        """Create a tree view of test structure."""
        tree = Tree("[bold cyan]Test Structure[/bold cyan]")
        
        for category in categories:
            category_branch = tree.add(f"[cyan]{category}[/cyan]")
            for i in range(tests_per_category):
                category_branch.add(f"Test {i+1}")
        
        return tree
    
    def print_test_structure(self, categories: List[str], tests_per_category: int):
        """Print the test structure as a tree."""
        if not self.enabled:
            return
            
        tree = self.create_test_tree(categories, tests_per_category)
        self.console.print()
        self.console.print(tree)
        self.console.print()
