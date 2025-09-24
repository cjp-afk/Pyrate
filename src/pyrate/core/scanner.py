"""
Core scanner functionality for Pyrate vulnerability scanner.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import Config
from .plugin_manager import PluginManager
from ..models.scan_result import ScanResult, Vulnerability
from ..utils.http_client import HTTPClient

logger = logging.getLogger(__name__)


class Scanner:
    """Main vulnerability scanner class."""
    
    def __init__(self, config: Config):
        """
        Initialize the scanner.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self.plugin_manager = PluginManager(config)
        self.http_client = HTTPClient(config)
        self.console = Console()
        
    async def scan_async(
        self,
        target: str,
        plugins: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Perform asynchronous vulnerability scan.
        
        Args:
            target: Target URL to scan
            plugins: Specific plugins to run (default: all enabled)
            
        Returns:
            ScanResult containing vulnerabilities and metadata
        """
        logger.info(f"Starting scan of target: {target}")
        
        # Validate target URL
        parsed_url = urlparse(target)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid target URL: {target}")
        
        # Initialize scan result
        scan_result = ScanResult(
            target=target,
            timestamp=None,  # Will be set automatically
            vulnerabilities=[],
            scan_info={
                "scanner_version": "0.1.0",
                "target_url": target,
                "plugins_used": plugins or [],
            }
        )
        
        # Get plugins to run
        active_plugins = self.plugin_manager.get_active_plugins(plugins)
        scan_result.scan_info["plugins_used"] = [p.name for p in active_plugins]
        
        if not active_plugins:
            logger.warning("No active plugins found for scan")
            return scan_result
        
        # Run plugins with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            
            # Create tasks for each plugin
            tasks = []
            for plugin in active_plugins:
                task_id = progress.add_task(f"Running {plugin.name}...", total=None)
                task = self._run_plugin_async(plugin, target, progress, task_id)
                tasks.append(task)
            
            # Execute all plugins concurrently
            plugin_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect vulnerabilities from plugin results
            for i, result in enumerate(plugin_results):
                plugin = active_plugins[i]
                if isinstance(result, Exception):
                    logger.error(f"Plugin {plugin.name} failed: {result}")
                    continue
                
                if isinstance(result, list):
                    scan_result.vulnerabilities.extend(result)
                    logger.info(f"Plugin {plugin.name} found {len(result)} vulnerabilities")
        
        logger.info(f"Scan completed. Found {len(scan_result.vulnerabilities)} vulnerabilities")
        return scan_result
    
    def scan(
        self,
        target: str,
        plugins: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Perform synchronous vulnerability scan.
        
        Args:
            target: Target URL to scan
            plugins: Specific plugins to run (default: all enabled)
            
        Returns:
            ScanResult containing vulnerabilities and metadata
        """
        return asyncio.run(self.scan_async(target, plugins))
    
    async def _run_plugin_async(
        self,
        plugin: Any,
        target: str,
        progress: Progress,
        task_id: Any,
    ) -> List[Vulnerability]:
        """
        Run a single plugin asynchronously.
        
        Args:
            plugin: Plugin instance to run
            target: Target URL
            progress: Progress tracker
            task_id: Progress task ID
            
        Returns:
            List of vulnerabilities found by the plugin
        """
        try:
            # Run plugin
            vulnerabilities = await plugin.run_async(target, self.http_client)
            progress.update(task_id, description=f"✓ {plugin.name} completed")
            return vulnerabilities
        except Exception as e:
            progress.update(task_id, description=f"✗ {plugin.name} failed")
            logger.error(f"Plugin {plugin.name} failed: {e}")
            return []
    
    def save_results(
        self,
        results: ScanResult,
        output_path: Path,
        format: str = "json",
    ) -> None:
        """
        Save scan results to file.
        
        Args:
            results: Scan results to save
            output_path: Output file path
            format: Output format (json, html, txt, xml)
        """
        from ..reports.generator import ReportGenerator
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        generator = ReportGenerator(self.config)
        generator.generate_report(results, output_path, format)
        
        logger.info(f"Results saved to {output_path} in {format} format")
    
    def display_results(self, results: ScanResult) -> None:
        """
        Display scan results in the console.
        
        Args:
            results: Scan results to display
        """
        self.console.print(f"\n[bold green]Scan Results for {results.target}[/bold green]")
        self.console.print(f"Scan completed at: {results.timestamp}")
        self.console.print(f"Total vulnerabilities found: {len(results.vulnerabilities)}")
        
        if not results.vulnerabilities:
            self.console.print("[green]No vulnerabilities found![/green]")
            return
        
        # Group vulnerabilities by severity
        severity_groups = {}
        for vuln in results.vulnerabilities:
            severity = vuln.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Display summary table
        table = Table(title="Vulnerability Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Plugin", style="cyan")
        
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severity_order:
            if severity in severity_groups:
                vulns = severity_groups[severity]
                plugins = list(set(v.plugin_name for v in vulns))
                
                color = {
                    "CRITICAL": "red",
                    "HIGH": "orange3",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                    "INFO": "green",
                }.get(severity, "white")
                
                table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    str(len(vulns)),
                    ", ".join(plugins)
                )
        
        self.console.print(table)
        
        # Display detailed vulnerabilities
        for severity in severity_order:
            if severity not in severity_groups:
                continue
                
            vulns = severity_groups[severity]
            color = {
                "CRITICAL": "red",
                "HIGH": "orange3", 
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "green",
            }.get(severity, "white")
            
            self.console.print(f"\n[bold {color}]{severity} Vulnerabilities:[/bold {color}]")
            
            for vuln in vulns:
                self.console.print(f"  • [{color}]{vuln.title}[/{color}]")
                self.console.print(f"    URL: {vuln.url}")
                self.console.print(f"    Plugin: {vuln.plugin_name}")
                if vuln.description:
                    self.console.print(f"    Description: {vuln.description}")
                if vuln.recommendation:
                    self.console.print(f"    Recommendation: {vuln.recommendation}")
                self.console.print()