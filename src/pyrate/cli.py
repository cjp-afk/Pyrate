"""
Command Line Interface for Pyrate vulnerability scanner.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from pyrate import __version__
from pyrate.core.config import Config
from pyrate.core.scanner import Scanner
from pyrate.utils.logging import setup_logging

console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (can be used multiple times)",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress output except errors",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config: Optional[Path] = None,
    verbose: int = 0,
    quiet: bool = False,
) -> None:
    """Pyrate - Web Application Vulnerability Scanner."""
    ctx.ensure_object(dict)
    
    # Setup logging
    log_level = "ERROR" if quiet else "INFO"
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"
    
    setup_logging(log_level)
    
    # Load configuration
    try:
        ctx.obj["config"] = Config.load(config)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("target", required=True)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for results",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "html", "txt", "xml"]),
    default="json",
    help="Output format",
)
@click.option(
    "--plugins",
    "-p",
    multiple=True,
    help="Specific plugins to run (default: all)",
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    output: Optional[Path] = None,
    format: str = "json",
    plugins: tuple[str, ...] = (),
) -> None:
    """Scan a target for vulnerabilities."""
    config = ctx.obj["config"]
    
    console.print(f"[green]Starting scan of target: {target}[/green]")
    
    try:
        scanner = Scanner(config)
        results = scanner.scan(target, plugins=list(plugins) if plugins else None)
        
        if output:
            scanner.save_results(results, output, format)
            console.print(f"[green]Results saved to: {output}[/green]")
        else:
            scanner.display_results(results)
            
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def plugins(ctx: click.Context) -> None:
    """List available plugins."""
    from pyrate.core.plugin_manager import PluginManager
    
    config = ctx.obj["config"]
    plugin_manager = PluginManager(config)
    available_plugins = plugin_manager.list_plugins()
    
    table = Table(title="Available Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="magenta")
    table.add_column("Category", style="green")
    table.add_column("Risk Level", style="yellow")
    
    for plugin in available_plugins:
        table.add_row(
            plugin.name,
            plugin.description,
            plugin.category,
            plugin.risk_level,
        )
    
    console.print(table)


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default="pyrate-config.yaml",
    help="Output configuration file path",
)
def init_config(output: Path) -> None:
    """Generate a sample configuration file."""
    try:
        Config.create_sample(output)
        console.print(f"[green]Sample configuration created: {output}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to create configuration: {e}[/red]")
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()