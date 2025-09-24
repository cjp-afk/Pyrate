"""Command-line interface for Pyrate."""

import click

from . import __version__


@click.group()
@click.version_option(version=__version__)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Pyrate - A web app vulnerability scanner."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command()
@click.argument("url")
@click.option("--output", "-o", type=click.Path(), help="Output file for scan results")
@click.pass_context
def scan(ctx: click.Context, url: str, output: str | None) -> None:
    """Scan a web application for vulnerabilities."""
    verbose = ctx.obj["verbose"]

    if verbose:
        click.echo(f"Starting vulnerability scan of {url}")

    # TODO: Implement actual scanning logic
    click.echo(f"Scanning {url}...")
    click.echo("Scan completed. No vulnerabilities found.")

    if output:
        click.echo(f"Results would be saved to {output}")


@cli.command()
def info() -> None:
    """Show information about Pyrate."""
    click.echo(f"Pyrate v{__version__}")
    click.echo("A web app vulnerability scanner")
    click.echo("https://github.com/cjp-afk/Pyrate")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
