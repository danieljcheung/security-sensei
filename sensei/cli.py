"""Command-line interface for Security Sensei."""

import click

from sensei import __version__


@click.group()
@click.version_option(version=__version__, prog_name="Security Sensei")
def cli():
    """Security Sensei - A security scanner for code analysis."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["text", "json", "sarif"]), default="text", help="Output format")
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]), help="Minimum severity to report")
def scan(path, format, severity):
    """Scan a project for security vulnerabilities."""
    click.echo("Not implemented yet")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--accept", "-a", multiple=True, help="Finding IDs to accept as baseline")
@click.option("--clear", is_flag=True, help="Clear the baseline file")
def baseline(path, accept, clear):
    """Manage the security baseline for accepted risks."""
    click.echo("Not implemented yet")


@cli.command()
def version():
    """Show the version of Security Sensei."""
    click.echo(f"Security Sensei v{__version__}")


if __name__ == "__main__":
    cli()
