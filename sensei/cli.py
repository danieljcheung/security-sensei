"""Command-line interface for Security Sensei."""

import json
import sys

import click

from sensei import __version__
from sensei.core.scanner import SenseiScanner, ScanResult
from sensei.core.finding import Severity
from sensei.core.baseline import BaselineManager


@click.group()
@click.version_option(version=__version__, prog_name="Security Sensei")
def cli():
    """Security Sensei - A security scanner for code analysis."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)"
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default=None,
    help="Minimum severity to report"
)
@click.option(
    "--category", "-c",
    multiple=True,
    help="Scanner categories to run (e.g., secrets, code). Can be specified multiple times."
)
@click.option(
    "--include-baselined",
    is_flag=True,
    help="Include findings that have been baselined"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show verbose output"
)
@click.option(
    "--include-git-history",
    is_flag=True,
    help="Scan git history for secrets (catches deleted but still exploitable secrets)"
)
def scan(path, output, severity, category, include_baselined, verbose, include_git_history):
    """Scan a project for security vulnerabilities."""
    config = {"verbose": verbose, "include_git_history": include_git_history}

    # Convert severity to uppercase for internal use
    min_severity = severity.upper() if severity else None

    # Convert category tuple to list or None
    categories = list(category) if category else None

    # Run the scan
    scanner = SenseiScanner(path, config)
    result = scanner.scan(
        categories=categories,
        min_severity=min_severity,
        include_baselined=include_baselined,
    )

    # Output results
    if output == "json":
        _output_json(result)
    else:
        _output_text(result, verbose)

    # Exit with appropriate code
    if result.total_findings > 0:
        # Check if any findings are HIGH or CRITICAL
        by_severity = result.findings_by_severity
        if by_severity.get(Severity.CRITICAL, 0) > 0 or by_severity.get(Severity.HIGH, 0) > 0:
            sys.exit(1)
    sys.exit(0)


def _output_json(result: ScanResult) -> None:
    """Output scan results as JSON."""
    click.echo(json.dumps(result.to_dict(), indent=2))


def _output_text(result: ScanResult, verbose: bool = False) -> None:
    """Output scan results as formatted text."""
    click.echo(f"\nSecurity Sensei v{__version__}")
    click.echo(f"Scanning: {result.project_info.get('languages', [])}")

    if verbose:
        click.echo(f"Frameworks: {result.project_info.get('frameworks', [])}")
        click.echo(f"Scanners run: {result.scanners_run}")

    click.echo("")

    # Summary
    by_severity = result.findings_by_severity
    summary_parts = []
    if by_severity.get(Severity.CRITICAL, 0) > 0:
        summary_parts.append(f"{by_severity[Severity.CRITICAL]} critical")
    if by_severity.get(Severity.HIGH, 0) > 0:
        summary_parts.append(f"{by_severity[Severity.HIGH]} high")
    if by_severity.get(Severity.MEDIUM, 0) > 0:
        summary_parts.append(f"{by_severity[Severity.MEDIUM]} medium")
    if by_severity.get(Severity.LOW, 0) > 0:
        summary_parts.append(f"{by_severity[Severity.LOW]} low")
    if by_severity.get(Severity.INFO, 0) > 0:
        summary_parts.append(f"{by_severity[Severity.INFO]} info")

    if result.total_findings == 0:
        click.echo("No security issues found!")
    else:
        click.echo(f"Found {result.total_findings} findings: {', '.join(summary_parts)}")

        # List findings
        click.echo("")
        for finding in result.findings:
            _print_finding(finding, verbose)

    if result.baselined_count > 0:
        click.echo(f"\n({result.baselined_count} baselined findings hidden)")

    click.echo(f"\nScan completed in {result.scan_time:.2f}s")


def _print_finding(finding, verbose: bool = False) -> None:
    """Print a single finding."""
    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "white",
    }
    color = severity_colors.get(finding.severity, "white")

    # Header
    click.echo(click.style(f"[{finding.severity}] ", fg=color, bold=True) + finding.title)

    # Location
    location = f"  {finding.file_path}"
    if finding.line_number:
        location += f":{finding.line_number}"
    click.echo(location)

    # Historical finding info (from git history)
    metadata = finding.metadata or {}
    if metadata.get("historical"):
        commit = metadata.get("commit", "unknown")
        deleted = metadata.get("deleted", False)
        status = "deleted from current files" if deleted else "still present"
        click.echo(click.style(f"  Git: commit {commit} ({status})", fg="magenta"))

    # Code snippet
    if finding.code_snippet and verbose:
        click.echo(f"  Code: {finding.code_snippet[:80]}...")

    # References
    refs = []
    if finding.cwe_id:
        refs.append(finding.cwe_id)
    if finding.owasp_category:
        refs.append(f"OWASP {finding.owasp_category}")
    if refs:
        click.echo(f"  {' | '.join(refs)}")

    click.echo("")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--add", "-a",
    nargs=2,
    multiple=True,
    metavar="ID REASON",
    help="Add a finding to the baseline with a reason"
)
@click.option(
    "--remove", "-r",
    multiple=True,
    metavar="ID",
    help="Remove a finding from the baseline"
)
@click.option(
    "--list", "-l", "list_all",
    is_flag=True,
    help="List all baselined findings"
)
@click.option(
    "--clear",
    is_flag=True,
    help="Clear all baselined findings"
)
def baseline(path, add, remove, list_all, clear):
    """Manage the security baseline for accepted risks."""
    manager = BaselineManager(path)

    if clear:
        manager.clear()
        click.echo("Baseline cleared.")
        return

    if add:
        for finding_id, reason in add:
            manager.add(finding_id, reason)
            click.echo(f"Added {finding_id} to baseline: {reason}")

    if remove:
        for finding_id in remove:
            if manager.remove(finding_id):
                click.echo(f"Removed {finding_id} from baseline")
            else:
                click.echo(f"Finding {finding_id} was not in baseline")

    if list_all or (not add and not remove and not clear):
        entries = manager.list_all()
        if not entries:
            click.echo("No baselined findings.")
        else:
            click.echo(f"Baselined findings ({len(entries)}):\n")
            for entry in entries:
                click.echo(f"  {entry['finding_id']}")
                click.echo(f"    Reason: {entry['reason']}")
                if entry.get('added_at'):
                    click.echo(f"    Added: {entry['added_at']}")
                click.echo("")


@cli.command()
def version():
    """Show the version of Security Sensei."""
    click.echo(f"Security Sensei v{__version__}")


if __name__ == "__main__":
    cli()
