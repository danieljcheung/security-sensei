"""Command-line interface for Security Sensei."""

import json
import sys

import click

from sensei import __version__
from sensei.core.scanner import SenseiScanner, ScanResult
from sensei.core.finding import Finding, Severity
from sensei.core.baseline import BaselineManager
from sensei.fixes import AutoFixer, ProposedFix, AppliedFix


# Color scheme for severity levels
SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "cyan",
    Severity.LOW: "white",
    Severity.INFO: "bright_black",
}

SEVERITY_BOLD = {
    Severity.CRITICAL: True,
    Severity.HIGH: True,
    Severity.MEDIUM: False,
    Severity.LOW: False,
    Severity.INFO: False,
}


@click.group()
@click.version_option(version=__version__, prog_name="Security Sensei")
def cli():
    """Security Sensei - A security scanner for code analysis."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json", "markdown"]),
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
@click.option(
    "--fix",
    is_flag=True,
    help="Apply safe, reversible auto-fixes for detected issues"
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what fixes would be applied without making changes (use with --fix)"
)
def scan(path, output, severity, category, include_baselined, verbose, include_git_history, fix, dry_run):
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

    # Handle auto-fix if requested
    applied_fixes = []
    proposed_fixes = []
    if fix or dry_run:
        auto_fixer = AutoFixer(path)
        proposed_fixes = auto_fixer.analyze(result.findings)

        if proposed_fixes:
            if dry_run:
                # Just show what would be done
                _output_proposed_fixes(proposed_fixes)
            else:
                # Apply the fixes
                applied_fixes = auto_fixer.apply(proposed_fixes)

    # Output results
    if output == "json":
        _output_json(result, applied_fixes)
    elif output == "markdown":
        _output_markdown(result, verbose, applied_fixes)
    else:
        _output_text(result, verbose, applied_fixes)

    # Exit with appropriate code
    if result.total_findings > 0:
        # Check if any findings are HIGH or CRITICAL
        by_severity = result.findings_by_severity
        if by_severity.get(Severity.CRITICAL, 0) > 0 or by_severity.get(Severity.HIGH, 0) > 0:
            sys.exit(1)
    sys.exit(0)


def _output_json(result: ScanResult, applied_fixes: list = None) -> None:
    """Output scan results as JSON."""
    output = result.to_dict()
    if applied_fixes:
        output["applied_fixes"] = [fix.to_dict() for fix in applied_fixes]
    click.echo(json.dumps(output, indent=2))


def _output_text(result: ScanResult, verbose: bool = False, applied_fixes: list = None) -> None:
    """Output scan results as formatted text with colors."""
    # Header
    click.echo("")
    click.echo(click.style("Security Sensei", fg="bright_blue", bold=True) + f" v{__version__}")
    click.echo(click.style("-" * 50, fg="bright_black"))

    # Project info
    languages = result.project_info.get("languages", [])
    click.echo(f"Project: {result.project_info.get('path', '.')}")
    click.echo(f"Languages: {', '.join(languages) if languages else 'None detected'}")

    if verbose:
        frameworks = result.project_info.get("frameworks", [])
        if frameworks:
            click.echo(f"Frameworks: {', '.join(frameworks)}")
        click.echo(f"Scanners: {', '.join(result.scanners_run)}")

    click.echo("")

    # Summary counts
    by_severity = result.findings_by_severity

    if result.total_findings == 0:
        click.echo(click.style("[OK] No security issues found!", fg="green", bold=True))
    else:
        # Build summary line with colors
        summary_parts = []
        if by_severity.get(Severity.CRITICAL, 0) > 0:
            count = by_severity[Severity.CRITICAL]
            summary_parts.append(click.style(f"{count} critical", fg="red", bold=True))
        if by_severity.get(Severity.HIGH, 0) > 0:
            count = by_severity[Severity.HIGH]
            summary_parts.append(click.style(f"{count} high", fg="yellow", bold=True))
        if by_severity.get(Severity.MEDIUM, 0) > 0:
            count = by_severity[Severity.MEDIUM]
            summary_parts.append(click.style(f"{count} medium", fg="cyan"))
        if by_severity.get(Severity.LOW, 0) > 0:
            count = by_severity[Severity.LOW]
            summary_parts.append(click.style(f"{count} low", fg="white"))
        if by_severity.get(Severity.INFO, 0) > 0:
            count = by_severity[Severity.INFO]
            summary_parts.append(click.style(f"{count} info", fg="bright_black"))

        click.echo(f"Found {click.style(str(result.total_findings), bold=True)} findings: {', '.join(summary_parts)}")
        click.echo("")

        # List findings
        for finding in result.findings:
            _print_finding(finding, verbose)

    # Baselined count
    if result.baselined_count > 0:
        click.echo(click.style(f"({result.baselined_count} baselined findings hidden)", fg="bright_black"))

    # Footer with scan time
    click.echo(click.style("-" * 50, fg="bright_black"))
    click.echo(click.style(f"Scan completed in {result.scan_time:.2f}s", fg="bright_black"))

    # Summary box at end
    if result.total_findings > 0:
        click.echo("")
        _print_summary_box(by_severity)

    # Applied fixes
    if applied_fixes:
        click.echo("")
        _print_applied_fixes(applied_fixes)


def _output_proposed_fixes(proposed_fixes: list) -> None:
    """Output proposed fixes in dry-run mode."""
    click.echo("")
    click.echo(click.style("Proposed Fixes (Dry Run)", fg="bright_blue", bold=True))
    click.echo(click.style("-" * 50, fg="bright_black"))
    click.echo("")

    for fix in proposed_fixes:
        click.echo(click.style(f"[{fix.fix_type}]", fg="green", bold=True) + f" {fix.description}")
        click.echo(click.style(f"  File: {fix.file_path}", fg="bright_black"))
        click.echo("")
        click.echo(click.style("  Preview:", fg="cyan"))
        for line in fix.preview.split("\n"):
            click.echo(click.style(f"    {line}", fg="bright_black"))
        click.echo("")

    click.echo(click.style("-" * 50, fg="bright_black"))
    click.echo(f"Total: {len(proposed_fixes)} fix(es) would be applied")
    click.echo(click.style("Run without --dry-run to apply these fixes", fg="yellow"))


def _print_applied_fixes(applied_fixes: list) -> None:
    """Print applied fixes summary."""
    click.echo(click.style("Applied Fixes", fg="green", bold=True))
    click.echo(click.style("-" * 50, fg="bright_black"))

    for fix in applied_fixes:
        click.echo(click.style(f"[OK]", fg="green", bold=True) + f" {fix.description}")
        click.echo(click.style(f"  File: {fix.file_path}", fg="bright_black"))
        click.echo(click.style(f"  Changes: {fix.changes_made}", fg="bright_black"))
        if fix.backup_path:
            click.echo(click.style(f"  Backup: {fix.backup_path}", fg="bright_black"))
        click.echo("")

    click.echo(click.style("-" * 50, fg="bright_black"))
    click.echo(click.style(f"Applied {len(applied_fixes)} fix(es)", fg="green"))


def _print_finding(finding: Finding, verbose: bool = False) -> None:
    """Print a single finding with colors."""
    color = SEVERITY_COLORS.get(finding.severity, "white")
    bold = SEVERITY_BOLD.get(finding.severity, False)

    # Severity badge and title
    severity_badge = click.style(f"[{finding.severity}]", fg=color, bold=bold)
    click.echo(f"{severity_badge} {finding.title}")

    # Location
    location = f"  {finding.file_path}"
    if finding.line_number:
        location += f":{finding.line_number}"
    click.echo(click.style(location, fg="bright_black"))

    # Historical finding info (from git history)
    metadata = finding.metadata or {}
    if metadata.get("historical"):
        commit = metadata.get("commit", "unknown")
        deleted = metadata.get("deleted", False)
        status = "deleted from current files" if deleted else "still present"
        click.echo(click.style(f"  Git: commit {commit} ({status})", fg="magenta"))

    # Code snippet (verbose mode)
    if finding.code_snippet and verbose:
        snippet = finding.code_snippet[:80]
        if len(finding.code_snippet) > 80:
            snippet += "..."
        click.echo(click.style(f"  Code: {snippet}", fg="bright_black"))

    # Auto-fixable indicator
    if finding.auto_fixable:
        click.echo(click.style("  [*] Auto-fixable", fg="green"))

    # References
    refs = []
    if finding.cwe_id:
        refs.append(finding.cwe_id)
    if finding.owasp_category:
        refs.append(f"OWASP {finding.owasp_category}")
    if refs:
        click.echo(click.style(f"  {' | '.join(refs)}", fg="bright_black"))

    click.echo("")


def _print_summary_box(by_severity: dict) -> None:
    """Print a summary box with severity counts."""
    click.echo(click.style("+-----------------------------+", fg="bright_black"))
    click.echo(click.style("|", fg="bright_black") + "         Summary            " + click.style("|", fg="bright_black"))
    click.echo(click.style("+-----------------------------+", fg="bright_black"))

    for sev, label, color in [
        (Severity.CRITICAL, "Critical", "red"),
        (Severity.HIGH, "High", "yellow"),
        (Severity.MEDIUM, "Medium", "cyan"),
        (Severity.LOW, "Low", "white"),
        (Severity.INFO, "Info", "bright_black"),
    ]:
        count = by_severity.get(sev, 0)
        if count > 0:
            count_str = click.style(f"{count:>3}", fg=color, bold=(sev in [Severity.CRITICAL, Severity.HIGH]))
            label_str = click.style(f"{label:<10}", fg=color)
            click.echo(click.style("|", fg="bright_black") + f"  {label_str} {count_str}            " + click.style("|", fg="bright_black"))

    click.echo(click.style("+-----------------------------+", fg="bright_black"))


def _output_markdown(result: ScanResult, verbose: bool = False, applied_fixes: list = None) -> None:
    """Output scan results as Markdown."""
    # Header
    click.echo(f"# Security Scan Report")
    click.echo("")
    click.echo(f"**Generated by:** Security Sensei v{__version__}")
    click.echo(f"**Scan time:** {result.scan_timestamp}")
    click.echo(f"**Duration:** {result.scan_time:.2f}s")
    click.echo("")

    # Project info
    click.echo("## Project Information")
    click.echo("")
    click.echo(f"- **Path:** `{result.project_info.get('path', '.')}`")
    languages = result.project_info.get("languages", [])
    click.echo(f"- **Languages:** {', '.join(languages) if languages else 'None detected'}")
    frameworks = result.project_info.get("frameworks", [])
    if frameworks:
        click.echo(f"- **Frameworks:** {', '.join(frameworks)}")
    click.echo(f"- **Scanners run:** {', '.join(result.scanners_run)}")
    click.echo("")

    # Summary
    by_severity = result.findings_by_severity
    click.echo("## Summary")
    click.echo("")
    click.echo(f"| Severity | Count |")
    click.echo("|----------|-------|")
    click.echo(f"| Critical | {by_severity.get(Severity.CRITICAL, 0)} |")
    click.echo(f"| High | {by_severity.get(Severity.HIGH, 0)} |")
    click.echo(f"| Medium | {by_severity.get(Severity.MEDIUM, 0)} |")
    click.echo(f"| Low | {by_severity.get(Severity.LOW, 0)} |")
    click.echo(f"| Info | {by_severity.get(Severity.INFO, 0)} |")
    click.echo(f"| **Total** | **{result.total_findings}** |")
    click.echo("")

    if result.baselined_count > 0:
        click.echo(f"*{result.baselined_count} findings were baselined and hidden.*")
        click.echo("")

    # Findings
    if result.total_findings == 0:
        click.echo("## Findings")
        click.echo("")
        click.echo("**No security issues found!**")
    else:
        click.echo("## Findings")
        click.echo("")

        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_findings = [f for f in result.findings if f.severity == severity]
            if not severity_findings:
                continue

            click.echo(f"### {severity} ({len(severity_findings)})")
            click.echo("")

            for finding in severity_findings:
                _print_finding_markdown(finding, verbose)

    # Applied fixes section
    if applied_fixes:
        click.echo("")
        click.echo("## Applied Fixes")
        click.echo("")
        click.echo(f"The following {len(applied_fixes)} fix(es) were automatically applied:")
        click.echo("")
        for fix in applied_fixes:
            click.echo(f"### {fix.description}")
            click.echo("")
            click.echo(f"- **File:** `{fix.file_path}`")
            click.echo(f"- **Changes:** {fix.changes_made}")
            if fix.backup_path:
                click.echo(f"- **Backup:** `{fix.backup_path}`")
            click.echo("")

    click.echo("")
    click.echo("---")
    click.echo(f"*Report generated by [Security Sensei](https://github.com/danieljcheung/security-sensei)*")


def _print_finding_markdown(finding: Finding, verbose: bool = False) -> None:
    """Print a finding in Markdown format."""
    location = f"`{finding.file_path}"
    if finding.line_number:
        location += f":{finding.line_number}"
    location += "`"

    click.echo(f"#### {finding.title}")
    click.echo("")
    click.echo(f"- **Location:** {location}")

    refs = []
    if finding.cwe_id:
        refs.append(finding.cwe_id)
    if finding.owasp_category:
        refs.append(f"OWASP {finding.owasp_category}")
    if refs:
        click.echo(f"- **References:** {' | '.join(refs)}")

    if finding.auto_fixable:
        click.echo(f"- **Auto-fixable:** Yes")

    click.echo("")
    click.echo(f"> {finding.description}")
    click.echo("")

    if finding.code_snippet and verbose:
        click.echo("**Code:**")
        click.echo("```")
        click.echo(finding.code_snippet)
        click.echo("```")
        click.echo("")

    click.echo(f"**Fix:** {finding.fix_recommendation}")
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
