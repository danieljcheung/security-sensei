"""Command-line interface for Security Sensei."""

import json
import os
import sys
import threading
import time
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table

from sensei import __version__
from sensei.core.scanner import SenseiScanner, ScanResult
from sensei.core.finding import Finding, Severity
from sensei.core.baseline import BaselineManager
from sensei.fixes import AutoFixer, ProposedFix, AppliedFix


# Check if terminal supports Unicode (most modern terminals do)
def _supports_unicode() -> bool:
    """Check if the terminal supports Unicode output."""
    if sys.platform == "win32":
        # Check if running in Windows Terminal or other modern terminal
        return os.environ.get("WT_SESSION") is not None or os.environ.get("TERM_PROGRAM") is not None
    return True


# Use ASCII fallbacks on systems without Unicode support
UNICODE_SUPPORT = _supports_unicode()

# Rich console for output - force UTF-8 on Windows
if sys.platform == "win32":
    # Enable UTF-8 mode for Windows console
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass

console = Console(force_terminal=True)

# Severity emoji and color mapping (with ASCII fallbacks)
if UNICODE_SUPPORT:
    SEVERITY_CONFIG = {
        Severity.CRITICAL: {"emoji": "🔴", "color": "bold bright_red", "label": "CRITICAL"},
        Severity.HIGH: {"emoji": "🟠", "color": "red", "label": "HIGH"},
        Severity.MEDIUM: {"emoji": "🟡", "color": "yellow", "label": "MEDIUM"},
        Severity.LOW: {"emoji": "🔵", "color": "blue", "label": "LOW"},
        Severity.INFO: {"emoji": "⚪", "color": "dim", "label": "INFO"},
    }
    SPINNER_CHARS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    ICON_OK = "✓"
    ICON_FAIL = "✗"
    ICON_WARN = "⚠️"
    ICON_SENSEI = "🥋"
else:
    # ASCII fallbacks for older terminals
    SEVERITY_CONFIG = {
        Severity.CRITICAL: {"emoji": "[!]", "color": "bold bright_red", "label": "CRITICAL"},
        Severity.HIGH: {"emoji": "[H]", "color": "red", "label": "HIGH"},
        Severity.MEDIUM: {"emoji": "[M]", "color": "yellow", "label": "MEDIUM"},
        Severity.LOW: {"emoji": "[L]", "color": "blue", "label": "LOW"},
        Severity.INFO: {"emoji": "[i]", "color": "dim", "label": "INFO"},
    }
    SPINNER_CHARS = "|/-\\"
    ICON_OK = "[OK]"
    ICON_FAIL = "[X]"
    ICON_WARN = "[!]"
    ICON_SENSEI = "[S]"


class ScanProgress:
    """Track scan progress for live display."""

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.current_status = "Initializing..."
        self.completed_scanners: List[dict] = []
        self.project_info: Optional[dict] = None
        self.spinner_idx = 0
        self._lock = threading.Lock()

    def update(self, event_type: str, data: dict) -> None:
        """Handle progress callback from scanner."""
        with self._lock:
            if event_type == 'project_analyzed':
                self.project_info = data
                self.current_status = "Project analyzed"
            elif event_type == 'scanner_start':
                self.current_status = f"Running {data['name']} scanner..."
            elif event_type == 'scanner_complete':
                self.completed_scanners.append({
                    'name': data['name'],
                    'findings': data['findings_count'],
                    'status': 'success',
                })
                self.current_status = f"{data['name']} complete"
            elif event_type == 'scanner_error':
                self.completed_scanners.append({
                    'name': data['name'],
                    'error': data['error'],
                    'status': 'error',
                })
                self.current_status = f"{data['name']} failed"

    def get_spinner_char(self) -> str:
        """Get current spinner character."""
        char = SPINNER_CHARS[self.spinner_idx % len(SPINNER_CHARS)]
        self.spinner_idx += 1
        return char

    def render(self) -> Text:
        """Render current progress state."""
        text = Text()

        # Show completed scanners
        for scanner in self.completed_scanners:
            if scanner['status'] == 'success':
                text.append(f"{ICON_OK} ", style="green bold")
                text.append(f"{scanner['name'].capitalize()} ", style="green")
                text.append(f"({scanner['findings']} findings)\n", style="dim")
            else:
                text.append(f"{ICON_FAIL} ", style="red bold")
                text.append(f"{scanner['name'].capitalize()} failed: ", style="red")
                text.append(f"{scanner['error']}\n", style="dim red")

        # Show current status with spinner
        if self.current_status and "complete" not in self.current_status.lower():
            spinner = self.get_spinner_char()
            text.append(f"{spinner} ", style="cyan")
            text.append(self.current_status, style="cyan")

        return text


def print_banner(quiet: bool = False) -> None:
    """Print the Security Sensei banner."""
    if quiet:
        return

    banner_text = Text()
    banner_text.append(f"  {ICON_SENSEI} SECURITY SENSEI ", style="bold bright_blue")
    banner_text.append(f"v{__version__}\n", style="dim")
    banner_text.append("  Find vulnerabilities. Learn why.", style="italic dim")

    panel = Panel(
        banner_text,
        border_style="bright_blue",
        padding=(0, 1),
    )
    console.print(panel)
    console.print()


def print_project_info(project_info: dict, quiet: bool = False) -> None:
    """Print detected project information."""
    if quiet:
        return

    languages = project_info.get('languages', [])
    package_managers = project_info.get('package_managers', [])

    text = Text()
    text.append(f"{ICON_OK} ", style="green bold")
    text.append("Detected: ", style="green")

    parts = []
    if languages:
        parts.append(", ".join(lang.capitalize() for lang in languages))
    if package_managers:
        parts.append(f"({', '.join(package_managers)})")

    text.append(" ".join(parts) if parts else "No specific languages detected", style="dim")
    console.print(text)
    console.print()


def print_findings(findings: List[Finding], verbose: bool = False, quiet: bool = False) -> None:
    """Print findings grouped by severity."""
    if quiet or not findings:
        return

    console.print()
    console.print("─" * 50, style="dim")
    console.print("FINDINGS", style="bold")
    console.print("─" * 50, style="dim")
    console.print()

    # Group by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        config = SEVERITY_CONFIG[severity]

        for finding in severity_findings:
            # Severity badge and title
            text = Text()
            text.append(f"{config['emoji']} ", style=config['color'])
            text.append(f"{config['label']}: ", style=config['color'])
            text.append(finding.title, style="bold")
            console.print(text)

            # Location
            location = f"   {finding.file_path}"
            if finding.line_number:
                location += f":{finding.line_number}"
            console.print(location, style="cyan")

            # Description
            console.print(f"   → {finding.description}", style="dim")

            # Historical finding info (from git history)
            metadata = finding.metadata or {}
            if metadata.get("historical"):
                commit = metadata.get("commit", "unknown")
                deleted = metadata.get("deleted", False)
                status = "deleted from current files" if deleted else "still present"
                console.print(f"   Git: commit {commit} ({status})", style="magenta")

            # Code snippet (verbose mode)
            if finding.code_snippet and verbose:
                snippet = finding.code_snippet[:80]
                if len(finding.code_snippet) > 80:
                    snippet += "..."
                console.print(f"   Code: {snippet}", style="dim")

            # Auto-fixable indicator
            if finding.auto_fixable:
                console.print("   [*] Auto-fixable", style="green")

            # References
            refs = []
            if finding.cwe_id:
                refs.append(finding.cwe_id)
            if finding.owasp_category:
                refs.append(f"OWASP {finding.owasp_category}")
            if refs:
                console.print(f"   {' | '.join(refs)}", style="dim")

            console.print()


def print_summary_box(
    result: ScanResult,
    applied_fixes: List[AppliedFix] = None,
    quiet: bool = False,
) -> None:
    """Print the final summary box."""
    if quiet:
        return

    by_severity = result.findings_by_severity

    # Build summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="dim")
    table.add_column("Value", style="bold")

    # Total findings
    table.add_row("Total:", f"{result.total_findings} findings")
    table.add_row("", "")

    # Severity counts on same line
    severity_line = Text()
    for sev, cfg in [
        (Severity.CRITICAL, SEVERITY_CONFIG[Severity.CRITICAL]),
        (Severity.HIGH, SEVERITY_CONFIG[Severity.HIGH]),
        (Severity.MEDIUM, SEVERITY_CONFIG[Severity.MEDIUM]),
        (Severity.LOW, SEVERITY_CONFIG[Severity.LOW]),
    ]:
        count = by_severity.get(sev, 0)
        if count > 0 or sev in [Severity.CRITICAL, Severity.HIGH]:
            severity_line.append(f"{cfg['emoji']} {cfg['label']} ", style=cfg['color'])
            severity_line.append(f"{count}  ", style="bold")

    # Build panel content
    content = Text()
    content.append("Total: ", style="dim")
    content.append(f"{result.total_findings} findings\n\n", style="bold")
    content.append(severity_line)

    # Add auto-fixes and baselined info
    extras = []
    if applied_fixes:
        extras.append(f"Auto-fixes applied: {len(applied_fixes)}")
    if result.baselined_count > 0:
        extras.append(f"Baselined (skipped): {result.baselined_count}")

    if extras:
        content.append("\n\n")
        for extra in extras:
            content.append(f"{extra}\n", style="dim")

    # Determine panel style based on severity
    if by_severity.get(Severity.CRITICAL, 0) > 0:
        border_style = "bright_red"
        title = f"{ICON_WARN}  SCAN COMPLETE - CRITICAL ISSUES FOUND"
    elif by_severity.get(Severity.HIGH, 0) > 0:
        border_style = "red"
        title = f"{ICON_WARN}  SCAN COMPLETE - HIGH ISSUES FOUND"
    elif result.total_findings > 0:
        border_style = "yellow"
        title = "SCAN COMPLETE"
    else:
        border_style = "green"
        title = f"{ICON_OK} SCAN COMPLETE - NO ISSUES FOUND"

    console.print()
    console.print(Panel(content, title=title, border_style=border_style))
    console.print(f"Scan completed in {result.scan_time:.2f}s", style="dim")


def print_applied_fixes(applied_fixes: List[AppliedFix], quiet: bool = False) -> None:
    """Print applied fixes summary."""
    if quiet or not applied_fixes:
        return

    console.print()
    console.print("─" * 50, style="dim")
    console.print("APPLIED FIXES", style="bold green")
    console.print("─" * 50, style="dim")

    for fix in applied_fixes:
        text = Text()
        text.append(f"{ICON_OK} ", style="green bold")
        text.append(fix.description, style="green")
        console.print(text)
        console.print(f"   File: {fix.file_path}", style="cyan")
        console.print(f"   Changes: {fix.changes_made}", style="dim")
        if fix.backup_path:
            console.print(f"   Backup: {fix.backup_path}", style="dim")
        console.print()


def print_proposed_fixes(proposed_fixes: List[ProposedFix], quiet: bool = False) -> None:
    """Print proposed fixes in dry-run mode."""
    if quiet or not proposed_fixes:
        return

    console.print()
    console.print("─" * 50, style="dim")
    console.print("PROPOSED FIXES (DRY RUN)", style="bold bright_blue")
    console.print("─" * 50, style="dim")
    console.print()

    for fix in proposed_fixes:
        text = Text()
        text.append(f"[{fix.fix_type}] ", style="cyan bold")
        text.append(fix.description)
        console.print(text)
        console.print(f"   File: {fix.file_path}", style="cyan")
        console.print()
        console.print("   Preview:", style="yellow")
        for line in fix.preview.split("\n"):
            console.print(f"     {line}", style="dim")
        console.print()

    console.print("─" * 50, style="dim")
    console.print(f"Total: {len(proposed_fixes)} fix(es) would be applied")
    console.print("Run without --dry-run to apply these fixes", style="yellow")


def _output_json(result: ScanResult, applied_fixes: List[AppliedFix] = None) -> None:
    """Output scan results as JSON."""
    output = result.to_dict()
    if applied_fixes:
        output["applied_fixes"] = [fix.to_dict() for fix in applied_fixes]
    console.print_json(json.dumps(output, indent=2))


def _output_markdown(result: ScanResult, verbose: bool = False, applied_fixes: List[AppliedFix] = None) -> None:
    """Output scan results as Markdown."""
    # Header
    print(f"# Security Scan Report")
    print("")
    print(f"**Generated by:** Security Sensei v{__version__}")
    print(f"**Scan time:** {result.scan_timestamp}")
    print(f"**Duration:** {result.scan_time:.2f}s")
    print("")

    # Project info
    print("## Project Information")
    print("")
    print(f"- **Path:** `{result.project_info.get('path', '.')}`")
    languages = result.project_info.get("languages", [])
    print(f"- **Languages:** {', '.join(languages) if languages else 'None detected'}")
    frameworks = result.project_info.get("frameworks", [])
    if frameworks:
        print(f"- **Frameworks:** {', '.join(frameworks)}")
    print(f"- **Scanners run:** {', '.join(result.scanners_run)}")
    print("")

    # Summary
    by_severity = result.findings_by_severity
    print("## Summary")
    print("")
    print(f"| Severity | Count |")
    print("|----------|-------|")
    print(f"| 🔴 Critical | {by_severity.get(Severity.CRITICAL, 0)} |")
    print(f"| 🟠 High | {by_severity.get(Severity.HIGH, 0)} |")
    print(f"| 🟡 Medium | {by_severity.get(Severity.MEDIUM, 0)} |")
    print(f"| 🔵 Low | {by_severity.get(Severity.LOW, 0)} |")
    print(f"| ⚪ Info | {by_severity.get(Severity.INFO, 0)} |")
    print(f"| **Total** | **{result.total_findings}** |")
    print("")

    if result.baselined_count > 0:
        print(f"*{result.baselined_count} findings were baselined and hidden.*")
        print("")

    # Findings
    if result.total_findings == 0:
        print("## Findings")
        print("")
        print("**✅ No security issues found!**")
    else:
        print("## Findings")
        print("")

        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_findings = [f for f in result.findings if f.severity == severity]
            if not severity_findings:
                continue

            config = SEVERITY_CONFIG[severity]
            print(f"### {config['emoji']} {severity} ({len(severity_findings)})")
            print("")

            for finding in severity_findings:
                location = f"`{finding.file_path}"
                if finding.line_number:
                    location += f":{finding.line_number}"
                location += "`"

                print(f"#### {finding.title}")
                print("")
                print(f"- **Location:** {location}")

                refs = []
                if finding.cwe_id:
                    refs.append(finding.cwe_id)
                if finding.owasp_category:
                    refs.append(f"OWASP {finding.owasp_category}")
                if refs:
                    print(f"- **References:** {' | '.join(refs)}")

                if finding.auto_fixable:
                    print(f"- **Auto-fixable:** Yes")

                print("")
                print(f"> {finding.description}")
                print("")

                if finding.code_snippet and verbose:
                    print("**Code:**")
                    print("```")
                    print(finding.code_snippet)
                    print("```")
                    print("")

                print(f"**Fix:** {finding.fix_recommendation}")
                print("")

    # Applied fixes section
    if applied_fixes:
        print("")
        print("## Applied Fixes")
        print("")
        print(f"The following {len(applied_fixes)} fix(es) were automatically applied:")
        print("")
        for fix in applied_fixes:
            print(f"### ✓ {fix.description}")
            print("")
            print(f"- **File:** `{fix.file_path}`")
            print(f"- **Changes:** {fix.changes_made}")
            if fix.backup_path:
                print(f"- **Backup:** `{fix.backup_path}`")
            print("")

    print("")
    print("---")
    print(f"*Report generated by [Security Sensei](https://github.com/danieljcheung/security-sensei)*")


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
    help="Show verbose output including code snippets"
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Quiet mode - minimal output for CI pipelines"
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
def scan(path, output, severity, category, include_baselined, verbose, quiet, include_git_history, fix, dry_run):
    """Scan a project for security vulnerabilities."""
    config = {"verbose": verbose, "include_git_history": include_git_history}

    # Convert severity to uppercase for internal use
    min_severity = severity.upper() if severity else None

    # Convert category tuple to list or None
    categories = list(category) if category else None

    # Quiet mode implies no spinners/banner for text output
    is_interactive = output == "text" and not quiet

    # Show banner
    if is_interactive:
        print_banner()

    # Create progress tracker
    progress = ScanProgress(quiet=not is_interactive)

    # Run the scan with progress callback
    scanner = SenseiScanner(path, config)

    if is_interactive:
        # Run with live progress display
        with Live(progress.render(), refresh_per_second=10, console=console) as live:
            def update_display(event_type: str, data: dict):
                progress.update(event_type, data)
                live.update(progress.render())

            result = scanner.scan(
                categories=categories,
                min_severity=min_severity,
                include_baselined=include_baselined,
                progress_callback=update_display,
            )

        # Show project info after scan completes
        if progress.project_info:
            console.print()  # Add spacing after live output
            print_project_info(progress.project_info)
    else:
        # Non-interactive mode (JSON/markdown/quiet)
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
                if output == "text":
                    print_proposed_fixes(proposed_fixes, quiet)
            else:
                # Apply the fixes
                applied_fixes = auto_fixer.apply(proposed_fixes)

    # Output results
    if output == "json":
        _output_json(result, applied_fixes)
    elif output == "markdown":
        _output_markdown(result, verbose, applied_fixes)
    else:
        # Text output
        print_findings(result.findings, verbose, quiet)
        print_summary_box(result, applied_fixes, quiet)
        print_applied_fixes(applied_fixes, quiet)

        # Quiet mode: just print summary line
        if quiet:
            by_severity = result.findings_by_severity
            crit = by_severity.get(Severity.CRITICAL, 0)
            high = by_severity.get(Severity.HIGH, 0)
            med = by_severity.get(Severity.MEDIUM, 0)
            low = by_severity.get(Severity.LOW, 0)
            print(f"Findings: {result.total_findings} (critical={crit}, high={high}, medium={med}, low={low})")

    # Exit with appropriate code
    by_severity = result.findings_by_severity
    if by_severity.get(Severity.CRITICAL, 0) > 0:
        sys.exit(2)  # Critical findings
    elif by_severity.get(Severity.HIGH, 0) > 0:
        sys.exit(1)  # High findings
    sys.exit(0)  # No critical/high findings


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
        console.print(f"{ICON_OK} Baseline cleared.", style="green")
        return

    if add:
        for finding_id, reason in add:
            manager.add(finding_id, reason)
            console.print(f"{ICON_OK} Added {finding_id} to baseline: {reason}", style="green")

    if remove:
        for finding_id in remove:
            if manager.remove(finding_id):
                console.print(f"{ICON_OK} Removed {finding_id} from baseline", style="green")
            else:
                console.print(f"{ICON_FAIL} Finding {finding_id} was not in baseline", style="yellow")

    if list_all or (not add and not remove and not clear):
        entries = manager.list_all()
        if not entries:
            console.print("No baselined findings.", style="dim")
        else:
            console.print(f"\nBaselined findings ({len(entries)}):\n", style="bold")
            for entry in entries:
                console.print(f"  {entry['finding_id']}", style="cyan")
                console.print(f"    Reason: {entry['reason']}", style="dim")
                if entry.get('added_at'):
                    console.print(f"    Added: {entry['added_at']}", style="dim")
                console.print("")


@cli.command()
def version():
    """Show the version of Security Sensei."""
    print_banner(quiet=False)


@cli.command()
@click.option(
    "--slow",
    is_flag=True,
    help="Slower animations for GIF recording"
)
@click.option(
    "--json",
    "show_json",
    is_flag=True,
    help="Show JSON output example at end"
)
def demo(slow, show_json):
    """Run a showcase demo for screenshots/recording."""
    from sensei.demo import run_demo
    run_demo(slow=slow, show_json=show_json)


if __name__ == "__main__":
    cli()
