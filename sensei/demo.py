"""Demo script for Security Sensei - showcases features for recordings/screenshots."""

import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live

from sensei import __version__
from sensei.core.finding import Finding, Severity


# Demo console - force colors even in non-TTY
console = Console(force_terminal=True, width=80)

# Timing configuration
class DemoTiming:
    """Timing configuration for demo animations."""

    def __init__(self, slow: bool = False):
        self.slow = slow
        # Multiplier for slow mode
        self.mult = 2.0 if slow else 1.0

    @property
    def banner_pause(self) -> float:
        return 1.5 * self.mult

    @property
    def intro_pause(self) -> float:
        return 1.0 * self.mult

    @property
    def spinner_frame(self) -> float:
        return 0.1 * self.mult

    @property
    def scanner_complete(self) -> float:
        return 0.8 * self.mult

    @property
    def finding_pause(self) -> float:
        return 1.2 * self.mult

    @property
    def summary_pause(self) -> float:
        return 2.5 * self.mult


# Braille spinner characters
SPINNER_CHARS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Pre-selected showcase findings for demo
DEMO_FINDINGS = [
    {
        "severity": Severity.CRITICAL,
        "emoji": "🔴",
        "title": "Command Injection (os.system)",
        "file": "app.py",
        "line": 29,
        "code": 'os.system(f"ping {host}")',
        "desc": "User input passed directly to shell command",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "severity": Severity.HIGH,
        "emoji": "🟠",
        "title": "SQL Injection (f-string)",
        "file": "app.py",
        "line": 17,
        "code": 'f"SELECT * FROM users WHERE id = {user_id}"',
        "desc": "User input concatenated into SQL query",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "severity": Severity.HIGH,
        "emoji": "🟠",
        "title": "Hardcoded Database Credentials",
        "file": "config.py",
        "line": 35,
        "code": 'postgresql://admin:password123@localhost/db',
        "desc": "Database credentials exposed in source code",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
    },
    {
        "severity": Severity.MEDIUM,
        "emoji": "🟡",
        "title": "Debug Mode Enabled",
        "file": "config.py",
        "line": 4,
        "code": "DEBUG = True",
        "desc": "Debug mode exposes sensitive information",
        "cwe": "CWE-489",
        "owasp": "A05:2021",
    },
]

# Scanner results for demo
DEMO_SCANNERS = [
    ("secrets", 4),
    ("code", 5),
    ("config", 3),
    ("dependencies", 6),
    ("deployment", 2),
]


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner() -> None:
    """Print the Security Sensei banner."""
    banner_text = Text()
    banner_text.append("  🥋 SECURITY SENSEI ", style="bold bright_blue")
    banner_text.append(f"v{__version__}\n", style="dim")
    banner_text.append("  Find vulnerabilities. Learn why.", style="italic dim")

    panel = Panel(
        banner_text,
        border_style="bright_blue",
        padding=(0, 1),
    )
    console.print(panel)


def print_intro() -> None:
    """Print demo introduction."""
    console.print()
    text = Text()
    text.append("📹 ", style="yellow")
    text.append("Demo Mode", style="bold yellow")
    text.append(" - Scanning vulnerable Python project...", style="dim")
    console.print(text)
    console.print()


def animate_scanners(timing: DemoTiming) -> None:
    """Animate scanner progress with spinners."""
    spinner_idx = 0

    for scanner_name, finding_count in DEMO_SCANNERS:
        # Animate spinner for this scanner
        frames = int(1.5 / timing.spinner_frame)  # ~1.5 seconds of spinning

        for _ in range(frames):
            char = SPINNER_CHARS[spinner_idx % len(SPINNER_CHARS)]
            spinner_idx += 1

            # Build status line
            status = Text()
            status.append(f"{char} ", style="cyan")
            status.append(f"Running {scanner_name} scanner...", style="cyan")

            # Print with carriage return to overwrite
            console.print(status, end="\r")
            time.sleep(timing.spinner_frame)

        # Show completion
        complete = Text()
        complete.append("✓ ", style="green bold")
        complete.append(f"{scanner_name.capitalize()}", style="green")
        complete.append(f" ({finding_count} findings)", style="dim")
        console.print(complete)

        time.sleep(timing.scanner_complete * 0.3)  # Brief pause between scanners


def print_findings_header() -> None:
    """Print the findings section header."""
    console.print()
    console.print("─" * 60, style="dim")
    console.print("FINDINGS", style="bold")
    console.print("─" * 60, style="dim")
    console.print()


def print_finding(finding: dict, timing: DemoTiming) -> None:
    """Print a single showcase finding with full detail."""
    severity = finding["severity"]

    # Severity colors
    colors = {
        Severity.CRITICAL: "bold bright_red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }
    color = colors.get(severity, "white")

    # Title line
    title_text = Text()
    title_text.append(f"{finding['emoji']} ", style=color)
    title_text.append(f"{severity}: ", style=color)
    title_text.append(finding["title"], style="bold")
    console.print(title_text)

    # Location
    console.print(f"   {finding['file']}:{finding['line']}", style="cyan")

    # Description
    console.print(f"   → {finding['desc']}", style="dim")

    # Code snippet
    console.print()
    console.print(f"   Code: ", style="dim", end="")
    console.print(f"{finding['code']}", style="italic dim")

    # References
    console.print(f"   {finding['cwe']} | OWASP {finding['owasp']}", style="dim")

    console.print()
    time.sleep(timing.finding_pause)


def print_summary(timing: DemoTiming) -> None:
    """Print the summary panel."""
    # Calculate totals from demo scanners
    total = sum(count for _, count in DEMO_SCANNERS)

    # Build content
    content = Text()
    content.append("Total: ", style="dim")
    content.append(f"{total} findings\n\n", style="bold")

    # Severity breakdown
    content.append("🔴 CRITICAL ", style="bold bright_red")
    content.append("4  ", style="bold")
    content.append("🟠 HIGH ", style="red")
    content.append("8  ", style="bold")
    content.append("🟡 MEDIUM ", style="yellow")
    content.append("6  ", style="bold")
    content.append("🔵 LOW ", style="blue")
    content.append("2", style="bold")

    panel = Panel(
        content,
        title="⚠️  SCAN COMPLETE - CRITICAL ISSUES FOUND",
        border_style="bright_red",
    )

    console.print()
    console.print(panel)
    console.print("Scan completed in 0.05s", style="dim")

    time.sleep(timing.summary_pause)


def print_json_flash() -> None:
    """Flash JSON output briefly."""
    console.print()
    console.print("─" * 60, style="dim")
    console.print("JSON OUTPUT (--output json)", style="bold cyan")
    console.print("─" * 60, style="dim")

    json_preview = '''{
  "summary": {
    "total": 20,
    "critical": 4,
    "high": 8,
    "medium": 6,
    "low": 2
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "Command Injection (os.system)",
      "file_path": "app.py:29",
      "cwe_id": "CWE-78"
    },
    ...
  ]
}'''
    console.print(json_preview, style="dim")
    time.sleep(1.5)


def print_outro() -> None:
    """Print demo outro."""
    console.print()
    console.print("─" * 60, style="dim")

    text = Text()
    text.append("\n🥋 ", style="bright_blue")
    text.append("Security Sensei", style="bold bright_blue")
    text.append(" - ", style="dim")
    text.append("github.com/danieljcheung/security-sensei", style="cyan underline")
    console.print(text)

    console.print()
    console.print("Commands:", style="bold")
    console.print("  sensei scan <path>        ", style="green", end="")
    console.print("Scan for vulnerabilities", style="dim")
    console.print("  sensei scan . --fix       ", style="green", end="")
    console.print("Auto-fix safe issues", style="dim")
    console.print("  sensei scan . -o json     ", style="green", end="")
    console.print("JSON output for CI", style="dim")
    console.print()


def run_demo(slow: bool = False, show_json: bool = False) -> None:
    """Run the full demo sequence.

    Args:
        slow: Use slower animations for GIF recording
        show_json: Show JSON output flash at end
    """
    timing = DemoTiming(slow=slow)

    # 1. Setup
    clear_screen()
    print_banner()
    time.sleep(timing.banner_pause)

    print_intro()
    time.sleep(timing.intro_pause)

    # 2. Scanner animation
    animate_scanners(timing)

    # 3. Findings showcase
    print_findings_header()

    for finding in DEMO_FINDINGS:
        print_finding(finding, timing)

    # 4. Summary
    print_summary(timing)

    # 5. Optional JSON flash
    if show_json:
        print_json_flash()

    # 6. Outro
    print_outro()


if __name__ == "__main__":
    # Allow running directly: python -m sensei.demo
    import argparse
    parser = argparse.ArgumentParser(description="Security Sensei Demo")
    parser.add_argument("--slow", action="store_true", help="Slower animations")
    parser.add_argument("--json", action="store_true", help="Show JSON output")
    args = parser.parse_args()

    run_demo(slow=args.slow, show_json=args.json)
