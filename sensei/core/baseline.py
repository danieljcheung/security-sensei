"""Baseline manager for accepted security risks."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from sensei.core.finding import Finding


BASELINE_FILENAME = ".sensei-baseline.json"


class BaselineManager:
    """Manages the security baseline for accepted risks.

    Stores baselined findings in .sensei-baseline.json in the project root.
    Each baselined finding includes the finding ID, reason for acceptance,
    and timestamp.
    """

    def __init__(self, project_path: str):
        """Initialize the baseline manager.

        Args:
            project_path: Path to the project root directory.
        """
        self.project_path = Path(project_path).resolve()
        self.baseline_file = self.project_path / BASELINE_FILENAME
        self._entries: Dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        """Load the baseline file if it exists."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Support both old format (list) and new format (dict with entries)
                    if "entries" in data:
                        self._entries = data["entries"]
                    elif "accepted" in data:
                        # Migrate old format
                        self._entries = {
                            fid: {"reason": "Migrated from old baseline", "added_at": None}
                            for fid in data["accepted"]
                        }
                    else:
                        self._entries = {}
            except (json.JSONDecodeError, IOError):
                self._entries = {}
        else:
            self._entries = {}

    def save(self) -> None:
        """Save the baseline file."""
        data = {
            "version": "1.0",
            "entries": self._entries,
        }
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

    def add(self, finding_id: str, reason: str) -> None:
        """Add a finding to the baseline.

        Args:
            finding_id: The unique ID of the finding to baseline.
            reason: The reason for accepting this risk.
        """
        self._entries[finding_id] = {
            "reason": reason,
            "added_at": datetime.utcnow().isoformat() + "Z",
        }
        self.save()

    def remove(self, finding_id: str) -> bool:
        """Remove a finding from the baseline.

        Args:
            finding_id: The unique ID of the finding to remove.

        Returns:
            True if the finding was removed, False if it wasn't in the baseline.
        """
        if finding_id in self._entries:
            del self._entries[finding_id]
            self.save()
            return True
        return False

    def is_baselined(self, finding_id: str) -> bool:
        """Check if a finding is in the baseline.

        Args:
            finding_id: The unique ID of the finding to check.

        Returns:
            True if the finding is baselined, False otherwise.
        """
        return finding_id in self._entries

    def get_reason(self, finding_id: str) -> Optional[str]:
        """Get the reason for a baselined finding.

        Args:
            finding_id: The unique ID of the finding.

        Returns:
            The reason string, or None if not baselined.
        """
        entry = self._entries.get(finding_id)
        return entry["reason"] if entry else None

    def list_all(self) -> List[dict]:
        """List all baselined findings.

        Returns:
            List of dicts with finding_id, reason, and added_at for each entry.
        """
        return [
            {
                "finding_id": fid,
                "reason": entry["reason"],
                "added_at": entry.get("added_at"),
            }
            for fid, entry in sorted(self._entries.items())
        ]

    def clear(self) -> None:
        """Clear all baselined findings and delete the baseline file."""
        self._entries.clear()
        if self.baseline_file.exists():
            self.baseline_file.unlink()

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter out findings that are in the baseline.

        Args:
            findings: List of findings to filter.

        Returns:
            List of findings that are not baselined.
        """
        return [f for f in findings if not self.is_baselined(f.id)]

    def count(self) -> int:
        """Return the number of baselined findings."""
        return len(self._entries)
