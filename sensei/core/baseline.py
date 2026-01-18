"""Baseline manager for accepted security risks."""

import json
from pathlib import Path
from typing import List, Set

from sensei.core.finding import Finding


BASELINE_FILENAME = ".sensei-baseline.json"


class BaselineManager:
    """Manages the security baseline for accepted risks."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.baseline_file = self.path / BASELINE_FILENAME
        self._accepted_ids: Set[str] = set()
        self._load_baseline()

    def _load_baseline(self) -> None:
        """Load the baseline file if it exists."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r") as f:
                    data = json.load(f)
                    self._accepted_ids = set(data.get("accepted", []))
            except (json.JSONDecodeError, IOError):
                self._accepted_ids = set()

    def _save_baseline(self) -> None:
        """Save the baseline file."""
        data = {
            "accepted": sorted(list(self._accepted_ids)),
        }
        with open(self.baseline_file, "w") as f:
            json.dump(data, f, indent=2)

    def accept(self, finding_id: str) -> None:
        """Accept a finding as a known risk."""
        self._accepted_ids.add(finding_id)
        self._save_baseline()

    def reject(self, finding_id: str) -> None:
        """Remove a finding from the accepted baseline."""
        self._accepted_ids.discard(finding_id)
        self._save_baseline()

    def clear(self) -> None:
        """Clear all accepted findings."""
        self._accepted_ids.clear()
        if self.baseline_file.exists():
            self.baseline_file.unlink()

    def is_accepted(self, finding_id: str) -> bool:
        """Check if a finding is in the accepted baseline."""
        return finding_id in self._accepted_ids

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter out findings that are in the baseline."""
        return [f for f in findings if not self.is_accepted(f.id)]
