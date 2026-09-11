"""Baseline files: accept today's findings, gate CI on tomorrow's.

Dropping a scanner into a mature codebase usually surfaces hundreds of findings
at once. Without a way to say "this is the debt we already have", the only
options are to leave CI permanently red or to turn the scanner off. A baseline
is the third option: snapshot the current findings, then fail the build only on
findings that are *not* in the snapshot.

**Fingerprints are deliberately line-independent.** A baseline keyed on line
numbers invalidates itself the moment anyone adds an import, which trains people
to regenerate it and defeats the point. The fingerprint hashes the rule id, the
file path *relative to the baseline file*, the algorithm, and the
whitespace-normalized snippet — so a finding survives being moved down a file or
reformatted, while genuinely new crypto gets a new fingerprint.

Identical findings are tracked by **count**, not just presence: if a file
baselines two ``hashlib.sha1()`` calls and someone adds a third, the third is
reported as new.

The on-disk document keeps ``rule_id`` / ``path`` / ``algorithm`` alongside each
fingerprint so a baseline diff is reviewable in a pull request instead of being
an opaque wall of hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from pqcscan import __version__
from pqcscan.scanner.base import Finding

#: Default file name looked for / written by the ``baseline`` command.
DEFAULT_BASELINE_NAME = ".pqcscan-baseline.json"

_FORMAT_VERSION = 1


class BaselineError(Exception):
    """Raised when a baseline file exists but cannot be used."""


def _rel_path(file_path: str, base_dir: str) -> str:
    """Path relative to *base_dir*, POSIX-style, falling back to the basename.

    The basename fallback keeps a fingerprint stable (rather than embedding an
    absolute, machine-specific path) when a scan target lives outside the
    directory holding the baseline.
    """
    try:
        rel = os.path.relpath(file_path, base_dir)
    except ValueError:  # different drive on Windows
        return Path(file_path).name
    if rel.startswith(".."):
        return Path(file_path).name
    return rel.replace(os.sep, "/")


def fingerprint(finding: Finding, base_dir: str) -> str:
    """Stable, line-independent identity for *finding*."""
    snippet = " ".join((finding.code_snippet or "").split())
    raw = "|".join(
        (
            finding.rule_id,
            _rel_path(finding.file_path, base_dir),
            finding.algorithm,
            snippet,
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class BaselineEntry:
    rule_id: str
    path: str
    algorithm: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "algorithm": self.algorithm,
            "count": self.count,
        }


@dataclass
class Baseline:
    """A loaded baseline document."""

    entries: dict[str, BaselineEntry] = field(default_factory=dict)
    #: Directory the recorded paths (and therefore fingerprints) are relative to.
    base_dir: str = "."
    generated_at: Optional[str] = None
    source_path: Optional[str] = None

    @property
    def total(self) -> int:
        return sum(entry.count for entry in self.entries.values())

    # ----- construction --------------------------------------------------- #

    @classmethod
    def from_findings(
        cls, findings: Iterable[Finding], *, base_dir: str, generated_at: Optional[str] = None
    ) -> "Baseline":
        baseline = cls(base_dir=base_dir, generated_at=generated_at)
        counts: Counter[str] = Counter()
        meta: dict[str, Finding] = {}
        for finding in findings:
            fp = fingerprint(finding, base_dir)
            counts[fp] += 1
            meta.setdefault(fp, finding)
        for fp, count in counts.items():
            finding = meta[fp]
            baseline.entries[fp] = BaselineEntry(
                rule_id=finding.rule_id,
                path=_rel_path(finding.file_path, base_dir),
                algorithm=finding.algorithm,
                count=count,
            )
        return baseline

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        """Read a baseline document. Raises :class:`BaselineError` if unusable."""
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except OSError as exc:
            raise BaselineError(f"Could not read baseline file {p}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise BaselineError(f"Baseline file {p} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
            raise BaselineError(
                f"Baseline file {p} is missing an 'entries' object — "
                "regenerate it with 'pqc-scan baseline'."
            )
        baseline = cls(
            base_dir=str(p.parent.resolve()),
            generated_at=data.get("generated_at"),
            source_path=str(p),
        )
        for fp, raw in data["entries"].items():
            if not isinstance(raw, dict):
                continue
            try:
                count = int(raw.get("count", 1))
            except (TypeError, ValueError):
                count = 1
            baseline.entries[str(fp)] = BaselineEntry(
                rule_id=str(raw.get("rule_id", "")),
                path=str(raw.get("path", "")),
                algorithm=str(raw.get("algorithm", "")),
                count=max(1, count),
            )
        return baseline

    # ----- serialization -------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "pqc-scan",
            "version": __version__,
            "baseline_format": _FORMAT_VERSION,
            "generated_at": self.generated_at
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total": self.total,
            # Sorted by (rule, path) so regenerating produces a reviewable diff
            # rather than a reshuffled file.
            "entries": {
                fp: entry.to_dict()
                for fp, entry in sorted(
                    self.entries.items(), key=lambda kv: (kv[1].rule_id, kv[1].path, kv[0])
                )
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent) + "\n"

    def write(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    # ----- filtering ------------------------------------------------------ #

    def partition(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Split *findings* into (new, baselined).

        Counts are consumed as they match, so an extra occurrence of an
        already-baselined pattern is correctly reported as new.
        """
        remaining = {fp: entry.count for fp, entry in self.entries.items()}
        new: list[Finding] = []
        baselined: list[Finding] = []
        for finding in findings:
            fp = fingerprint(finding, self.base_dir)
            if remaining.get(fp, 0) > 0:
                remaining[fp] -= 1
                finding.baselined = True
                baselined.append(finding)
            else:
                new.append(finding)
        return new, baselined

    def diff(self, other: "Baseline") -> tuple[int, int]:
        """(added, removed) finding counts of *self* relative to *other*."""
        mine = Counter({fp: e.count for fp, e in self.entries.items()})
        theirs = Counter({fp: e.count for fp, e in other.entries.items()})
        added = sum((mine - theirs).values())
        removed = sum((theirs - mine).values())
        return added, removed


def find_baseline(start_dir: str | Path) -> Optional[Path]:
    """Discover ``.pqcscan-baseline.json`` by walking up from *start_dir*."""
    base = Path(start_dir)
    if base.is_file():
        base = base.parent
    for directory in [base, *base.resolve().parents]:
        candidate = directory / DEFAULT_BASELINE_NAME
        if candidate.is_file():
            return candidate
    return None
