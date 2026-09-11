"""Inline suppression directives (``# pqc-scan: ignore[PQC001]``).

Every linter a developer already uses supports an in-source escape hatch, and a
scanner without one gets silenced wholesale (``rules.disable``) the first time it
reports something a team has consciously accepted. These directives keep the
acceptance next to the code that needs it, with a reason attached.

The parser is deliberately **comment-syntax agnostic**: it looks for the
directive anywhere in a raw line, so the same spelling works in Python (``#``),
Go/Java/JS (``//``, ``/* */``), YAML, ``.conf`` files and dependency manifests
without this module needing to know any language's comment grammar. The cost is
that a directive inside a *string literal* also suppresses — an acceptable
trade for a token as unusual as ``pqc-scan: ignore``.

Supported forms (case-insensitive, ``pqcscan``/``pqc_scan`` also accepted)::

    key = rsa.generate_private_key(...)   # pqc-scan: ignore
    key = rsa.generate_private_key(...)   # pqc-scan: ignore[PQC001]
    # pqc-scan: ignore-next-line[PQC001,PQC003] -- legacy interop, tracked in JIRA-42
    key = rsa.generate_private_key(...)
    # pqc-scan: ignore-file[PQC014]

``ignore`` applies to the line it appears on, ``ignore-next-line`` to the
following line, and ``ignore-file`` to every finding in the file. An empty or
absent rule list means "every rule". Text after ``--`` is recorded as the reason
and reported back so a reviewer can audit why something was waived.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

#: Directive kinds, longest-first so the alternation does not match the
#: ``ignore`` prefix of ``ignore-next-line``.
_KINDS = ("ignore-next-line", "ignore-file", "ignore")

_DIRECTIVE_RE = re.compile(
    r"pqc[-_]?scan\s*:\s*(" + "|".join(_KINDS) + r")"
    r"(?:\s*\[([^\]]*)\])?"
    r"(?:\s*--\s*(.*))?",
    re.IGNORECASE,
)

#: Cheap pre-filter: skip the per-line regex entirely for files with no marker.
_MARKER_RE = re.compile(r"pqc[-_]?scan\s*:", re.IGNORECASE)

_RULE_ID_RE = re.compile(r"[A-Za-z]+[0-9]+")


@dataclass(frozen=True)
class Directive:
    """One parsed suppression directive."""

    kind: str
    #: Rule ids this directive covers; ``None`` means every rule.
    rules: Optional[frozenset[str]]
    reason: Optional[str]
    line_number: int

    def covers(self, rule_id: str) -> bool:
        return self.rules is None or rule_id.upper() in self.rules

    def describe(self) -> str:
        scope = "all rules" if self.rules is None else ",".join(sorted(self.rules))
        base = f"{self.kind}[{scope}] at line {self.line_number}"
        return f"{base}: {self.reason}" if self.reason else base


class FileSuppressions:
    """Suppression directives parsed out of one file."""

    __slots__ = ("_file", "_lines")

    def __init__(self) -> None:
        self._file: list[Directive] = []
        self._lines: dict[int, list[Directive]] = {}

    def match(self, rule_id: str, line_number: int) -> Optional[Directive]:
        """The directive suppressing *rule_id* at *line_number*, if any."""
        for directive in self._file:
            if directive.covers(rule_id):
                return directive
        for directive in self._lines.get(line_number, ()):
            if directive.covers(rule_id):
                return directive
        return None

    def __bool__(self) -> bool:
        return bool(self._file or self._lines)

    def __len__(self) -> int:
        return len(self._file) + sum(len(v) for v in self._lines.values())


def _parse_rules(raw: Optional[str]) -> Optional[frozenset[str]]:
    """``"PQC001, pqc009"`` -> ``{"PQC001", "PQC009"}``; empty/missing -> ``None``."""
    if raw is None:
        return None
    ids = {m.group(0).upper() for m in _RULE_ID_RE.finditer(raw)}
    return frozenset(ids) or None


def _parse_reason(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    # Trim trailing comment punctuation (`*/`, `-->`) so a directive inside a
    # block comment does not carry the terminator into the reason.
    reason = raw.strip().rstrip("*/->").strip()
    return reason or None


def parse_suppressions(text: str) -> FileSuppressions:
    """Parse every suppression directive in *text*."""
    suppressions = FileSuppressions()
    if not _MARKER_RE.search(text):
        return suppressions
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in _DIRECTIVE_RE.finditer(line):
            directive = Directive(
                kind=match.group(1).lower(),
                rules=_parse_rules(match.group(2)),
                reason=_parse_reason(match.group(3)),
                line_number=line_no,
            )
            if directive.kind == "ignore-file":
                suppressions._file.append(directive)
            elif directive.kind == "ignore-next-line":
                suppressions._lines.setdefault(line_no + 1, []).append(directive)
            else:
                suppressions._lines.setdefault(line_no, []).append(directive)
    return suppressions
