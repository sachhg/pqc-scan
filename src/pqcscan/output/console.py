"""Human-readable, colored terminal output (Rich)."""

from __future__ import annotations

import io
import os
from collections import OrderedDict
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.text import Text

from pqcscan.scanner.base import RULES, Finding
from pqcscan.scanner.engine import ScanResult

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}
SEVERITY_MARKER = {
    "critical": "✖",
    "high": "⚠",
    "medium": "▲",
    "low": "ℹ",
}

GROUP_BY_CHOICES = ("severity", "file")

#: How many scan errors to print verbatim before collapsing to a count.
_MAX_ERRORS_SHOWN = 5


class ConsoleReporter:
    """Renders a :class:`ScanResult` to a terminal."""

    def __init__(self, console: Optional[Console] = None, *, no_color: bool = False):
        self.console = console or Console(no_color=no_color, highlight=False, soft_wrap=False)

    # ----- public API ---------------------------------------------------- #

    def report(
        self,
        result: ScanResult,
        *,
        show_migration: bool = True,
        limit: int = 0,
        summary_only: bool = False,
        group_by: str = "severity",
    ) -> None:
        """Render *result*.

        ``limit`` > 0 caps the number of individual findings printed;
        ``summary_only`` prints only the totals and a per-file breakdown;
        ``group_by`` is ``severity`` (default, most severe first) or ``file``.
        """
        console = self.console
        console.print()
        console.print(
            Text("  pqc-scan", style="bold white")
            + Text("  ·  Post-Quantum Cryptography scan", style="dim")
        )
        console.print()

        if not result.findings:
            console.print(
                Text("  ✓ No quantum-vulnerable cryptography detected.", style="bold green")
            )
            self._summary(result)
            return

        if summary_only:
            self._file_breakdown(result)
            self._summary(result)
            return

        shown = 0
        if group_by == "file":
            for file_path, group in self._grouped_by_file(result).items():
                if limit and shown >= limit:
                    break
                header = Text("  ▍ ", style="bold")
                header.append(self._display_path(file_path, result), style="bold underline")
                header.append(f"   {len(group)} finding(s)", style="dim")
                console.print(header)
                console.print()
                for finding in group:
                    if limit and shown >= limit:
                        break
                    self._render_finding(finding, result, show_migration=show_migration)
                    console.print()
                    shown += 1
        else:
            for finding in result.findings:
                if limit and shown >= limit:
                    break
                self._render_finding(finding, result, show_migration=show_migration)
                console.print()
                shown += 1

        remaining = result.total - shown
        if remaining > 0:
            console.print(
                Text(
                    f"  … {remaining} more finding(s) not shown "
                    "(raise --limit, or use --summary for a per-file overview).",
                    style="dim",
                )
            )

        self._summary(result)

    # ----- finding rendering --------------------------------------------- #

    def _render_finding(self, f: Finding, result: ScanResult, *, show_migration: bool) -> None:
        console = self.console
        style = SEVERITY_STYLE.get(f.severity, "white")
        marker = SEVERITY_MARKER.get(f.severity, "•")
        rule = RULES.get(f.rule_id)
        title = rule.name if rule else f.rule_id

        header = Text("  ")
        header.append(f"{marker}  {f.severity.upper()}", style=style)
        header.append("  ")
        header.append(f"{f.rule_id}", style="bold")
        header.append(" · ")
        header.append(title, style="bold white")
        header.append(f"   [{f.confidence} confidence]", style="dim")
        console.print(header)

        loc = Text("  ┌─ ", style=style)
        loc.append(
            f"{self._display_path(f.file_path, result)}:{f.line_number}:{f.column_number}",
            style="underline",
        )
        loc.append(f"   ({f.algorithm})", style="dim")
        console.print(loc)

        for line in (f.code_snippet or "").splitlines() or [""]:
            row = Text("  │  ", style=style)
            row.append(line)
            console.print(row)

        desc = Text("  └─ ", style=style)
        desc.append(f.description)
        console.print(desc)

        if show_migration and f.migration_suggestion:
            mig = f.migration_suggestion
            console.print(
                Text("       Migrate to: ", style="bold green")
                + Text(_shorten(mig.recommended_algorithm, 80), style="green")
                + Text(f"  ·  {mig.nist_standard}", style="dim")
            )
            console.print(
                Text("       ", style="")
                + Text(_shorten(mig.recommended_library, 100), style="dim")
            )
            console.print(Text(f"       see: {mig.docs_url}", style="blue underline"))

        if f.context_hint:
            console.print(
                Text("       Context: ", style="bold cyan")
                + Text(f.context_hint, style="italic dim")
            )

    # ----- per-file breakdown (for --summary) ----------------------------- #

    def _file_breakdown(self, result: ScanResult) -> None:
        table = Table(title=None, show_lines=False, pad_edge=False, box=None)
        table.add_column("  File", style="bold", overflow="fold")
        for sev in ("critical", "high", "medium", "low"):
            table.add_column(sev.capitalize(), justify="right", style=SEVERITY_STYLE[sev])
        table.add_column("Total", justify="right", style="bold")

        for file_path, group in self._grouped_by_file(result).items():
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in group:
                if f.severity in counts:
                    counts[f.severity] += 1
            table.add_row(
                "  " + self._display_path(file_path, result),
                *(str(counts[s]) if counts[s] else "·" for s in ("critical", "high", "medium", "low")),
                str(len(group)),
            )
        self.console.print(table)

    @staticmethod
    def _grouped_by_file(result: ScanResult) -> "OrderedDict[str, list[Finding]]":
        """Findings grouped by file; files ordered by their most severe finding
        (result.findings is already sorted most-severe first), findings within a
        file ordered by line."""
        groups: OrderedDict[str, list[Finding]] = OrderedDict()
        for f in result.findings:
            groups.setdefault(f.file_path, []).append(f)
        for group in groups.values():
            group.sort(key=lambda f: (f.line_number, f.column_number, f.rule_id))
        return groups

    # ----- summary ------------------------------------------------------- #

    def _summary(self, result: ScanResult) -> None:
        console = self.console
        counts = result.counts_by_severity()
        console.print()
        console.rule(style="dim")
        line = Text("  ")
        for sev in ("critical", "high", "medium", "low"):
            line.append(f"{sev.capitalize()}: ", style=SEVERITY_STYLE[sev])
            line.append(f"{counts[sev]}  ", style="bold")
        line.append(" |  ", style="dim")
        line.append("Total findings: ", style="bold")
        line.append(str(result.total), style="bold")
        console.print(line)

        meta = Text("  ")
        meta.append(f"Files scanned: {result.files_scanned}", style="dim")
        meta.append("  |  ", style="dim")
        meta.append(f"Time: {result.duration_seconds:.2f}s", style="dim")
        console.print(meta)
        if result.errors:
            for err in result.errors[:_MAX_ERRORS_SHOWN]:
                console.print(Text(f"  ! {err}", style="yellow"))
            hidden = len(result.errors) - _MAX_ERRORS_SHOWN
            if hidden > 0:
                console.print(
                    Text(f"  ! … and {hidden} more file(s) could not be scanned.", style="yellow")
                )
        console.print()

    # ----- path display ---------------------------------------------------#

    @staticmethod
    def _display_path(path: str, result: ScanResult) -> str:
        """Prefer a path relative to the scan root, then to the CWD, else as-is."""
        for base in (result.root_path, os.getcwd()):
            if not base:
                continue
            try:
                rel = os.path.relpath(path, base)
            except ValueError:  # different drive on Windows
                continue
            if not rel.startswith(".."):
                return rel
        return path


def _shorten(value: str, limit: int) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def render_to_string(
    result: ScanResult,
    *,
    no_color: bool = True,
    show_migration: bool = True,
    limit: int = 0,
    summary_only: bool = False,
    group_by: str = "severity",
) -> str:
    """Render a result to a plain string (used in tests and --output-file)."""
    console = Console(
        no_color=no_color, record=True, width=100, highlight=False, file=io.StringIO()
    )
    ConsoleReporter(console).report(
        result,
        show_migration=show_migration,
        limit=limit,
        summary_only=summary_only,
        group_by=group_by,
    )
    return console.export_text()
