"""Markdown output for pull-request comments and CI job summaries.

Console output is ANSI art and SARIF is a machine format; neither pastes into a
PR comment or a GitHub step summary. This renderer produces the shape a reviewer
actually wants there: a counts table, one scannable row per finding, and the
migration guidance folded into ``<details>`` blocks so the comment stays short
until someone opens one.

Output is length-bounded on purpose. A GitHub step summary caps at 1 MiB and a PR
comment at 65,536 characters, and a scan of a large monorepo can exceed both —
so the table and the detail blocks are capped independently and the renderer says
exactly how many findings it left out rather than silently truncating.
"""

from __future__ import annotations

import html
import os
import re
from typing import Optional

from pqcscan.scanner.base import RULES, Finding
from pqcscan.scanner.engine import ScanResult

#: Default caps. Roughly 10x under GitHub's PR-comment limit for a typical scan.
DEFAULT_TABLE_LIMIT = 100
DEFAULT_DETAIL_LIMIT = 20

_SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}

_LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rs": "rust",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
}


def _escape_cell(value: str) -> str:
    """Escape the characters that would break a Markdown table cell."""
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


_BACKTICK_RUN_RE = re.compile(r"`+")


def _code_fence(content: str) -> str:
    """A fence long enough to contain *content*.

    Source snippets are arbitrary text and can legally contain a run of
    backticks (``hashlib.md5(b"```")`` is valid Python). A fixed three-backtick
    fence would be closed by that run, spilling the snippet — and everything
    after it — into the surrounding document. CommonMark closes a fence only
    with a run at least as long, so the fence is sized to beat the content.
    """
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN_RE.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def _rel(path: str, result: ScanResult) -> str:
    for base in (result.root_path, os.getcwd()):
        if not base:
            continue
        try:
            candidate = os.path.relpath(path, base)
        except ValueError:  # different drive on Windows
            continue
        if not candidate.startswith(".."):
            return candidate.replace(os.sep, "/")
    return path.replace(os.sep, "/")


def _fence_language(path: str) -> str:
    _, _, suffix = path.rpartition(".")
    return _LANGUAGE_BY_SUFFIX.get(f".{suffix}", "")


def _counts_table(result: ScanResult) -> list[str]:
    counts = result.counts_by_severity()
    return [
        "| Critical | High | Medium | Low | Total |",
        "| ---: | ---: | ---: | ---: | ---: |",
        "| {critical} | {high} | {medium} | {low} | **{total}** |".format(
            **counts, total=result.total
        ),
    ]


def _meta_line(result: ScanResult) -> str:
    parts = [
        f"{result.files_scanned} file(s) scanned",
        f"{result.duration_seconds:.2f}s",
    ]
    if result.suppressed:
        parts.append(f"{len(result.suppressed)} suppressed inline")
    if result.baselined:
        parts.append(f"{len(result.baselined)} accepted by baseline")
    return "_" + " · ".join(parts) + "_"


def _finding_row(finding: Finding, result: ScanResult) -> str:
    rule = RULES.get(finding.rule_id)
    icon = _SEVERITY_ICON.get(finding.severity, "⚪")
    location = f"{_rel(finding.file_path, result)}:{finding.line_number}"
    return (
        f"| {icon} {finding.severity} "
        f"| `{finding.rule_id}` "
        f"| {_escape_cell(rule.name if rule else finding.rule_id)} "
        f"| `{_escape_cell(location)}` "
        f"| {_escape_cell(finding.algorithm)} |"
    )


def _detail_block(finding: Finding, result: ScanResult) -> list[str]:
    rule = RULES.get(finding.rule_id)
    title = rule.name if rule else finding.rule_id
    location = f"{_rel(finding.file_path, result)}:{finding.line_number}"
    # The summary is raw HTML, so its interpolated values must be escaped.
    lines = [
        "<details>",
        f"<summary><code>{html.escape(finding.rule_id)}</code> · {html.escape(title)} — "
        f"<code>{html.escape(location)}</code></summary>",
        "",
    ]
    snippet = (finding.code_snippet or "").strip()
    if snippet:
        fence = _code_fence(snippet)
        lines += [f"{fence}{_fence_language(finding.file_path)}", snippet, fence, ""]
    lines += [finding.description, ""]
    migration = finding.migration_suggestion
    if migration:
        lines += [
            f"**Migrate to:** {migration.recommended_algorithm}  ",
            f"**Standard:** {migration.nist_standard}  ",
            f"**Docs:** {migration.docs_url}",
            "",
        ]
    if finding.context_hint:
        lines += [f"> {finding.context_hint}", ""]
    lines += ["</details>", ""]
    return lines


def to_markdown(
    result: ScanResult,
    *,
    title: str = "pqc-scan — Post-Quantum Cryptography scan",
    table_limit: int = DEFAULT_TABLE_LIMIT,
    detail_limit: int = DEFAULT_DETAIL_LIMIT,
    footer: Optional[str] = None,
) -> str:
    """Render *result* as Markdown. ``0`` for either limit means "no cap"."""
    lines: list[str] = [f"## 🔐 {title}", ""]

    if not result.findings:
        lines.append("✅ **No quantum-vulnerable cryptography detected.**")
        lines += ["", _meta_line(result), ""]
        if footer:
            lines += [footer, ""]
        return "\n".join(lines)

    lines += _counts_table(result)
    lines += ["", _meta_line(result), "", "### Findings", ""]
    lines += [
        "| Severity | Rule | Name | Location | Algorithm |",
        "| --- | --- | --- | --- | --- |",
    ]

    shown = result.findings if not table_limit else result.findings[:table_limit]
    lines += [_finding_row(f, result) for f in shown]
    hidden = result.total - len(shown)
    if hidden > 0:
        lines.append(f"| … | | _{hidden} more finding(s) not shown_ | | |")
    lines.append("")

    detailed = shown if not detail_limit else shown[:detail_limit]
    if detailed:
        lines += ["### Migration guidance", ""]
        for finding in detailed:
            lines += _detail_block(finding, result)
        remaining = result.total - len(detailed)
        if remaining > 0:
            lines += [
                f"_Guidance shown for the {len(detailed)} most severe finding(s); "
                f"{remaining} more in the full report._",
                "",
            ]

    if result.errors:
        lines += ["### Scan warnings", ""]
        lines += [f"- {error}" for error in result.errors[:10]]
        if len(result.errors) > 10:
            lines.append(f"- _… and {len(result.errors) - 10} more_")
        lines.append("")

    if footer:
        lines += [footer, ""]
    return "\n".join(lines)
