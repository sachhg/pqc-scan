"""pqc-scan command-line interface (Typer).

Commands:
  scan [PATH]   scan a path and emit console / SARIF / CBOM / JSON
  report        run a scan over a path and write a report file (CBOM/SARIF/JSON)
  baseline      snapshot current findings so CI gates on new ones only
  init          write a starter .pqcscan.yml
  rules         list every detection rule
  explain       show one rule in full, with its migration code example
"""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from pqcscan import __version__
from pqcscan.baseline import DEFAULT_BASELINE_NAME, Baseline, BaselineError
from pqcscan.config import ConfigError, PqcConfig
from pqcscan.output import cbom as cbom_out
from pqcscan.output import json_output
from pqcscan.output import markdown as markdown_out
from pqcscan.output import sarif as sarif_out
from pqcscan.output.console import GROUP_BY_CHOICES, ConsoleReporter
from pqcscan.scanner.base import RULES, all_rules, severity_rank
from pqcscan.scanner.engine import ScanResult, timed_scan

app = typer.Typer(
    name="pqc-scan",
    help="Developer-native scanner for quantum-vulnerable cryptography.",
    no_args_is_help=True,
    add_completion=False,
)

_VALID_SCAN_FORMATS = ("console", "sarif", "cbom", "json", "markdown")
_VALID_REPORT_FORMATS = ("cbom", "sarif", "json", "markdown")
_VALID_SEVERITIES = ("critical", "high", "medium", "low")

_err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pqc-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """pqc-scan: find quantum-vulnerable cryptography before quantum computers do."""


def _require_config_exists(config: Optional[str]) -> None:
    """Error out when an explicit --config path does not exist (instead of
    silently falling back to defaults on a typo)."""
    if config and not Path(config).is_file():
        _err_console.print(f"[red]Config file not found: {config}[/red]")
        raise typer.Exit(2)


def _require_path_exists(path: str) -> None:
    """Error out when the scan target does not exist — a silent '0 files
    scanned' on a typo'd path reads like a clean scan."""
    if not Path(path).exists():
        _err_console.print(f"[red]Path does not exist: {path}[/red]")
        raise typer.Exit(2)


def _load_config(config: Optional[str], start_dir: str) -> PqcConfig:
    """Load config, turning a malformed explicit config into exit code 2 and
    surfacing non-fatal warnings on stderr."""
    try:
        cfg = PqcConfig.load(explicit_path=config, start_dir=start_dir)
    except ConfigError as exc:
        _err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)
    if cfg.load_warning:
        _err_console.print(f"[yellow]{cfg.load_warning}[/yellow]")
    return cfg


def _validate_choice(value: str, choices: tuple[str, ...], label: str) -> str:
    value = value.lower()
    if value not in choices:
        _err_console.print(
            f"[red]Invalid {label} '{value}'. Choose one of: {', '.join(choices)}.[/red]"
        )
        raise typer.Exit(2)
    return value


def _resolve_baseline(cfg: PqcConfig, baseline: Optional[str], no_baseline: bool) -> None:
    """Fold the --baseline / --no-baseline flags into *cfg* in place.

    An explicitly requested baseline that does not exist is an error: silently
    treating every finding as new would turn a green build red for the wrong
    reason (and vice versa once someone "fixes" it by deleting the file).
    """
    if no_baseline:
        cfg.baseline_path = None
        return
    if baseline is None:
        return
    if not Path(baseline).is_file():
        _err_console.print(f"[red]Baseline file not found: {baseline}[/red]")
        raise typer.Exit(2)
    cfg.baseline_path = baseline


def _load_baseline_or_exit(path: str | Path) -> Baseline:
    try:
        return Baseline.load(path)
    except BaselineError as exc:
        _err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)


def _render_output(result: ScanResult, fmt: str, base_path: str) -> str:
    if fmt == "sarif":
        return sarif_out.to_sarif_json(result, base_path=base_path)
    if fmt == "cbom":
        return cbom_out.to_cbom_json(result)
    if fmt == "json":
        return json_output.to_json(result)
    if fmt == "markdown":
        return markdown_out.to_markdown(result)
    raise ValueError(fmt)


@app.command()
def scan(
    path: str = typer.Argument(".", help="File or directory to scan."),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output format: console (default), sarif, cbom, json, markdown.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f", help="Write output to this file instead of stdout.",
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity to report: critical, high, medium, low.",
    ),
    exclude: List[str] = typer.Option(
        [], "--exclude", help="Glob pattern to exclude (repeatable).",
    ),
    changed_only: bool = typer.Option(
        False, "--changed-only", help="Only scan files changed in the current git diff.",
    ),
    config: Optional[str] = typer.Option(
        None, "--config", help="Path to a .pqcscan.yml config file.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output."),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings",
        help="Exit with code 1 if any findings are reported (for CI gating).",
    ),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit with code 1 only when a finding is at least this severe "
        "(critical, high, medium, low). Report everything else without failing.",
    ),
    limit: int = typer.Option(
        0, "--limit", help="Show at most N findings in console output (0 = all).",
    ),
    summary: bool = typer.Option(
        False, "--summary",
        help="Console output: only totals and a per-file breakdown, no details.",
    ),
    group_by: str = typer.Option(
        "severity", "--group-by",
        help="Console grouping: severity (default) or file.",
    ),
    no_suppress: bool = typer.Option(
        False, "--no-suppress",
        help="Ignore inline 'pqc-scan: ignore' directives and report every finding.",
    ),
    show_suppressed: bool = typer.Option(
        False, "--show-suppressed",
        help="Console output: also list findings waived by an inline ignore directive.",
    ),
    baseline: Optional[str] = typer.Option(
        None, "--baseline",
        help="Baseline file of accepted findings; report only what is new.",
    ),
    no_baseline: bool = typer.Option(
        False, "--no-baseline",
        help="Ignore any baseline configured in .pqcscan.yml.",
    ),
) -> None:
    """Scan PATH for quantum-vulnerable cryptography."""
    _require_config_exists(config)
    _require_path_exists(path)
    group_by = _validate_choice(group_by, GROUP_BY_CHOICES, "group-by")
    # Resolve the scan target to an absolute path up front so discovery is
    # independent of the process working directory (and can never resolve
    # relative to the installed package). os.walk on an absolute root is
    # equivalent to a relative one but unambiguous.
    scan_root = str(Path(path).resolve())

    cfg = _load_config(config, scan_root)
    if severity is not None:
        cfg.severity_threshold = _validate_choice(severity, _VALID_SEVERITIES, "severity")
    if no_suppress:
        cfg.honor_suppressions = False
    if fail_on is not None:
        fail_on = _validate_choice(fail_on, _VALID_SEVERITIES, "fail-on severity")
    _resolve_baseline(cfg, baseline, no_baseline)

    # Explicit --output wins; otherwise fall back to the config's default format.
    chosen = output or (cfg.default_format if cfg.default_format in _VALID_SCAN_FORMATS else "console")
    fmt = _validate_choice(chosen, _VALID_SCAN_FORMATS, "output format")

    if changed_only:
        from pqcscan.utils.git import is_git_repo

        if not is_git_repo(scan_root):
            _err_console.print(
                "[yellow]--changed-only: not inside a git repository; "
                "no files will be scanned.[/yellow]"
            )

    base_path = os.getcwd()
    try:
        result = timed_scan(
            [scan_root],
            cfg,
            changed_only=changed_only,
            repo_root=scan_root if Path(scan_root).is_dir() else ".",
            extra_excludes=list(exclude),
        )
    except BaselineError as exc:
        _err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)

    if fmt == "console":
        render_opts = dict(
            limit=limit,
            summary_only=summary,
            group_by=group_by,
            show_suppressed=show_suppressed,
        )
        if output_file:
            # Render into a recording console whose output is discarded (StringIO),
            # then persist only the captured text — otherwise rich would ALSO emit
            # the full report to stdout.
            rec = Console(record=True, no_color=True, width=100, file=io.StringIO())
            ConsoleReporter(rec).report(result, **render_opts)
            Path(output_file).write_text(rec.export_text(), encoding="utf-8")
            _err_console.print(f"[green]Wrote console report to {output_file}[/green]")
        else:
            ConsoleReporter(no_color=no_color).report(result, **render_opts)
    else:
        rendered = _render_output(result, fmt, base_path)
        if output_file:
            Path(output_file).write_text(rendered, encoding="utf-8")
            _err_console.print(
                f"[green]Wrote {fmt.upper()} output to {output_file}[/green] "
                f"({result.total} finding(s), {result.files_scanned} file(s) scanned)."
            )
        else:
            typer.echo(rendered)

    # --fail-on gates on severity; --fail-on-findings gates on any reported
    # finding. Reporting at a low threshold while failing only on high findings
    # is the normal CI shape, so the two compose rather than conflict.
    if fail_on is not None:
        threshold = severity_rank(fail_on)
        if any(severity_rank(f.severity) >= threshold for f in result.findings):
            raise typer.Exit(1)
    if fail_on_findings and result.findings:
        raise typer.Exit(1)


@app.command()
def report(
    path: str = typer.Argument(".", help="File or directory to scan."),
    format: str = typer.Option(
        "cbom", "--format", help="Report format: cbom, sarif, json, markdown.",
    ),
    output_file: str = typer.Option(
        ..., "--output-file", help="File to write the report to (required).",
    ),
    config: Optional[str] = typer.Option(None, "--config", help="Path to a .pqcscan.yml file."),
) -> None:
    """Scan PATH and write a CBOM / SARIF / JSON / Markdown report to a file."""
    fmt = _validate_choice(format, _VALID_REPORT_FORMATS, "report format")
    _require_config_exists(config)
    _require_path_exists(path)
    scan_root = str(Path(path).resolve())
    cfg = _load_config(config, scan_root)
    result = timed_scan([scan_root], cfg)
    rendered = _render_output(result, fmt, os.getcwd())
    Path(output_file).write_text(rendered, encoding="utf-8")
    _err_console.print(
        f"[green]Wrote {fmt.upper()} report to {output_file}[/green] "
        f"({result.total} finding(s) across {result.files_scanned} file(s))."
    )


@app.command()
def baseline(
    path: str = typer.Argument(".", help="File or directory to scan."),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", "-f",
        help=f"Baseline file to write (default: {DEFAULT_BASELINE_NAME} in PATH).",
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Minimum severity to record in the baseline.",
    ),
    exclude: List[str] = typer.Option(
        [], "--exclude", help="Glob pattern to exclude (repeatable).",
    ),
    config: Optional[str] = typer.Option(
        None, "--config", help="Path to a .pqcscan.yml config file.",
    ),
) -> None:
    """Snapshot the current findings so later scans report only new ones.

    Commit the generated file; then run `pqc-scan scan . --baseline <file>
    --fail-on-findings` in CI to gate on newly introduced crypto while the
    existing debt stays visible but non-blocking.
    """
    _require_config_exists(config)
    _require_path_exists(path)
    scan_root = str(Path(path).resolve())
    cfg = _load_config(config, scan_root)
    if severity is not None:
        cfg.severity_threshold = _validate_choice(severity, _VALID_SEVERITIES, "severity")
    # A baseline records the raw state of the tree: an existing baseline must not
    # filter what the new one captures, or regenerating would empty it out.
    cfg.baseline_path = None

    target = Path(output_file) if output_file else Path(path) / DEFAULT_BASELINE_NAME
    previous = _load_baseline_or_exit(target) if target.is_file() else None

    result = timed_scan([scan_root], cfg, extra_excludes=list(exclude))
    # Inline-suppressed findings are already waived at the source; recording them
    # again in the baseline would double-count the same acceptance.
    snapshot = Baseline.from_findings(
        result.findings, base_dir=str(target.resolve().parent)
    )
    snapshot.write(target)

    _err_console.print(
        f"[green]Wrote baseline to {target}[/green] "
        f"({snapshot.total} finding(s) across {result.files_scanned} file(s) scanned)."
    )
    if previous is not None:
        added, removed = snapshot.diff(previous)
        _err_console.print(
            f"[dim]Since the previous baseline: {added} new, {removed} resolved.[/dim]"
        )
    if result.suppressed:
        _err_console.print(
            f"[dim]{len(result.suppressed)} inline-suppressed finding(s) were not "
            "recorded (they are already waived in-source).[/dim]"
        )


_DEFAULT_CONFIG_TEMPLATE = """\
# .pqcscan.yml — configuration for pqc-scan
# Docs: https://github.com/pqc-scan/pqc-scan

exclude:
  - "**/tests/**"
  - "**/*.test.py"
  - "**/vendor/**"
  - "**/node_modules/**"

# Minimum severity to report: critical | high | medium | low
severity_threshold: medium

languages:
  - python
  - javascript
  - java
  - go
  - rust

scan_configs: true        # Scan YAML/JSON/TOML/.conf config files
scan_dependencies: true   # Scan dependency manifests (requirements.txt, package.json, ...)
scan_certificates: true   # Scan PEM/OpenSSH keys and X.509 certificates (PQC015/PQC016)

# Honor inline "pqc-scan: ignore" directives (set false for an audit run).
suppressions: true

# Path to a baseline of accepted findings, relative to this file. Generate it
# with `pqc-scan baseline`; later scans then report only NEW findings.
# baseline: .pqcscan-baseline.json

rules:
  disable: []             # e.g. [PQC010] to silence a specific rule

output:
  default_format: console
  cbom_path: cbom.json
"""


@app.command()
def init(
    path: str = typer.Argument(".", help="Directory to create the config in."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config."),
) -> None:
    """Create a starter .pqcscan.yml in the current directory."""
    target = Path(path) / ".pqcscan.yml"
    if target.exists() and not force:
        _err_console.print(
            f"[yellow]{target} already exists. Use --force to overwrite.[/yellow]"
        )
        raise typer.Exit(1)
    target.write_text(_DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    _err_console.print(f"[green]Created {target}[/green]")


@app.command()
def rules(
    json_output_flag: bool = typer.Option(
        False, "--json", help="Emit the rule registry as JSON instead of a table.",
    ),
) -> None:
    """List all detection rules with their IDs and descriptions."""
    if json_output_flag:
        import json as _json

        typer.echo(
            _json.dumps(
                [
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "default_severity": rule.default_severity,
                        "category": rule.category,
                        "primitive": rule.primitive,
                        "algorithm_family": rule.algorithm_family,
                        "help_uri": rule.help_uri,
                    }
                    for rule in all_rules()
                ],
                indent=2,
            )
        )
        return
    console = Console()
    table = Table(title="pqc-scan detection rules", title_style="bold", show_lines=False)
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Category", style="dim", no_wrap=True)
    table.add_column("Description")

    sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
    for rule in all_rules():
        table.add_row(
            rule.rule_id,
            rule.name,
            f"[{sev_color.get(rule.default_severity, 'white')}]{rule.default_severity}[/]",
            rule.category,
            rule.description,
        )
    console.print(table)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule to explain, e.g. PQC001."),
    json_output_flag: bool = typer.Option(
        False, "--json", help="Emit the rule and its migration guidance as JSON.",
    ),
) -> None:
    """Show one rule in full, including its before/after migration example.

    Console and SARIF output have to stay terse, so the code example attached to
    every finding is never shown in full there. This is where to read it.
    """
    from pqcscan.migration.suggestions import get_suggestion

    key = rule_id.strip().upper()
    rule = RULES.get(key)
    if rule is None:
        known = ", ".join(sorted(RULES))
        _err_console.print(
            f"[red]Unknown rule '{rule_id}'.[/red] Known rules: {known}"
        )
        raise typer.Exit(2)
    suggestion = get_suggestion(rule.algorithm_family)

    if json_output_flag:
        import json as _json

        typer.echo(
            _json.dumps(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "default_severity": rule.default_severity,
                    "category": rule.category,
                    "primitive": rule.primitive,
                    "algorithm_family": rule.algorithm_family,
                    "help_uri": rule.help_uri,
                    "migration": suggestion.to_dict(),
                },
                indent=2,
            )
        )
        return

    console = Console()
    sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
    console.print()
    console.print(
        f"[bold cyan]{rule.rule_id}[/]  [bold]{rule.name}[/]  "
        f"[{sev_color.get(rule.default_severity, 'white')}]{rule.default_severity}[/]"
        f"  [dim]({rule.category} · {rule.primitive})[/]"
    )
    console.print()
    console.print(rule.description)
    console.print()
    console.print("[bold green]Migrate to[/]")
    console.print(f"  {suggestion.recommended_algorithm}")
    console.print(f"  [dim]{suggestion.nist_standard}[/]")
    console.print()
    console.print("[bold green]Library[/]")
    console.print(f"  {suggestion.recommended_library}")
    console.print()
    console.print("[bold green]Why and how[/]")
    console.print(f"  {suggestion.migration_description}")
    console.print()
    console.print("[bold green]Example[/]")
    for line in suggestion.code_example.splitlines():
        console.print(f"  [dim]{line}[/]")
    console.print()
    console.print(f"[blue underline]{suggestion.docs_url}[/]")
    console.print()


if __name__ == "__main__":  # pragma: no cover
    app()
