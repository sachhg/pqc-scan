"""Tests for inline `pqc-scan: ignore` suppression directives."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqcscan.cli import app
from pqcscan.config import PqcConfig
from pqcscan.output import sarif as sarif_out
from pqcscan.scanner.engine import run_scan
from pqcscan.scanner.suppressions import parse_suppressions

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _scan(path: Path, **kwargs):
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    for key, value in kwargs.items():
        setattr(cfg, key, value)
    return run_scan([path], cfg)


# --------------------------------------------------------------------------- #
# Directive parsing
# --------------------------------------------------------------------------- #


def test_parse_same_line_directive_with_rule_list_and_reason():
    supp = parse_suppressions("x = rsa.gen()  # pqc-scan: ignore[PQC001] -- why not")
    directive = supp.match("PQC001", 1)
    assert directive is not None
    assert directive.kind == "ignore"
    assert directive.reason == "why not"
    # Scoped directives must not leak onto other rules.
    assert supp.match("PQC003", 1) is None


def test_bare_directive_covers_every_rule():
    supp = parse_suppressions("x = 1  # pqc-scan: ignore")
    assert supp.match("PQC001", 1) is not None
    assert supp.match("PQC014", 1) is not None
    # ...but only on its own line.
    assert supp.match("PQC001", 2) is None


def test_ignore_next_line_applies_to_the_following_line():
    supp = parse_suppressions("# pqc-scan: ignore-next-line[PQC004]\nkey = ec.gen()")
    assert supp.match("PQC004", 2) is not None
    assert supp.match("PQC004", 1) is None


def test_ignore_file_applies_everywhere():
    supp = parse_suppressions("// pqc-scan: ignore-file[PQC010]\nline2\nline3")
    assert supp.match("PQC010", 999) is not None
    assert supp.match("PQC001", 999) is None


def test_comment_syntax_and_spelling_variants_all_parse():
    variants = [
        "// pqc-scan: ignore",
        "# pqcscan:ignore",
        "/* pqc_scan : ignore */",
        "<!-- PQC-SCAN: IGNORE -->",
    ]
    for line in variants:
        assert parse_suppressions(line).match("PQC001", 1) is not None, line


def test_block_comment_terminator_is_not_part_of_the_reason():
    supp = parse_suppressions("/* pqc-scan: ignore -- vendored code */")
    assert supp.match("PQC001", 1).reason == "vendored code"


def test_file_without_marker_parses_to_empty():
    assert not parse_suppressions("just some ordinary source\nwith no directives\n")


# --------------------------------------------------------------------------- #
# Engine integration
# --------------------------------------------------------------------------- #


def test_suppressed_findings_are_partitioned_out_of_findings():
    result = _scan(FIXTURES / "suppressed_rsa.py")
    assert result.findings == []
    assert {f.rule_id for f in result.suppressed} == {
        "PQC001", "PQC004", "PQC008", "PQC009"
    }
    assert all(f.suppressed for f in result.suppressed)
    assert all(f.suppression_reason for f in result.suppressed)


def test_file_level_directive_suppresses_the_whole_file():
    result = _scan(FIXTURES / "suppressed_file.py")
    assert result.findings == []
    assert result.suppressed_count >= 1


def test_honor_suppressions_false_reports_everything():
    result = _scan(FIXTURES / "suppressed_rsa.py", honor_suppressions=False)
    assert result.suppressed == []
    assert {f.rule_id for f in result.findings} == {
        "PQC001", "PQC004", "PQC008", "PQC009"
    }


def test_directives_do_not_suppress_unrelated_files():
    result = _scan(FIXTURES / "vulnerable_rsa.py")
    assert result.suppressed == []
    assert result.findings


def test_suppression_runs_after_the_severity_threshold():
    """A suppressed finding below the threshold must not inflate the count."""
    cfg = PqcConfig.default()
    cfg.severity_threshold = "critical"
    result = run_scan([FIXTURES / "suppressed_rsa.py"], cfg)
    # PQC009 (medium) is filtered by the threshold, so only the three criticals
    # can be reported as suppressed.
    assert {f.rule_id for f in result.suppressed} == {"PQC001", "PQC004", "PQC008"}


# --------------------------------------------------------------------------- #
# Output integration
# --------------------------------------------------------------------------- #


def test_sarif_emits_suppressed_results_with_a_suppressions_array():
    result = _scan(FIXTURES / "suppressed_rsa.py")
    doc = sarif_out.to_sarif(result, base_path=str(FIXTURES))
    results = doc["runs"][0]["results"]
    assert results, "suppressed findings must still appear in SARIF"
    for entry in results:
        assert entry["suppressions"][0]["kind"] == "inSource"
        assert entry["suppressions"][0]["status"] == "accepted"
    justifications = [r["suppressions"][0].get("justification", "") for r in results]
    assert any("JIRA-42" in j for j in justifications)


def test_unsuppressed_results_have_no_suppressions_key():
    result = _scan(FIXTURES / "vulnerable_rsa.py")
    doc = sarif_out.to_sarif(result, base_path=str(FIXTURES))
    assert all("suppressions" not in r for r in doc["runs"][0]["results"])


def test_cbom_still_inventories_suppressed_algorithms():
    from pqcscan.output import cbom as cbom_out

    result = _scan(FIXTURES / "suppressed_rsa.py")
    doc = cbom_out.to_cbom(result, timestamp="2026-01-01T00:00:00Z")
    names = {c["name"] for c in doc["components"]}
    assert "RSA-2048" in names


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_json_reports_suppressed_separately():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "suppressed_rsa.py"), "-o", "json", "-s", "low"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["summary"]["total"] == 0
    assert data["summary"]["suppressed"] == 4
    assert len(data["suppressed_findings"]) == 4
    assert data["suppressed_findings"][0]["suppressed"] is True


def test_cli_no_suppress_flag_reports_everything():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "suppressed_rsa.py"), "-o", "json", "-s", "low",
         "--no-suppress"],
    )
    data = json.loads(result.stdout)
    assert data["summary"]["total"] == 4
    assert data["summary"]["suppressed"] == 0


def test_cli_fail_on_findings_ignores_suppressed():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "suppressed_rsa.py"), "-s", "low",
         "--fail-on-findings", "--no-color"],
    )
    assert result.exit_code == 0


def test_cli_show_suppressed_lists_them_with_reasons():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "suppressed_rsa.py"), "-s", "low",
         "--show-suppressed", "--no-color"],
    )
    assert result.exit_code == 0
    assert "Suppressed (4)" in result.stdout
    assert "JIRA-42" in result.stdout


def test_cli_hides_suppressed_list_by_default():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "suppressed_rsa.py"), "-s", "low", "--no-color"]
    )
    assert "JIRA-42" not in result.stdout
    assert "+4 suppressed" in result.stdout.replace("\n", "")


def test_config_can_disable_suppressions(tmp_path):
    cfg = tmp_path / ".pqcscan.yml"
    cfg.write_text("suppressions: false\nseverity_threshold: low\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "suppressed_rsa.py"), "-o", "json",
         "--config", str(cfg)],
    )
    data = json.loads(result.stdout)
    assert data["summary"]["total"] == 4
