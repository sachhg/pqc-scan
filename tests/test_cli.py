"""Tests for the Typer CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqcscan.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "python"


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "pqc-scan" in result.stdout


def test_rules_lists_pqc001():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "PQC001" in result.stdout


def test_scan_json_output_is_valid():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "-o", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    # metadata wrapper: tool identity, version, timestamp, scanned paths
    assert data["tool"] == "pqc-scan"
    assert data["version"]
    assert data["generated_at"]
    assert data["paths"]
    assert data["summary"]["total"] == len(data["findings"])
    findings = data["findings"]
    assert any(f["rule_id"] == "PQC001" for f in findings)
    # every finding carries a migration suggestion
    assert all(f["migration_suggestion"]["recommended_algorithm"] for f in findings)


def test_scan_safe_code_reports_no_findings():
    result = runner.invoke(app, ["scan", str(FIXTURES / "safe_code.py"), "--no-color"])
    assert result.exit_code == 0
    assert "No quantum-vulnerable cryptography detected" in result.stdout


def test_scan_severity_filter():
    crit = runner.invoke(
        app, ["scan", str(FIXTURES), "-o", "json", "-s", "critical"]
    )
    assert crit.exit_code == 0
    findings = json.loads(crit.stdout)["findings"]
    assert findings, "expected at least one critical finding"
    assert all(f["severity"] == "critical" for f in findings)


def test_init_creates_config(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".pqcscan.yml").is_file()


def test_init_refuses_overwrite_without_force(tmp_path):
    (tmp_path / ".pqcscan.yml").write_text("existing")
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 1


def test_scan_fail_on_findings_exit_code():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "vulnerable_rsa.py"), "--fail-on-findings", "-o", "json"],
    )
    assert result.exit_code == 1


def test_sarif_output_to_file(tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "-o", "sarif", "-f", str(out)]
    )
    assert result.exit_code == 0
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"


def test_json_output_to_file(tmp_path):
    out = tmp_path / "out.json"
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "-o", "json", "-f", str(out)]
    )
    assert result.exit_code == 0
    doc = json.loads(out.read_text())
    assert doc["tool"] == "pqc-scan"
    assert doc["findings"]


def test_scan_nonexistent_path_exits_2():
    result = runner.invoke(app, ["scan", "/no/such/path/anywhere"])
    assert result.exit_code == 2


def test_scan_summary_mode():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--summary", "--no-color"])
    assert result.exit_code == 0
    # totals table present, but no per-finding detail markers
    assert "Total findings:" in result.stdout
    assert "Migrate to:" not in result.stdout


def test_scan_group_by_file():
    result = runner.invoke(
        app, ["scan", str(FIXTURES), "--group-by", "file", "--no-color"]
    )
    assert result.exit_code == 0
    assert "finding(s)" in result.stdout  # per-file group headers


def test_scan_group_by_rejects_unknown():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--group-by", "planet"])
    assert result.exit_code == 2


def test_scan_limit_caps_output():
    result = runner.invoke(
        app, ["scan", str(FIXTURES), "--limit", "1", "--no-color"]
    )
    assert result.exit_code == 0
    assert "more finding(s) not shown" in result.stdout


def test_scan_paths_are_relative_in_console(tmp_path):
    """Console output shows paths relative to the scan root, not absolute."""
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "--no-color"]
    )
    assert result.exit_code == 0
    assert str(FIXTURES / "vulnerable_rsa.py") not in result.stdout
    assert "vulnerable_rsa.py:" in result.stdout


def test_explicit_malformed_config_exits_2(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("exclude: [unclosed\n")
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "safe_code.py"), "--config", str(bad)]
    )
    assert result.exit_code == 2


def test_discovered_malformed_config_warns_and_continues(tmp_path):
    (tmp_path / ".pqcscan.yml").write_text("exclude: [unclosed\n")
    target = tmp_path / "clean.py"
    target.write_text("print('hello')\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-color"])
    assert result.exit_code == 0
    assert "malformed config" in result.output
