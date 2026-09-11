"""Tests for `pqc-scan explain`, `rules --json` and `scan --fail-on`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqcscan.cli import app
from pqcscan.scanner.base import RULES

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "python"


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #


def test_explain_shows_the_full_migration_example():
    result = runner.invoke(app, ["explain", "PQC001"])
    assert result.exit_code == 0
    assert "RSA Key Generation" in result.stdout
    assert "ML-KEM-768" in result.stdout
    # The code example is the thing console/SARIF output cannot show.
    assert "Example" in result.stdout
    assert "oqs" in result.stdout


def test_explain_is_case_insensitive():
    assert runner.invoke(app, ["explain", "pqc009"]).exit_code == 0


def test_explain_unknown_rule_exits_two_and_lists_the_valid_ids():
    result = runner.invoke(app, ["explain", "PQC999"])
    assert result.exit_code == 2
    # Errors go to stderr so JSON/report output on stdout stays pipeable.
    assert "PQC001" in (result.stderr or result.output)


def test_explain_json_carries_rule_and_migration():
    result = runner.invoke(app, ["explain", "PQC015", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["rule_id"] == "PQC015"
    assert data["algorithm_family"] == "key-material"
    assert data["migration"]["code_example"]
    assert data["migration"]["docs_url"].startswith("https://")


def test_every_registered_rule_can_be_explained():
    for rule_id in RULES:
        result = runner.invoke(app, ["explain", rule_id, "--json"])
        assert result.exit_code == 0, rule_id
        assert json.loads(result.stdout)["migration"]["recommended_algorithm"]


# --------------------------------------------------------------------------- #
# rules --json
# --------------------------------------------------------------------------- #


def test_rules_json_matches_the_registry():
    result = runner.invoke(app, ["rules", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == len(RULES)
    assert {r["rule_id"] for r in data} == set(RULES)
    assert all(r["description"] and r["category"] for r in data)


def test_rules_table_still_works():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "PQC016" in result.stdout


# --------------------------------------------------------------------------- #
# --fail-on
# --------------------------------------------------------------------------- #


def test_fail_on_critical_gates_on_critical_findings():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "-s", "low",
              "--fail-on", "critical", "-o", "json"],
    )
    assert result.exit_code == 1


def test_fail_on_ignores_findings_below_the_threshold(tmp_path):
    """Report everything, block only on the worst — the normal CI shape."""
    src = tmp_path / "hash.py"
    src.write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    reported = runner.invoke(app, ["scan", str(src), "-s", "low", "-o", "json"])
    assert json.loads(reported.stdout)["summary"]["by_severity"]["medium"] == 1

    gated = runner.invoke(
        app, ["scan", str(src), "-s", "low", "--fail-on", "critical", "-o", "json"]
    )
    assert gated.exit_code == 0, "a medium finding must not trip a critical gate"


def test_fail_on_accepts_the_lowest_severity():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "-s", "low",
              "--fail-on", "low", "-o", "json"],
    )
    assert result.exit_code == 1


def test_fail_on_rejects_an_unknown_severity():
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable_rsa.py"), "--fail-on", "urgent"]
    )
    assert result.exit_code == 2


def test_clean_scan_passes_every_gate():
    for extra in (["--fail-on", "low"], ["--fail-on-findings"]):
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "safe_code.py"), "-s", "low", *extra]
        )
        assert result.exit_code == 0
