"""Tests for baseline files (accept existing debt, gate on new findings)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pqcscan.baseline import Baseline, BaselineError, fingerprint
from pqcscan.cli import app
from pqcscan.config import PqcConfig
from pqcscan.scanner.engine import run_scan

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "python"
VULN = FIXTURES / "vulnerable_rsa.py"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A scratch tree holding one copy of the RSA fixture."""
    (tmp_path / "keys.py").write_text(VULN.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def _scan(path: Path, baseline_path: str | None = None):
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    cfg.baseline_path = baseline_path
    return run_scan([path], cfg)


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #


def test_fingerprint_is_independent_of_line_number(repo: Path):
    before = _scan(repo).findings
    base = str(repo)
    original = sorted(fingerprint(f, base) for f in before)

    target = repo / "keys.py"
    target.write_text("import os\nimport sys\n\n\n" + target.read_text(), encoding="utf-8")

    after = _scan(repo).findings
    assert sorted(fingerprint(f, base) for f in after) == original
    # ...and the line numbers really did move.
    assert [f.line_number for f in after] != [f.line_number for f in before]


def test_fingerprint_changes_with_the_rule_or_algorithm(repo: Path):
    findings = _scan(repo).findings
    prints = {fingerprint(f, str(repo)) for f in findings}
    assert len(prints) == len(findings), "distinct findings must fingerprint distinctly"


# --------------------------------------------------------------------------- #
# Partitioning
# --------------------------------------------------------------------------- #


def test_baselined_findings_are_not_reported(repo: Path):
    snapshot = Baseline.from_findings(_scan(repo).findings, base_dir=str(repo))
    path = repo / ".pqcscan-baseline.json"
    snapshot.write(path)

    result = _scan(repo, str(path))
    assert result.findings == []
    assert result.baselined_count == snapshot.total
    assert all(f.baselined for f in result.baselined)


def test_new_findings_are_still_reported(repo: Path):
    snapshot = Baseline.from_findings(_scan(repo).findings, base_dir=str(repo))
    path = repo / ".pqcscan-baseline.json"
    snapshot.write(path)

    (repo / "new.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "key = dsa.generate_private_key(key_size=3072)\n",
        encoding="utf-8",
    )
    result = _scan(repo, str(path))
    assert {f.rule_id for f in result.findings} == {"PQC008"}


def test_an_extra_occurrence_of_a_baselined_pattern_counts_as_new(tmp_path: Path):
    """Baseline entries are counted, not just present."""
    src = tmp_path / "hash.py"
    two = "import hashlib\nhashlib.sha1(b'a')\nhashlib.sha1(b'a')\n"
    src.write_text(two, encoding="utf-8")

    path = tmp_path / ".pqcscan-baseline.json"
    Baseline.from_findings(_scan(tmp_path).findings, base_dir=str(tmp_path)).write(path)
    assert _scan(tmp_path, str(path)).findings == []

    src.write_text(two + "hashlib.sha1(b'a')\n", encoding="utf-8")
    result = _scan(tmp_path, str(path))
    assert len(result.findings) == 1
    assert result.baselined_count == 2


def test_baseline_diff_reports_added_and_removed():
    old = Baseline()
    old.entries = {}
    findings = _scan(FIXTURES / "vulnerable_rsa.py").findings
    new = Baseline.from_findings(findings, base_dir=str(FIXTURES))
    added, removed = new.diff(old)
    assert added == len(findings)
    assert removed == 0
    assert old.diff(new) == (0, len(findings))


# --------------------------------------------------------------------------- #
# Loading / errors
# --------------------------------------------------------------------------- #


def test_round_trip_preserves_entries(repo: Path):
    snapshot = Baseline.from_findings(_scan(repo).findings, base_dir=str(repo))
    path = repo / ".pqcscan-baseline.json"
    snapshot.write(path)
    loaded = Baseline.load(path)
    assert loaded.total == snapshot.total
    assert set(loaded.entries) == set(snapshot.entries)


def test_malformed_baseline_raises(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        Baseline.load(bad)

    wrong = tmp_path / "wrong.json"
    wrong.write_text('{"tool": "pqc-scan"}', encoding="utf-8")
    with pytest.raises(BaselineError):
        Baseline.load(wrong)


def test_baseline_entries_are_sorted_for_reviewable_diffs(repo: Path):
    snapshot = Baseline.from_findings(_scan(repo).findings, base_dir=str(repo))
    entries = list(snapshot.to_dict()["entries"].values())
    keys = [(e["rule_id"], e["path"]) for e in entries]
    assert keys == sorted(keys)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_baseline_command_writes_a_file(repo: Path):
    result = runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    assert result.exit_code == 0
    path = repo / ".pqcscan-baseline.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "pqc-scan"
    assert data["total"] > 0


def test_cli_scan_with_baseline_is_clean_then_fails_on_new(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    path = repo / ".pqcscan-baseline.json"

    clean = runner.invoke(
        app, ["scan", str(repo), "-s", "low", "--baseline", str(path),
              "--fail-on-findings", "--no-color"],
    )
    assert clean.exit_code == 0

    (repo / "new.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "key = dsa.generate_private_key(key_size=3072)\n",
        encoding="utf-8",
    )
    dirty = runner.invoke(
        app, ["scan", str(repo), "-s", "low", "--baseline", str(path),
              "--fail-on-findings", "--no-color"],
    )
    assert dirty.exit_code == 1
    assert "PQC008" in dirty.stdout


def test_cli_missing_baseline_is_an_error_not_a_silent_pass(repo: Path):
    result = runner.invoke(
        app, ["scan", str(repo), "--baseline", str(repo / "nope.json")]
    )
    assert result.exit_code == 2


def test_cli_malformed_baseline_exits_two(repo: Path):
    bad = repo / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(repo), "--baseline", str(bad)])
    assert result.exit_code == 2


def test_cli_regenerating_a_baseline_does_not_empty_it(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    path = repo / ".pqcscan-baseline.json"
    first = json.loads(path.read_text(encoding="utf-8"))["total"]
    second_run = runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    assert second_run.exit_code == 0
    second = json.loads(path.read_text(encoding="utf-8"))["total"]
    assert second == first > 0


def test_cli_json_reports_baselined_separately(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    path = repo / ".pqcscan-baseline.json"
    result = runner.invoke(
        app, ["scan", str(repo), "-s", "low", "--baseline", str(path), "-o", "json"]
    )
    data = json.loads(result.stdout)
    assert data["summary"]["total"] == 0
    assert data["summary"]["baselined"] > 0
    assert data["baselined_findings"][0]["baselined"] is True


def test_cli_no_baseline_overrides_the_config(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    (repo / ".pqcscan.yml").write_text(
        "severity_threshold: low\nbaseline: .pqcscan-baseline.json\n", encoding="utf-8"
    )
    configured = runner.invoke(app, ["scan", str(repo), "-o", "json"])
    assert json.loads(configured.stdout)["summary"]["total"] == 0

    overridden = runner.invoke(app, ["scan", str(repo), "-o", "json", "--no-baseline"])
    assert json.loads(overridden.stdout)["summary"]["total"] > 0


def test_cli_sarif_omits_baselined_findings(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    path = repo / ".pqcscan-baseline.json"
    result = runner.invoke(
        app, ["scan", str(repo), "-s", "low", "--baseline", str(path), "-o", "sarif"]
    )
    doc = json.loads(result.stdout)
    assert doc["runs"][0]["results"] == []


def test_cbom_still_inventories_baselined_findings(repo: Path):
    runner.invoke(app, ["baseline", str(repo), "-s", "low"])
    path = repo / ".pqcscan-baseline.json"
    result = runner.invoke(
        app, ["scan", str(repo), "-s", "low", "--baseline", str(path), "-o", "cbom"]
    )
    names = {c["name"] for c in json.loads(result.stdout)["components"]}
    assert "RSA-2048" in names
