"""Robustness: malformed inputs, git integration, grammar failures, self-scan."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from pqcscan.config import PqcConfig
from pqcscan.scanner.engine import run_scan

SRC_ROOT = Path(__file__).parent.parent / "src" / "pqcscan"


# --------------------------------------------------------------------------- #
# Malformed input files must never crash a scan
# --------------------------------------------------------------------------- #


def test_binary_file_with_py_extension(tmp_path):
    bad = tmp_path / "blob.py"
    bad.write_bytes(b"\x00\x01\x02\xff" * 64)
    result = run_scan([str(bad)], PqcConfig.default())
    assert result.findings == []
    # explicitly passed file: scanned (or skipped) without raising


def test_non_utf8_source_file(tmp_path):
    bad = tmp_path / "latin.py"
    bad.write_bytes("import hashlib\nh = hashlib.md5(b'\xe9\xe8')\n".encode("latin-1"))
    result = run_scan([str(bad)], PqcConfig.default())
    assert result.errors == []
    assert any(f.rule_id == "PQC010" for f in result.findings)


def test_truncated_source_recovers(tmp_path):
    bad = tmp_path / "broken.py"
    bad.write_text(
        "import hashlib\n"
        "h = hashlib.sha1(b'x')\n"
        "def unfinished(:\n",  # syntax error
        encoding="utf-8",
    )
    result = run_scan([str(bad)], PqcConfig.default())
    # tree-sitter error recovery still surfaces the finding above the error
    assert any(f.rule_id == "PQC009" for f in result.findings)
    assert result.errors == []


def test_unreadable_file_is_recorded_not_crashed(tmp_path):
    target = tmp_path / "locked.py"
    target.write_text("import hashlib\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        result = run_scan([str(target)], PqcConfig.default())
        assert result.findings == []
        assert result.errors, "read failure must be recorded in result.errors"
    finally:
        target.chmod(0o644)


def test_missing_grammar_is_surfaced_not_silent(monkeypatch, tmp_path):
    """A grammar that fails to import must be reported in result.errors, not
    silently produce zero findings for that language."""
    from pqcscan.scanner import ast_scanner as mod

    monkeypatch.setattr(mod, "_build_parser", lambda name: None)
    target = tmp_path / "x.py"
    target.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    result = run_scan([str(target)], PqcConfig.default())
    assert result.findings == []
    assert any("grammar" in e for e in result.errors)


# --------------------------------------------------------------------------- #
# --changed-only git integration
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_changed_only_scans_only_the_diff(tmp_path):
    def git(*args):
        subprocess.run(
            ["git", *args], cwd=tmp_path, check=True, capture_output=True,
            env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                 "HOME": str(tmp_path), "PATH": __import__("os").environ["PATH"]},
        )

    vulnerable = "import hashlib\nhashlib.md5(b'x')\n"
    git("init", "-q")
    committed = tmp_path / "committed.py"
    committed.write_text(vulnerable, encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "init")

    # A NEW untracked vulnerable file: the only thing --changed-only should see.
    fresh = tmp_path / "fresh.py"
    fresh.write_text(vulnerable, encoding="utf-8")

    result = run_scan(
        [str(tmp_path)], PqcConfig.default(),
        changed_only=True, repo_root=str(tmp_path),
    )
    files = {Path(f.file_path).name for f in result.findings}
    assert files == {"fresh.py"}


# --------------------------------------------------------------------------- #
# The tool must be clean when scanned with itself
# --------------------------------------------------------------------------- #


def test_self_scan_is_clean():
    """pqc-scan's own source must produce ZERO findings (dogfood guard).

    The rule tables mention RS256/SHA-1/etc. constantly — none of that may
    trip the analyzers.
    """
    result = run_scan([str(SRC_ROOT)], PqcConfig.default())
    assert result.findings == [], [
        f"{f.rule_id} {f.algorithm} {f.file_path}:{f.line_number}"
        for f in result.findings
    ]
    assert result.errors == []
