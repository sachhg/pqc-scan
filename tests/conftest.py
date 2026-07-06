"""Shared pytest fixtures / helpers for the pqc-scan test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def rules_at(findings, file_substring: str) -> set[str]:
    return {f.rule_id for f in findings if file_substring in f.file_path}
