"""Whole-project invariants that are easy to break and cheap to check.

These are not detection tests: they guard the promises the README makes about
precision, and the version/changelog bookkeeping a release depends on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pqcscan import __version__
from pqcscan.config import ALL_LANGUAGES, PqcConfig
from pqcscan.migration.suggestions import get_suggestion
from pqcscan.scanner.ast_scanner import _EXT_MAP, available_languages
from pqcscan.scanner.base import RULES, SEVERITY_ORDER
from pqcscan.scanner.engine import _LANG_MODULES, run_scan

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# "Safe code yields zero findings" — the core precision promise
# --------------------------------------------------------------------------- #

SAFE_INPUTS = [
    FIXTURES / "python" / "safe_code.py",
    FIXTURES / "configs" / "safe_config.yml",
    FIXTURES / "rust" / "safe.rs",
    FIXTURES / "dependencies" / "safe",
    FIXTURES / "keys" / "safe",
]


@pytest.mark.parametrize("target", SAFE_INPUTS, ids=lambda p: p.name)
def test_safe_fixtures_yield_zero_findings(target: Path):
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    result = run_scan([target], cfg)
    assert result.findings == [], [f.location for f in result.findings]
    # A safe fixture must be genuinely scanned, not skipped into a false pass.
    assert result.files_scanned > 0
    assert result.errors == []


def test_every_safe_fixture_is_covered_by_this_test():
    """A new `safe_*` fixture must be added to SAFE_INPUTS, not silently ignored."""
    covered = {p.resolve() for p in SAFE_INPUTS}
    for path in FIXTURES.rglob("safe*"):
        resolved = path.resolve()
        if any(resolved == c or c in resolved.parents for c in covered):
            continue
        pytest.fail(f"{path} is not covered by test_safe_fixtures_yield_zero_findings")


# --------------------------------------------------------------------------- #
# Rule registry
# --------------------------------------------------------------------------- #


def test_rule_ids_are_contiguous_and_well_formed():
    ids = sorted(RULES)
    assert ids == [f"PQC{n:03d}" for n in range(1, len(ids) + 1)]


def test_every_rule_is_internally_consistent():
    for rule_id, rule in RULES.items():
        assert rule.rule_id == rule_id
        assert rule.name and rule.description
        assert rule.default_severity in SEVERITY_ORDER
        assert rule.category and rule.primitive and rule.algorithm_family
        assert rule.help_uri.startswith("https://")


def test_every_rule_family_resolves_to_real_migration_guidance():
    """A missing family silently falls back to generic advice — catch that here."""
    for rule in RULES.values():
        suggestion = get_suggestion(rule.algorithm_family)
        assert suggestion.recommended_algorithm
        assert suggestion.code_example
        assert suggestion.docs_url.startswith("https://")
        assert "ML-KEM" in suggestion.recommended_algorithm or \
               "ML-DSA" in suggestion.recommended_algorithm or \
               "SLH-DSA" in suggestion.recommended_algorithm or \
               "SHA-256" in suggestion.recommended_algorithm or \
               "AES" in suggestion.recommended_algorithm or \
               "HS256" in suggestion.recommended_algorithm or \
               "TLS 1.3" in suggestion.recommended_algorithm, rule.rule_id


# --------------------------------------------------------------------------- #
# Language wiring
# --------------------------------------------------------------------------- #


def test_every_configured_language_has_a_module_and_a_grammar():
    assert set(ALL_LANGUAGES) == set(_LANG_MODULES)
    assert set(available_languages()) == set(ALL_LANGUAGES)


def test_every_language_module_satisfies_the_contract():
    for language, module in _LANG_MODULES.items():
        assert module.LANGUAGE == language
        assert module.EXTENSIONS and module.GRAMMAR
        assert callable(module.analyze)
        for extension in module.EXTENSIONS:
            assert _EXT_MAP[extension].module is module


# --------------------------------------------------------------------------- #
# Release bookkeeping
# --------------------------------------------------------------------------- #


def test_version_matches_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert match and match.group(1) == __version__


def test_changelog_documents_the_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{__version__}]" in changelog


def test_readme_documents_every_rule():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for rule_id in RULES:
        assert rule_id in readme, f"{rule_id} is missing from README.md"
