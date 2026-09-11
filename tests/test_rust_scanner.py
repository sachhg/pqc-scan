"""Tests for the Rust language analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.config import PqcConfig
from pqcscan.languages import rust_rules
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "rust"

pytest.importorskip("tree_sitter_rust")


def _analyze(source: str, name: str = "snippet.rs"):
    import tree_sitter_rust as grammar
    from tree_sitter import Language, Parser

    parser = Parser(Language(grammar.language()))
    raw = source.encode("utf-8")
    return rust_rules.analyze(parser.parse(raw).root_node, source, name)


def _scan(path: Path):
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    return run_scan([path], cfg)


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Module contract
# --------------------------------------------------------------------------- #


def test_module_contract():
    assert rust_rules.LANGUAGE == "rust"
    assert ".rs" in rust_rules.EXTENSIONS
    assert rust_rules.GRAMMAR == "tree_sitter_rust"


def test_rust_is_registered_end_to_end():
    from pqcscan.config import ALL_LANGUAGES
    from pqcscan.scanner.engine import _LANG_MODULES, extensions_for_languages

    assert "rust" in ALL_LANGUAGES
    assert "rust" in _LANG_MODULES
    assert ".rs" in extensions_for_languages(["rust"])


# --------------------------------------------------------------------------- #
# Fixture coverage
# --------------------------------------------------------------------------- #


def test_vulnerable_fixture_covers_every_expected_rule():
    result = _scan(FIXTURES / "vulnerable.rs")
    assert _rules(result.findings) == {
        "PQC001", "PQC002", "PQC003", "PQC004", "PQC005",
        "PQC006", "PQC007", "PQC008", "PQC009", "PQC010",
        "PQC011", "PQC012", "PQC013",
    }


def test_safe_fixture_yields_zero_findings():
    result = _scan(FIXTURES / "safe.rs")
    assert result.findings == []


def test_findings_carry_positions_and_migration_guidance():
    result = _scan(FIXTURES / "vulnerable.rs")
    for finding in result.findings:
        assert finding.line_number >= 1
        assert finding.column_number >= 1
        assert finding.code_snippet
        assert finding.migration_suggestion.recommended_algorithm


# --------------------------------------------------------------------------- #
# Import resolution — the precision gate
# --------------------------------------------------------------------------- #


def test_bare_use_of_an_imported_type_is_flagged():
    findings = _analyze(
        "use rsa::RsaPrivateKey;\n"
        "fn f() { let k = RsaPrivateKey::new(&mut rng, 4096); }\n"
    )
    assert [f.rule_id for f in findings] == ["PQC001"]
    assert findings[0].algorithm == "RSA-4096"


def test_same_name_without_a_crypto_import_is_not_flagged():
    """The whole precision gate: no import origin, no finding."""
    findings = _analyze("struct Sha1;\nfn f() { let h = Sha1::new(); }\n")
    assert findings == []


def test_aliased_import_resolves_to_the_real_crate():
    findings = _analyze(
        "use ed25519_dalek::SigningKey as EdKey;\n"
        "fn f() { let k = EdKey::generate(&mut rng); }\n"
    )
    assert [f.rule_id for f in findings] == ["PQC006"]


def test_brace_list_import_resolves_each_name():
    findings = _analyze(
        "use sha1::{Digest, Sha1};\nfn f() { let h = Sha1::new(); }\n"
    )
    assert [f.rule_id for f in findings] == ["PQC009"]


def test_glob_import_resolves_the_prefix():
    findings = _analyze(
        "use x25519_dalek::*;\nfn f() { let s = EphemeralSecret::random(rng); }\n"
    )
    assert [f.rule_id for f in findings] == ["PQC005"]


def test_glob_import_of_a_safe_crate_does_not_leak():
    findings = _analyze("use sha2::*;\nfn f() { let h = Sha1::new(); }\n")
    assert findings == []


def test_fully_qualified_path_needs_no_import():
    findings = _analyze("fn f() { let k = p256::ecdsa::SigningKey::random(&mut rng); }")
    assert [f.rule_id for f in findings] == ["PQC004"]
    assert findings[0].algorithm == "ECDSA-P-256"


def test_use_declarations_themselves_are_not_flagged():
    """Importing a name is not using it — only the call site is a finding."""
    findings = _analyze("use rsa::RsaPrivateKey;\nuse sha1::Sha1;\n")
    assert findings == []


# --------------------------------------------------------------------------- #
# Specific detections
# --------------------------------------------------------------------------- #


def test_turbofish_generics_are_stripped_from_the_path():
    findings = _analyze(
        "use rsa::Oaep;\nfn f() { let p = Oaep::new::<sha2::Sha256>(); }\n"
    )
    assert [f.rule_id for f in findings] == ["PQC002"]


def test_ring_constants_are_flagged_by_primitive():
    findings = _analyze(
        "use ring::{agreement, signature};\n"
        "fn a() -> &'static signature::EdDSAParameters { &signature::ED25519 }\n"
        "fn b() -> &'static agreement::Algorithm { &agreement::X25519 }\n"
        "fn c() { let _ = &signature::ECDSA_P384_SHA384_ASN1_SIGNING; }\n"
    )
    by_rule = {f.rule_id: f.algorithm for f in findings}
    assert by_rule["PQC006"] == "Ed25519"
    assert by_rule["PQC005"] == "X25519"
    assert by_rule["PQC004"] == "ECDSA-P-384"


def test_openssl_legacy_tls_version_is_high_severity():
    findings = _analyze(
        "use openssl::ssl::SslVersion;\nfn f() -> SslVersion { SslVersion::TLS1 }\n"
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "PQC012"
    assert findings[0].severity == "high"


def test_modern_tls_version_is_not_flagged():
    findings = _analyze(
        "use openssl::ssl::SslVersion;\nfn f() -> SslVersion { SslVersion::TLS1_3 }\n"
    )
    assert findings == []


def test_symmetric_jwt_algorithm_is_not_flagged():
    findings = _analyze(
        "use jsonwebtoken::Algorithm;\nfn f() -> Algorithm { Algorithm::HS256 }\n"
    )
    assert findings == []


def test_des_variants_report_the_right_cipher():
    findings = _analyze(
        "use des::{Des, TdesEde3};\n"
        "fn a() { let c = Des::new(&key); }\n"
        "fn b() { let c = TdesEde3::new(&key); }\n"
    )
    assert sorted(f.algorithm for f in findings) == ["3DES", "DES"]


def test_rsa_key_size_is_extracted_with_separators_and_suffixes():
    findings = _analyze(
        "use rsa::RsaPrivateKey;\nfn f() { RsaPrivateKey::new(&mut rng, 4_096usize); }\n"
    )
    assert findings[0].algorithm == "RSA-4096"


def test_duplicate_positions_are_deduplicated():
    findings = _analyze(
        "use sha1::Sha1;\nfn f() { let a = Sha1::new(); let b = Sha1::new(); }\n"
    )
    # Two distinct columns on one line -> two findings, not one and not four.
    assert len(findings) == 2
    assert len({(f.line_number, f.column_number) for f in findings}) == 2
