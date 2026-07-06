"""Tests for the Go AST scanner."""

from __future__ import annotations

from pathlib import Path

import tree_sitter_go as tsg
from tree_sitter import Language, Parser

from pqcscan.config import PqcConfig
from pqcscan.languages import go_rules
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "go"


def _analyze(source: str, name: str = "snippet.go"):
    parser = Parser(Language(tsg.language()))
    tree = parser.parse(source.encode("utf-8"))
    return go_rules.analyze(tree.root_node, source, name)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _wrap(body: str) -> str:
    return f"package main\nfunc f() {{\n{body}\n}}"


# --------------------------------------------------------------------------- #
# Direct analyzer unit tests
# --------------------------------------------------------------------------- #


def test_stdlib_crypto_calls():
    findings = _analyze(_wrap(
        "k, _ := rsa.GenerateKey(rand.Reader, 2048)\n"
        "e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n"
        "_ = sha1.New()\n_ = k; _ = e\n"
    ))
    assert {"PQC001", "PQC004", "PQC009"} <= _rule_ids(findings)


def test_tls_config_minversion_and_suites():
    findings = _analyze(_wrap(
        "cfg := &tls.Config{\n"
        "  MinVersion: tls.VersionTLS10,\n"
        "  CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},\n"
        "}\n_ = cfg\n"
    ))
    pqc012 = [f for f in findings if f.rule_id == "PQC012"]
    assert len(pqc012) == 2
    assert all(f.severity == "high" for f in pqc012)  # static RSA + 3DES + TLS1.0


def test_tls_config_assignment_form():
    findings = _analyze(_wrap("cfg.MaxVersion = tls.VersionTLS11\n"))
    assert "PQC012" in _rule_ids(findings)


def test_tls13_config_not_flagged():
    findings = _analyze(_wrap(
        "good := &tls.Config{\n"
        "  MinVersion:   tls.VersionTLS13,\n"
        "  CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},\n"
        "}\n_ = good\n"
    ))
    assert findings == []


def test_bare_version_constant_comparison_not_flagged():
    """A comparison against a legacy constant is feature detection, not a pin."""
    findings = _analyze(_wrap(
        "if state.Version == tls.VersionTLS10 {\n  reject()\n}\n"
    ))
    assert findings == []


def test_golang_jwt_signing_methods():
    findings = _analyze(_wrap(
        "t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)\n"
        "m := jwt.GetSigningMethod(\"ES384\")\n_ = t; _ = m\n"
    ))
    pqc011 = [f for f in findings if f.rule_id == "PQC011"]
    assert len(pqc011) == 2


def test_golang_jwt_hmac_not_flagged():
    findings = _analyze(_wrap(
        "t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)\n"
        "m := jwt.GetSigningMethod(\"HS256\")\n_ = t; _ = m\n"
    ))
    assert findings == []


# --------------------------------------------------------------------------- #
# End-to-end engine test against the committed fixture
# --------------------------------------------------------------------------- #


def test_fixture_vulnerable_go():
    result = run_scan([str(FIXTURES / "vulnerable.go")], PqcConfig.default())
    ids = _rule_ids(result.findings)
    assert {
        "PQC001", "PQC002", "PQC003", "PQC004", "PQC005", "PQC006",
        "PQC008", "PQC009", "PQC010", "PQC011", "PQC012", "PQC013",
    } <= ids
    # modernTLS() and safe() must contribute nothing
    assert not any("TLS_AES_" in f.algorithm or "CHACHA20" in f.algorithm
                   for f in result.findings)
    assert not any("VersionTLS13" in f.code_snippet and f.rule_id == "PQC012"
                   for f in result.findings)
