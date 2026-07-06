"""Tests for the Java AST scanner."""

from __future__ import annotations

from pathlib import Path

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

from pqcscan.config import PqcConfig
from pqcscan.languages import java_rules
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "java"


def _analyze(source: str, name: str = "Snippet.java"):
    parser = Parser(Language(tsjava.language()))
    tree = parser.parse(source.encode("utf-8"))
    return java_rules.analyze(tree.root_node, source, name)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _wrap(body: str) -> str:
    return f"class T {{ void f() throws Exception {{\n{body}\n}} }}"


# --------------------------------------------------------------------------- #
# Direct analyzer unit tests
# --------------------------------------------------------------------------- #


def test_jca_factories():
    findings = _analyze(_wrap(
        'KeyPairGenerator.getInstance("RSA");\n'
        'Signature.getInstance("SHA1withRSA");\n'
        'MessageDigest.getInstance("MD5");\n'
    ))
    ids = _rule_ids(findings)
    assert {"PQC001", "PQC003", "PQC009", "PQC010"} <= ids


def test_bouncy_castle_object_creation():
    findings = _analyze(_wrap(
        "RSAKeyGenerationParameters p = new RSAKeyGenerationParameters(e, r, 2048, 80);\n"
        "ECDSASigner signer = new ECDSASigner();\n"
        "Ed25519Signer ed = new Ed25519Signer();\n"
        "X25519Agreement xa = new X25519Agreement();\n"
    ))
    ids = _rule_ids(findings)
    assert {"PQC001", "PQC004", "PQC006", "PQC005"} <= ids


def test_sslcontext_legacy_flagged_modern_not():
    weak = _analyze(_wrap('SSLContext c = SSLContext.getInstance("SSLv3");'))
    assert "PQC012" in _rule_ids(weak)
    tls1 = _analyze(_wrap('SSLContext c = SSLContext.getInstance("TLSv1");'))
    assert "PQC012" in _rule_ids(tls1)
    modern = _analyze(_wrap('SSLContext c = SSLContext.getInstance("TLSv1.3");'))
    assert modern == []
    negotiated = _analyze(_wrap('SSLContext c = SSLContext.getInstance("TLS");'))
    assert negotiated == []


def test_safe_java_not_flagged():
    findings = _analyze(_wrap(
        'MessageDigest.getInstance("SHA-256");\n'
        'KeyGenerator.getInstance("AES");\n'
        'Cipher.getInstance("AES/GCM/NoPadding");\n'
        "MyOwnGenerator g = new MyOwnGenerator();\n"
    ))
    assert findings == []


# --------------------------------------------------------------------------- #
# End-to-end engine test against the committed fixture
# --------------------------------------------------------------------------- #


def test_fixture_vulnerable_crypto():
    result = run_scan([str(FIXTURES / "VulnerableCrypto.java")], PqcConfig.default())
    ids = _rule_ids(result.findings)
    assert {
        "PQC001", "PQC002", "PQC003", "PQC004", "PQC006", "PQC007",
        "PQC008", "PQC009", "PQC010", "PQC012", "PQC013",
    } <= ids
    # the safe() method's SHA-256/AES lines must not appear in any finding
    assert not any("SHA-256" in f.algorithm or "AES" in f.algorithm for f in result.findings)
