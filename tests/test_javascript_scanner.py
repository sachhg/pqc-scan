"""Tests for the JavaScript/Node.js AST scanner."""

from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as tsj
from tree_sitter import Language, Parser

from pqcscan.config import PqcConfig
from pqcscan.languages import javascript_rules
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "javascript"


def _analyze(source: str, name: str = "snippet.js"):
    parser = Parser(Language(tsj.language()))
    tree = parser.parse(source.encode("utf-8"))
    return javascript_rules.analyze(tree.root_node, source, name)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Direct analyzer unit tests
# --------------------------------------------------------------------------- #


def test_node_rsa_keypair_and_dh():
    findings = _analyze(
        "const crypto = require('crypto');\n"
        "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);\n"
        "crypto.createDiffieHellman(2048);\n"
    )
    assert {"PQC001", "PQC007"} <= _rule_ids(findings)


def test_public_encrypt_and_create_sign():
    findings = _analyze(
        "const crypto = require('crypto');\n"
        "crypto.publicEncrypt(pub, buf);\n"
        "crypto.privateEncrypt(priv, buf);\n"
        "crypto.createSign('RSA-SHA256');\n"
        "crypto.createVerify('RSA-SHA1');\n"
    )
    ids = _rule_ids(findings)
    assert "PQC002" in ids  # publicEncrypt
    assert "PQC003" in ids  # privateEncrypt + createSign
    assert "PQC009" in ids  # SHA-1 digest inside RSA-SHA1


def test_webcrypto_importkey_ecdh():
    findings = _analyze(
        "await window.crypto.subtle.importKey('raw', keyData, { name: 'ECDH' }, false, []);\n"
    )
    assert "PQC005" in _rule_ids(findings)


def test_jose_set_protected_header():
    findings = _analyze(
        "import { SignJWT } from 'jose';\n"
        "const t = await new SignJWT(claims)"
        ".setProtectedHeader({ alg: 'RS256' }).sign(key);\n"
    )
    pqc011 = [f for f in findings if f.rule_id == "PQC011"]
    assert pqc011 and pqc011[0].confidence == "high"


def test_algorithms_array_in_options_object():
    """jose-style option objects are caught even when the consuming call is
    not individually modeled (jwtVerify, fastify plugins, ...)."""
    findings = _analyze(
        "const { jwtVerify } = require('jose');\n"
        "await jwtVerify(token, key, { algorithms: ['ES384'] });\n"
    )
    assert "PQC011" in _rule_ids(findings)


def test_aws_kms_keyspec():
    findings = _analyze(
        "const cmd = new CreateKeyCommand({ KeySpec: 'RSA_2048', KeyUsage: 'SIGN_VERIFY' });\n"
    )
    hits = [f for f in findings if f.rule_id == "PQC001"]
    assert hits and hits[0].confidence == "medium"


def test_create_hash_sha256_not_flagged():
    findings = _analyze(
        "const crypto = require('crypto');\n"
        "crypto.createHash('sha256').update(data).digest('hex');\n"
        "crypto.createHmac('sha256', key);\n"
    )
    assert findings == []


def test_webcrypto_aes_gcm_not_flagged():
    findings = _analyze(
        "await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);\n"
    )
    assert findings == []


def test_comments_and_unrelated_names_not_flagged():
    findings = _analyze(
        "// TODO: migrate from RSA to ML-KEM\n"
        "const rsaKeyPath = '/etc/keys/service.pem';\n"
        "const hs = { algorithm: 'HS256' };\n"
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# End-to-end engine tests against the committed fixtures
# --------------------------------------------------------------------------- #


def test_fixture_vulnerable_node():
    result = run_scan([str(FIXTURES / "vulnerable_node.js")], PqcConfig.default())
    ids = _rule_ids(result.findings)
    assert {"PQC001", "PQC002", "PQC003", "PQC004", "PQC005", "PQC007"} <= ids


def test_fixture_vulnerable_jwt():
    result = run_scan([str(FIXTURES / "vulnerable_jwt.js")], PqcConfig.default())
    pqc011 = [f for f in result.findings if f.rule_id == "PQC011"]
    algorithms = {f.algorithm for f in pqc011}
    assert any("RS256" in a for a in algorithms)
    assert any("ES384" in a for a in algorithms)  # jose jwtVerify options object
