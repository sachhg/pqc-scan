"""Tests for the Python AST scanner (the core proof of concept)."""

from __future__ import annotations

from pathlib import Path

import tree_sitter_python as tsp
from tree_sitter import Language, Parser

from pqcscan.config import PqcConfig
from pqcscan.languages import python_rules
from pqcscan.scanner.base import SEVERITY_CRITICAL
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _analyze(source: str, name: str = "snippet.py"):
    parser = Parser(Language(tsp.language()))
    tree = parser.parse(source.encode("utf-8"))
    return python_rules.analyze(tree.root_node, source, name)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Direct analyzer unit tests
# --------------------------------------------------------------------------- #


def test_rsa_key_generation_is_critical():
    findings = _analyze(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    assert any(f.rule_id == "PQC001" for f in findings)
    rsa_finding = next(f for f in findings if f.rule_id == "PQC001")
    assert rsa_finding.severity == SEVERITY_CRITICAL
    assert "RSA" in rsa_finding.algorithm
    assert rsa_finding.migration_suggestion.recommended_algorithm  # populated


def test_rsa_4096_still_flagged():
    findings = _analyze("from Crypto.PublicKey import RSA\nk = RSA.generate(4096)\n")
    assert "PQC001" in _rule_ids(findings)


def test_elliptic_curve_detection():
    findings = _analyze(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP384R1())\n"
    )
    assert "PQC004" in _rule_ids(findings)
    assert any("P-384" in f.algorithm for f in findings)


def test_jwt_asymmetric_flagged_symmetric_not():
    findings = _analyze(
        'import jwt\n'
        't1 = jwt.encode(p, k, algorithm="RS256")\n'
        't2 = jwt.encode(p, k, algorithm="HS256")\n'
    )
    ids = _rule_ids(findings)
    assert "PQC011" in ids
    # HS256 must NOT produce a finding.
    assert all("HS256" not in f.algorithm for f in findings)
    assert sum(1 for f in findings if f.rule_id == "PQC011") == 1


def test_hashlib_sha1_md5_flagged_sha256_not():
    findings = _analyze(
        "import hashlib\n"
        "a = hashlib.md5(b'x')\n"
        "b = hashlib.sha1(b'x')\n"
        "c = hashlib.sha256(b'x')\n"
        "d = hashlib.sha3_256(b'x')\n"
    )
    ids = _rule_ids(findings)
    assert "PQC010" in ids  # md5
    assert "PQC009" in ids  # sha1
    # sha256 / sha3_256 are safe — only the two weak digests should appear.
    assert len(findings) == 2


# --------------------------------------------------------------------------- #
# End-to-end engine tests against the committed fixtures
# --------------------------------------------------------------------------- #


def _scan(path: Path):
    return run_scan([str(path)], PqcConfig.default())


def test_fixture_vulnerable_rsa():
    result = _scan(FIXTURES / "vulnerable_rsa.py")
    ids = _rule_ids(result.findings)
    assert "PQC001" in ids
    assert "PQC002" in ids
    assert any(f.severity == SEVERITY_CRITICAL for f in result.findings)


def test_fixture_vulnerable_ec():
    result = _scan(FIXTURES / "vulnerable_ec.py")
    ids = _rule_ids(result.findings)
    assert {"PQC004", "PQC005", "PQC006"} <= ids


def test_fixture_vulnerable_jwt():
    result = _scan(FIXTURES / "vulnerable_jwt.py")
    assert "PQC011" in _rule_ids(result.findings)


def test_fixture_vulnerable_tls():
    result = _scan(FIXTURES / "vulnerable_tls.py")
    ids = _rule_ids(result.findings)
    assert {"PQC009", "PQC010", "PQC013"} <= ids


def test_aliased_hash_imports_detected():
    """Regression: `from hashlib import md5 as m; m()` must still be caught."""
    assert "PQC010" in _rule_ids(_analyze("from hashlib import md5 as m\nm(b'x')\n"))
    assert "PQC009" in _rule_ids(_analyze("from hashlib import sha1 as s\ns(b'x')\n"))
    assert "PQC009" in _rule_ids(
        _analyze("from cryptography.hazmat.primitives.hashes import SHA1 as S\nS()\n")
    )


def test_dsa_generate_parameters_detected():
    """Regression: dsa.generate_parameters() is DSA usage (PQC008)."""
    findings = _analyze(
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "dsa.generate_parameters(key_size=2048)\n"
    )
    assert "PQC008" in _rule_ids(findings)


def test_bare_oaep_is_not_a_false_positive():
    """Regression: an unrelated user-defined OAEP()/PKCS1v15() must not flag."""
    findings = _analyze("def OAEP():\n    return 1\nx = OAEP()\n")
    assert findings == []


def test_safe_code_has_zero_findings():
    """The false-positive guard: safe_code.py must produce ZERO findings."""
    result = _scan(FIXTURES / "safe_code.py")
    assert result.findings == [], [f"{f.rule_id} {f.algorithm} L{f.line_number}" for f in result.findings]


# --------------------------------------------------------------------------- #
# Extended coverage: pycryptodome, pyOpenSSL, hashlib.new, indirection
# --------------------------------------------------------------------------- #


def test_aliased_module_import_detected():
    """`import ... as r` + `r.generate_private_key()` resolves through the alias."""
    findings = _analyze(
        "from cryptography.hazmat.primitives.asymmetric import rsa as r\n"
        "k = r.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    assert "PQC001" in _rule_ids(findings)


def test_pycryptodome_signature_objects():
    findings = _analyze(
        "from Crypto.Signature import pkcs1_15, pss, DSS\n"
        "s1 = pkcs1_15.new(key)\n"
        "s2 = pss.new(key)\n"
        "s3 = DSS.new(key, 'fips-186-3')\n"
    )
    ids = _rule_ids(findings)
    assert "PQC003" in ids  # pkcs1_15 + pss
    assert "PQC008" in ids  # DSS
    assert sum(1 for f in findings if f.rule_id == "PQC003") == 2


def test_pycryptodome_cipher_objects():
    findings = _analyze(
        "from Crypto.Cipher import PKCS1_OAEP\n"
        "c = PKCS1_OAEP.new(key)\n"
    )
    assert "PQC002" in _rule_ids(findings)


def test_pycryptodome_pkcs1_v1_5_signature_vs_cipher():
    sig = _analyze("from Crypto.Signature import PKCS1_v1_5\nPKCS1_v1_5.new(key)\n")
    assert "PQC003" in _rule_ids(sig)
    enc = _analyze("from Crypto.Cipher import PKCS1_v1_5\nPKCS1_v1_5.new(key)\n")
    assert "PQC002" in _rule_ids(enc)


def test_unrelated_pss_new_not_flagged():
    """A user-defined `pss` object without a Crypto import must not flag."""
    findings = _analyze("pss = MyPss()\nx = pss.new()\n")
    assert findings == []


def test_pyopenssl_type_rsa():
    findings = _analyze(
        "from OpenSSL.crypto import PKey, TYPE_RSA\n"
        "k = PKey()\n"
        "k.generate_key(TYPE_RSA, 2048)\n"
    )
    pqc001 = [f for f in findings if f.rule_id == "PQC001"]
    assert pqc001 and "2048" in pqc001[0].algorithm


def test_hashlib_new_string_forms():
    """hashlib.new('sha1') / hashlib.new(name='md5') are caught; sha256 not."""
    assert "PQC009" in _rule_ids(_analyze("import hashlib\nhashlib.new('sha1')\n"))
    assert "PQC010" in _rule_ids(_analyze("import hashlib\nhashlib.new(name='md5')\n"))
    assert _analyze("import hashlib\nhashlib.new('sha256')\n") == []


def test_usedforsecurity_false_demotes_to_low():
    findings = _analyze(
        "import hashlib\n"
        "cache_key = hashlib.md5(data, usedforsecurity=False)\n"
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "usedforsecurity" in findings[0].description


def test_jwt_algorithm_via_variable():
    findings = _analyze(
        "import jwt\n"
        "algo = 'RS256'\n"
        "token = jwt.encode(payload, key, algorithm=algo)\n"
    )
    pqc011 = [f for f in findings if f.rule_id == "PQC011"]
    assert len(pqc011) == 1
    assert pqc011[0].confidence == "medium"
    assert "via variable" in pqc011[0].algorithm
    # symmetric algorithm through a variable stays silent
    assert _analyze(
        "import jwt\nalgo = 'HS256'\nt = jwt.encode(p, k, algorithm=algo)\n"
    ) == []


def test_hardened_cipher_string_not_flagged():
    """OpenSSL '!X' exclusions harden the string — must NOT be reported."""
    findings = _analyze(
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.set_ciphers('HIGH:!aNULL:!MD5:!3DES:!RC4')\n"
    )
    assert findings == []


def test_uncalled_reference_in_assert_not_flagged():
    """Passing rsa.generate_private_key as a REFERENCE (e.g. to assert_raises)
    is test scaffolding, not a key generation call site."""
    findings = _analyze(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "assert_raises(ValueError, rsa.generate_private_key, 3, 512)\n"
    )
    assert _rule_ids(findings) == set()


def test_comment_and_docstring_not_flagged():
    findings = _analyze(
        '"""Uses RSA? No — this docstring mentions RS256 and rsa.generate_private_key()."""\n'
        "# TODO: migrate from RSA / SHA1 / md5\n"
        "rsa_key_path = '/etc/keys/rsa.pem'\n"
    )
    assert findings == []
