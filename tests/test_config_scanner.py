"""Tests for the configuration-file scanner."""

from __future__ import annotations

from pathlib import Path

from pqcscan.scanner.base import SEVERITY_CRITICAL
from pqcscan.scanner.config_scanner import ConfigScanner

FIXTURES = Path(__file__).parent / "fixtures" / "configs"


def _scan(name: str):
    return ConfigScanner().scan_file(FIXTURES / name)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_vulnerable_yaml_flags_tls_and_cert():
    findings = _scan("vulnerable.yml")
    ids = _rule_ids(findings)
    # weak cipher suites + outdated protocol + RSA key type
    assert "PQC012" in ids
    assert "PQC001" in ids
    # SHA-1 certificate signature is critical in a signing context
    assert "PQC009" in ids
    sha1 = next(f for f in findings if f.rule_id == "PQC009")
    assert sha1.severity == SEVERITY_CRITICAL


def test_vulnerable_nginx_conf():
    findings = _scan("vulnerable_nginx.conf")
    assert "PQC012" in _rule_ids(findings)
    # the legacy TLSv1 / TLSv1.1 protocol tokens are detected
    assert any("TLSv1" in f.algorithm for f in findings)


def test_safe_config_has_zero_findings():
    """TLS 1.3 + AEAD suites must produce ZERO findings."""
    findings = _scan("safe_config.yml")
    assert findings == [], [f"{f.rule_id} {f.algorithm} L{f.line_number}" for f in findings]


def _scan_text(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return {f"{f.rule_id}" for f in ConfigScanner().scan_file(p)}


def test_cipher_anchor_avoids_false_positive(tmp_path):
    """Regression: an uppercase constant containing a weak token but no cipher
    component must NOT be flagged as a cipher suite."""
    assert _scan_text(tmp_path, "a.yml", "env: MY-RSA-KEY-PATH\n") == set()
    assert _scan_text(tmp_path, "b.yml", "header: CONTENT-MD5\n") == set()


def test_two_part_broken_cipher_detected(tmp_path):
    """Regression: 2-part broken suites (RC4-MD5, NULL-SHA) must be caught."""
    assert "PQC012" in _scan_text(tmp_path, "c.conf", "ciphers RC4-MD5:NULL-SHA;\n")


def test_tls_version_forms(tmp_path):
    """Regression: TLS1.0/1.1 (no 'v') flagged; TLS 1.2/1.3 not."""
    assert "PQC012" in _scan_text(tmp_path, "d.conf", "min_version: TLS1.0\n")
    assert "PQC012" in _scan_text(tmp_path, "e.conf", "protocols: PROTOCOL_TLSv1_1\n")
    assert _scan_text(tmp_path, "f.conf", "protocols: TLSv1.2 TLSv1.3\n") == set()


def test_disabled_ssl_protocols_not_flagged(tmp_path):
    """Regression (Bug 2): a '-' prefix in an SSLProtocol/ssl_protocols directive
    means the protocol is being DISABLED, so it must not be flagged."""
    assert _scan_text(tmp_path, "apache.conf", "SSLProtocol all -SSLv2 -SSLv3\n") == set()
    assert _scan_text(tmp_path, "apache2.conf", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n") == set()
    # sanity: a genuinely ENABLED legacy protocol is still caught
    assert "PQC012" in _scan_text(tmp_path, "weak.conf", "SSLProtocol TLSv1\n")
    assert "PQC012" in _scan_text(tmp_path, "weak2.conf", "ssl_protocols TLSv1 TLSv1.1;\n")


def test_supports_detection():
    scanner = ConfigScanner()
    assert scanner.supports(Path("nginx.conf"))
    assert scanner.supports(Path("config.yml"))
    assert scanner.supports(Path("settings.toml"))
    assert not scanner.supports(Path("main.py"))


def test_openssl_cipher_exclusions_not_flagged(tmp_path):
    """Regression: '!SUITE' / '-SUITE' in an OpenSSL cipher string REMOVES the
    suite, so a hardened exclusion list must produce zero findings."""
    assert _scan_text(
        tmp_path, "h.conf", "ssl_ciphers 'HIGH:!EXP-RC4-MD5:!DES-CBC3-SHA';\n"
    ) == set()
    assert _scan_text(
        tmp_path, "i.conf", "SSLCipherSuite HIGH:!ECDHE-RSA-AES128-SHA:-NULL-SHA\n"
    ) == set()
    # sanity: the same suites WITHOUT negation are still caught
    assert "PQC012" in _scan_text(
        tmp_path, "j.conf", "ssl_ciphers 'EXP-RC4-MD5:DES-CBC3-SHA';\n"
    )
