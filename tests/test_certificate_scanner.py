"""Tests for key-material and certificate scanning (PQC015 / PQC016)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from pqcscan.config import PqcConfig
from pqcscan.scanner import asn1
from pqcscan.scanner.base import ScanContext
from pqcscan.scanner.certificate_scanner import CertificateScanner
from pqcscan.scanner.engine import run_scan

import sys

KEYS = Path(__file__).parent / "fixtures" / "keys"
SAFE = KEYS / "safe"
sys.path.insert(0, str(KEYS))
from private_material import PRIVATE_KEYS, materialize  # noqa: E402


@pytest.fixture(scope="module")
def private_keys(tmp_path_factory) -> dict[str, Path]:
    """Real private-key PEM files, written out for the duration of the module."""
    return materialize(tmp_path_factory.mktemp("keys"))


def _scan(path: Path):
    return CertificateScanner(ScanContext()).scan_file(path)


def _one(path: Path):
    findings = _scan(path)
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    return findings[0]


# --------------------------------------------------------------------------- #
# ASN.1 reader
# --------------------------------------------------------------------------- #


def test_oid_decoding():
    # DER for OID 1.2.840.113549.1.1.1 (rsaEncryption).
    der = bytes.fromhex("06092a864886f70d010101")
    assert asn1.oid_string(asn1.read(der)) == "1.2.840.113549.1.1.1"


def test_integer_bit_length_ignores_sign_padding():
    # INTEGER 0x00FF -> 8 bits, not 16.
    assert asn1.integer_bit_length(asn1.read(bytes.fromhex("020200ff"))) == 8


@pytest.mark.parametrize(
    "hexdata",
    [
        "3005",              # length exceeds buffer
        "0680",              # indefinite length
        "30",                # truncated
    ],
)
def test_malformed_der_raises_rather_than_looping(hexdata):
    with pytest.raises(asn1.Asn1Error):
        node = asn1.read(bytes.fromhex(hexdata))
        list(asn1.walk(node))


# --------------------------------------------------------------------------- #
# Private keys
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,algorithm",
    [
        ("rsa_2048_pkcs1.key", "RSA-2048"),
        ("rsa_3072_pkcs8.key", "RSA-3072"),
        ("ec_p256.key", "ECDSA-P-256"),
        ("ed25519.key", "Ed25519"),
        ("x25519.key", "X25519"),
        ("dsa_2048.key", "DSA"),
        ("id_rsa", "RSA-2048"),
        ("id_ed25519", "Ed25519"),
        ("id_ecdsa", "ECDSA-P-384"),
    ],
)
def test_private_keys_are_identified_from_their_der(private_keys, name, algorithm):
    finding = _one(private_keys[name])
    assert finding.rule_id == "PQC015"
    assert finding.algorithm == algorithm
    assert finding.severity == "high", "a private key outranks a public one"


def test_pkcs8_and_pkcs1_rsa_agree_on_the_key_size(private_keys):
    """The label differs, the DER does not — both must report the real size."""
    assert _one(private_keys["rsa_2048_pkcs1.key"]).algorithm == "RSA-2048"
    assert _one(private_keys["rsa_3072_pkcs8.key"]).algorithm == "RSA-3072"


# --------------------------------------------------------------------------- #
# Public keys and certificates
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,algorithm",
    [
        ("rsa_2048.pub.pem", "RSA-2048"),
        ("ec_p256.pub.pem", "ECDSA-P-256"),
        ("id_rsa.pub", "RSA-2048"),
        ("id_ed25519.pub", "Ed25519"),
        ("id_ecdsa.pub", "ECDSA-P-384"),
    ],
)
def test_public_keys_are_identified(name, algorithm):
    finding = _one(KEYS / name)
    assert finding.rule_id == "PQC015"
    assert finding.algorithm == algorithm
    assert finding.severity == "medium"


def test_authorized_keys_reports_every_entry():
    findings = _scan(KEYS / "authorized_keys")
    assert {f.algorithm for f in findings} == {"RSA-2048", "Ed25519", "ECDSA-P-384"}
    # Each entry gets its own line number.
    assert len({f.line_number for f in findings}) == 3


def test_certificate_reports_key_signature_and_expiry():
    finding = _one(KEYS / "cert_rsa_sha256.crt")
    assert finding.rule_id == "PQC016"
    assert finding.algorithm == "RSA-2048"
    assert "CN=modern.example.com" in finding.description
    assert "sha256WithRSAEncryption" in finding.description
    assert "expires 20" in finding.description


def test_ecdsa_certificate_reports_the_curve():
    assert _one(KEYS / "cert_ec_p256.crt").algorithm == "ECDSA-P-256"


def test_sha1_signed_certificate_is_critical():
    findings = _scan(KEYS / "cert_rsa_sha1.crt")
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"PQC016", "PQC009"}
    assert by_rule["PQC009"].severity == "critical"
    assert "sha1WithRSAEncryption" in by_rule["PQC009"].algorithm


def test_certificate_request_is_detected_at_lower_severity():
    finding = _one(KEYS / "request.csr")
    assert finding.rule_id == "PQC016"
    assert finding.severity == "medium"


def test_dh_parameters_are_flagged():
    finding = _one(KEYS / "dhparams.pem")
    assert finding.rule_id == "PQC015"
    assert finding.algorithm == "DH"


# --------------------------------------------------------------------------- #
# Precision
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["ml_dsa_65.key", "ml_kem_768.key"])
def test_post_quantum_private_keys_are_not_flagged(private_keys, name):
    """The whole point of reading the DER: ML-DSA/ML-KEM share the PKCS#8 label."""
    assert _scan(private_keys[name]) == []


@pytest.mark.parametrize("name", ["ml_dsa_65.pub.pem", "cert_ml_dsa.crt"])
def test_post_quantum_public_material_is_not_flagged(name):
    assert _scan(SAFE / name) == []


def test_encrypted_private_key_is_skipped(tmp_path):
    """Its algorithm is undeterminable without the passphrase — guessing is worse."""
    path = tmp_path / "enc.key"
    path.write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        + base64.b64encode(b"\x30\x03\x02\x01\x00").decode()
        + "\n-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    assert _scan(path) == []


def test_garbage_pem_body_does_not_raise(tmp_path):
    path = tmp_path / "broken.pem"
    path.write_text(
        "-----BEGIN CERTIFICATE-----\nnot!valid!base64!!!\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    assert _scan(path) == []


def test_truncated_der_does_not_raise(tmp_path):
    path = tmp_path / "truncated.pem"
    body = base64.b64encode(b"\x30\x82\x0f\xff\x02\x01\x00").decode()
    path.write_text(
        f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    assert _scan(path) == []


def test_a_file_without_key_material_is_free(tmp_path):
    path = tmp_path / "plain.yml"
    path.write_text("server:\n  port: 8443\n", encoding="utf-8")
    assert _scan(path) == []


# --------------------------------------------------------------------------- #
# Embedded keys in configuration files
# --------------------------------------------------------------------------- #


def test_pem_inlined_in_yaml_is_found(tmp_path, private_keys):
    pem = private_keys["rsa_2048_pkcs1.key"].read_text(encoding="utf-8")
    indented = "\n".join("    " + line for line in pem.splitlines())
    path = tmp_path / "secret.yml"
    path.write_text(
        "apiVersion: v1\nkind: Secret\nstringData:\n  tls.key: |\n" + indented + "\n",
        encoding="utf-8",
    )
    finding = _one(path)
    assert finding.rule_id == "PQC015"
    assert finding.algorithm == "RSA-2048"
    assert finding.line_number > 1


def test_pem_with_escaped_newlines_in_json_is_found(tmp_path, private_keys):
    pem = private_keys["ec_p256.key"].read_text(encoding="utf-8").replace("\n", "\\n")
    path = tmp_path / "config.json"
    path.write_text('{"key": "' + pem + '"}\n', encoding="utf-8")
    assert _one(path).algorithm == "ECDSA-P-256"


def test_config_file_gets_both_scanners(tmp_path, private_keys):
    """A config can enable a weak cipher AND inline a key; both must be reported."""
    pem = private_keys["rsa_2048_pkcs1.key"].read_text(encoding="utf-8")
    path = tmp_path / "tls.yml"
    path.write_text(
        "ciphers: ECDHE-RSA-DES-CBC3-SHA\nkey: |\n"
        + "\n".join("  " + line for line in pem.splitlines())
        + "\n",
        encoding="utf-8",
    )
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    result = run_scan([path], cfg)
    assert {f.rule_id for f in result.findings} == {"PQC012", "PQC015"}


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


def test_scan_certificates_can_be_disabled(tmp_path):
    cfg = PqcConfig.default()
    cfg.severity_threshold = "low"
    cfg.scan_certificates = False
    result = run_scan([KEYS / "cert_rsa_sha256.crt"], cfg)
    assert result.findings == []


def test_rules_can_be_disabled_individually():
    scanner = CertificateScanner(ScanContext(disabled_rules=frozenset({"PQC015"})))
    assert scanner.scan_file(KEYS / "id_rsa.pub") == []
    assert scanner.scan_file(KEYS / "cert_rsa_sha256.crt")


def test_findings_carry_key_specific_migration_guidance():
    finding = _one(KEYS / "cert_rsa_sha256.crt")
    assert "ML-DSA" in finding.migration_suggestion.recommended_algorithm
    key_finding = _one(KEYS / "id_ed25519.pub")
    assert key_finding.migration_suggestion.recommended_algorithm


def test_every_private_key_fixture_has_a_description():
    assert all(desc for desc, _ in PRIVATE_KEYS.values())


# --------------------------------------------------------------------------- #
# Pathological inputs — a scanner runs on repositories it does not control
# --------------------------------------------------------------------------- #


def test_many_unterminated_pem_headers_stay_linear(tmp_path):
    """Pairing BEGIN/END in one pass instead of matching the body with a regex.

    A backreferenced `.*?` body makes every unterminated BEGIN scan to end of
    file. This input took ~39 seconds that way; the bound is deliberately loose
    so it survives a slow CI runner while still catching a return to quadratic.
    """
    import time

    path = tmp_path / "flood.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\n" * 20000, encoding="utf-8")
    started = time.perf_counter()
    assert _scan(path) == []
    assert time.perf_counter() - started < 5.0


def test_many_small_pem_blocks_stay_linear(tmp_path):
    """Resolving each block's line by counting newlines from byte 0 is the same
    quadratic trap; the line index has to be built once per file."""
    import time

    path = tmp_path / "many.pem"
    path.write_text(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" * 20000,
        encoding="utf-8",
    )
    started = time.perf_counter()
    assert _scan(path) == []
    assert time.perf_counter() - started < 5.0


def test_many_ssh_public_keys_report_correct_line_numbers(tmp_path):
    entry = (KEYS / "id_rsa.pub").read_text(encoding="utf-8").strip()
    path = tmp_path / "authorized_keys"
    path.write_text("".join(f"host{i}.example.com {entry}\n" for i in range(200)),
                    encoding="utf-8")
    findings = _scan(path)
    assert len(findings) == 200
    assert [f.line_number for f in findings] == list(range(1, 201))


def test_an_unterminated_block_does_not_hide_the_next_valid_one(tmp_path):
    path = tmp_path / "mixed.pem"
    path.write_text(
        "-----BEGIN CERTIFICATE-----\ntruncated, no END marker\n\n"
        + (KEYS / "cert_rsa_sha256.crt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert [f.rule_id for f in _scan(path)] == ["PQC016"]


def test_a_certificate_chain_yields_one_finding_per_certificate(tmp_path):
    path = tmp_path / "chain.pem"
    path.write_text(
        (KEYS / "cert_rsa_sha256.crt").read_text(encoding="utf-8")
        + (KEYS / "cert_ec_p256.crt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings = _scan(path)
    assert [f.algorithm for f in findings] == ["RSA-2048", "ECDSA-P-256"]
    assert findings[1].line_number > findings[0].line_number
