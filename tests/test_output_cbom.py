"""Tests for CycloneDX 1.6 CBOM output."""

from __future__ import annotations

from pathlib import Path

from pqcscan.config import PqcConfig
from pqcscan.output import cbom as cbom_out
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "python"
FIXED_TS = "2024-08-13T00:00:00Z"


def _result():
    return run_scan([str(FIXTURES)], PqcConfig.default())


def test_cbom_top_level_shape():
    doc = cbom_out.to_cbom(_result(), timestamp=FIXED_TS)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    assert doc["metadata"]["timestamp"] == FIXED_TS
    tool = doc["metadata"]["tools"]["components"][0]
    assert tool["name"] == "pqc-scan"


def test_cbom_components_are_crypto_assets():
    doc = cbom_out.to_cbom(_result(), timestamp=FIXED_TS)
    assert doc["components"], "expected at least one component"
    crypto_assets = [c for c in doc["components"] if c["type"] == "cryptographic-asset"]
    assert crypto_assets
    for comp in crypto_assets:
        cp = comp["cryptoProperties"]
        assert cp["assetType"] in ("algorithm", "protocol", "certificate")
        if cp["assetType"] == "algorithm":
            ap = cp["algorithmProperties"]
            assert ap["nistQuantumSecurityLevel"] == 0
            assert ap["primitive"]
            assert ap["cryptoFunctions"]


def test_cbom_rsa_has_oid_and_classical_level():
    result = _result()
    doc = cbom_out.to_cbom(result, timestamp=FIXED_TS)
    rsa = [c for c in doc["components"] if c["name"].startswith("RSA")]
    assert rsa, "expected an RSA cryptographic asset"
    ap = rsa[0]["cryptoProperties"]["algorithmProperties"]
    assert ap.get("classicalSecurityLevel") is not None
    assert "oid" in rsa[0]["cryptoProperties"]


def test_cbom_oids_are_not_misassigned_by_substring():
    """Regression: EdDSA must not get the DSA OID; a SHA-1 cert asset must not
    get the rsaEncryption OID."""
    from pqcscan.output.cbom import _oid_for

    assert _oid_for("EdDSA", "ed25519") == "1.3.101.112"
    assert _oid_for("Ed25519", "ed25519") == "1.3.101.112"
    assert _oid_for("SHA-1 (sha1WithRSAEncryption)", "sha1") == "1.3.14.3.2.26"
    assert _oid_for("DSA", "dsa") == "1.2.840.10040.4.1"


def test_cbom_parameter_set_is_meaningful():
    """Regression: padding suffixes must not become a parameterSetIdentifier."""
    from pqcscan.output.cbom import _parameter_set

    assert _parameter_set("RSA-2048", "rsa") == "2048"
    assert _parameter_set("RSA-OAEP", "rsa-encryption") is None
    assert _parameter_set("ECDSA-P-384", "ecdsa") == "P-384"
    assert _parameter_set("X25519", "ecdh") == "X25519"


def test_cbom_is_deterministic_with_fixed_timestamp():
    result = _result()
    a = cbom_out.to_cbom_json(result, timestamp=FIXED_TS)
    b = cbom_out.to_cbom_json(result, timestamp=FIXED_TS)
    assert a == b


def test_cbom_deduplicates_with_occurrences():
    """One component per distinct algorithm, with every hit listed in
    evidence.occurrences — not one component per finding."""
    result = _result()
    doc = cbom_out.to_cbom(result, timestamp=FIXED_TS)
    names = [c["name"] for c in doc["components"]]
    assert len(names) == len(set(names)), "components must be deduplicated"
    occurrence_total = sum(
        len(c.get("evidence", {}).get("occurrences", [])) for c in doc["components"]
    )
    assert occurrence_total == len(result.findings)


def test_cbom_occurrence_locations_are_relative():
    """Occurrence locations are scan-root-relative so the CBOM is portable."""
    result = _result()
    doc = cbom_out.to_cbom(result, timestamp=FIXED_TS)
    for comp in doc["components"]:
        for occ in comp.get("evidence", {}).get("occurrences", []):
            assert not occ["location"].startswith("/")
            assert "\\" not in occ["location"]
