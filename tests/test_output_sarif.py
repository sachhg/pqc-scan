"""Tests for SARIF 2.1.0 output."""

from __future__ import annotations

from pathlib import Path

from pqcscan.config import PqcConfig
from pqcscan.output import sarif as sarif_out
from pqcscan.scanner.engine import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "python"


def _result():
    return run_scan([str(FIXTURES)], PqcConfig.default())


def test_sarif_top_level_shape():
    doc = sarif_out.to_sarif(_result())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pqc-scan"
    assert driver["version"]
    assert len(driver["rules"]) >= 14  # PQC001..PQC014


def test_sarif_results_have_required_fields():
    doc = sarif_out.to_sarif(_result())
    results = doc["runs"][0]["results"]
    assert results, "expected at least one result"
    for r in results:
        assert r["ruleId"].startswith("PQC")
        assert r["level"] in ("error", "warning", "note")
        assert r["message"]["text"]
        region = r["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["startColumn"] >= 1
        # migration guidance is surfaced in structured properties
        assert "migration" in r["properties"]
        assert r["properties"]["migration"]["recommendedAlgorithm"]
        # no schema-invalid fixes (missing artifactChanges)
        assert "fixes" not in r


def test_sarif_levels_map_from_severity():
    result = _result()
    doc = sarif_out.to_sarif(result)
    by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    # PQC001 (RSA keygen) is critical -> error
    if "PQC001" in by_rule:
        assert by_rule["PQC001"]["level"] == "error"


def test_sarif_security_severity_on_rules():
    doc = sarif_out.to_sarif(_result())
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_sarif_uris_are_relative(tmp_path):
    result = _result()
    json_str = sarif_out.to_sarif_json(result, base_path=str(Path.cwd()))
    assert "\\" not in json_str.split('"uri"')[1][:200]  # posix separators only


def test_sarif_uris_fall_back_to_scan_root(tmp_path):
    """When base_path would produce an escaping ../ URI (scan outside the CWD),
    URIs fall back to scan-root-relative — GitHub cannot render ../ paths."""
    result = _result()
    doc = sarif_out.to_sarif(result, base_path=str(tmp_path))  # unrelated base
    for r in doc["runs"][0]["results"]:
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("..")
        assert not uri.startswith("/")


def test_fingerprints_stable_across_checkout_dirs():
    """The partial fingerprint hashes the RELATIVE uri, so two scans of the
    same code from different absolute locations agree (dedup across runners)."""
    import shutil
    import tempfile

    from pqcscan.config import PqcConfig
    from pqcscan.scanner.engine import run_scan

    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        for dest in (a, b):
            shutil.copy(FIXTURES / "vulnerable_rsa.py", Path(dest) / "vulnerable_rsa.py")
        fp = []
        for dest in (a, b):
            res = run_scan([dest], PqcConfig.default())
            doc = sarif_out.to_sarif(res, base_path=dest)
            fp.append({
                r["partialFingerprints"]["pqcScanFingerprint/v1"]
                for r in doc["runs"][0]["results"]
            })
        assert fp[0] == fp[1]


def test_sarif_validates_against_minimal_schema():
    """Structural validation of the fields GitHub's SARIF ingestion requires.

    Not the full 2.1.0 schema (which is ~500 KB and would be vendored), but a
    strict subset: any violation here would break upload/rendering on GitHub.
    """
    import jsonschema

    schema = {
        "type": "object",
        "required": ["version", "runs"],
        "properties": {
            "version": {"const": "2.1.0"},
            "runs": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["tool", "results"],
                    "properties": {
                        "tool": {
                            "type": "object",
                            "required": ["driver"],
                            "properties": {
                                "driver": {
                                    "type": "object",
                                    "required": ["name", "rules"],
                                    "properties": {
                                        "name": {"type": "string", "minLength": 1},
                                        "rules": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "required": ["id", "name", "shortDescription", "helpUri"],
                                                "properties": {
                                                    "shortDescription": {
                                                        "type": "object",
                                                        "required": ["text"],
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "results": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["ruleId", "level", "message", "locations"],
                                "properties": {
                                    "level": {"enum": ["error", "warning", "note", "none"]},
                                    "message": {"type": "object", "required": ["text"]},
                                    "locations": {
                                        "type": "array",
                                        "minItems": 1,
                                        "items": {
                                            "type": "object",
                                            "required": ["physicalLocation"],
                                            "properties": {
                                                "physicalLocation": {
                                                    "type": "object",
                                                    "required": ["artifactLocation", "region"],
                                                    "properties": {
                                                        "artifactLocation": {
                                                            "type": "object",
                                                            "required": ["uri"],
                                                        },
                                                        "region": {
                                                            "type": "object",
                                                            "required": ["startLine"],
                                                            "properties": {
                                                                "startLine": {"type": "integer", "minimum": 1},
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    jsonschema.validate(sarif_out.to_sarif(_result()), schema)
