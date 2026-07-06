"""SARIF 2.1.0 output for GitHub code scanning.

GitHub turns SARIF into inline PR annotations, so the migration guidance is
embedded directly in ``message.text`` (what the annotation shows) and in
structured ``result.properties``. No ``fixes`` are emitted: a SARIF fix requires
concrete ``artifactChanges`` a detector cannot synthesize for a crypto
migration. ``security-severity`` is set on each rule so GitHub maps findings
onto its critical/high/medium/low scale.

URIs are emitted relative to ``base_path`` (the caller's CWD — the repo root in
CI) with the scan root as fallback, because GitHub cannot render absolute or
escaping paths. Fingerprints hash the *relative* URI so they are stable across
checkout directories and runners.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from pqcscan import __version__
from pqcscan.scanner.base import RULES, Finding, all_rules
from pqcscan.scanner.engine import ScanResult

INFORMATION_URI = "https://github.com/pqc-scan/pqc-scan"

# SARIF level per finding severity.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# GitHub security-severity (numeric, 0-10) per rule default severity.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}


def _rel_uri(file_path: str, base_path: str, root_path: str = "") -> str:
    """Relative URI for *file_path*: relative to *base_path* when it does not
    escape it, else relative to *root_path*, else the path as given."""
    for base in (base_path, root_path):
        if not base:
            continue
        try:
            rel = os.path.relpath(file_path, base)
        except ValueError:  # different drive on Windows
            continue
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    return file_path.replace(os.sep, "/")


def _rule_descriptor(rule) -> dict[str, Any]:
    return {
        "id": rule.rule_id,
        "name": rule.name.replace(" ", ""),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "helpUri": rule.help_uri,
        "help": {
            "text": rule.description,
            "markdown": f"**{rule.name}**\n\n{rule.description}",
        },
        "defaultConfiguration": {"level": _LEVEL.get(rule.default_severity, "warning")},
        "properties": {
            "tags": ["security", "cryptography", "post-quantum", "external/cwe/cwe-327"],
            "security-severity": _SECURITY_SEVERITY.get(rule.default_severity, "5.0"),
            "category": rule.category,
            "primitive": rule.primitive,
        },
    }


def _message_text(f: Finding) -> str:
    mig = f.migration_suggestion
    parts = [f"{f.description} (detected: {f.algorithm})"]
    if mig:
        parts.append(f"Migrate to {mig.recommended_algorithm} [{mig.nist_standard}].")
        parts.append(f"Library: {mig.recommended_library}")
        parts.append(f"Docs: {mig.docs_url}")
    return " ".join(parts)


def _fingerprint(f: Finding, uri: str) -> str:
    # Hash the RELATIVE uri (not the absolute path) so the fingerprint is
    # stable across machines/checkout dirs; omit line numbers so it survives
    # unrelated edits above the finding.
    raw = f"{f.rule_id}|{uri}|{f.algorithm}|{f.code_snippet}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _result(f: Finding, rule_index: dict[str, int], base_path: str, root_path: str) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": max(1, f.line_number),
        "startColumn": max(1, f.column_number),
    }
    snippet = (f.code_snippet or "").strip()
    if snippet:
        region["snippet"] = {"text": snippet}

    uri = _rel_uri(f.file_path, base_path, root_path)
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index.get(f.rule_id, 0),
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": _message_text(f)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {"pqcScanFingerprint/v1": _fingerprint(f, uri)},
        "properties": {
            "severity": f.severity,
            "confidence": f.confidence,
            "algorithm": f.algorithm,
            "category": f.category,
            "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
        },
    }
    if f.context_hint:
        result["properties"]["contextHint"] = f.context_hint
    if f.migration_suggestion:
        # NOTE: A SARIF `fix` requires concrete `artifactChanges` (actual text
        # edits), which a detector cannot synthesize for a crypto migration.
        # Emitting a fix without them produces schema-invalid SARIF, so the
        # migration guidance is surfaced in message.text, rule.help and these
        # structured properties instead.
        mig = f.migration_suggestion
        result["properties"]["migration"] = {
            "recommendedAlgorithm": mig.recommended_algorithm,
            "recommendedLibrary": mig.recommended_library,
            "nistStandard": mig.nist_standard,
            "docsUrl": mig.docs_url,
            "codeExample": mig.code_example,
        }
    return result


def to_sarif(result: ScanResult, *, base_path: str = ".") -> dict[str, Any]:
    rules = all_rules()
    rule_index = {rule.rule_id: i for i, rule in enumerate(rules)}
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-scan",
                        "informationUri": INFORMATION_URI,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": [_rule_descriptor(r) for r in rules],
                    }
                },
                "results": [
                    _result(f, rule_index, base_path, result.root_path)
                    for f in result.findings
                ],
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


def to_sarif_json(result: ScanResult, *, base_path: str = ".", indent: int = 2) -> str:
    return json.dumps(to_sarif(result, base_path=base_path), indent=indent)
