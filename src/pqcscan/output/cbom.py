"""CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) output.

Findings are grouped into ``cryptographic-asset`` components (one per distinct
algorithm / parameter set), each carrying ``cryptoProperties`` and the source
occurrences where it was found. TLS configuration findings become ``protocol``
assets; flagged dependencies become ``library`` components marked
quantum-vulnerable.

Field note: CycloneDX 1.6 names the post-quantum security field
``nistQuantumSecurityLevel`` (0-6). The spec text called it ``quantumSecurityLevel``;
we emit the schema-correct name so the document validates. All flagged algorithms
carry level ``0`` (no quantum security margin).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from pqcscan import __version__
from pqcscan.scanner.base import RULES, Finding
from pqcscan.scanner.engine import ScanResult

# Known OIDs by algorithm family / name fragment.
_OIDS = {
    "rsa": "1.2.840.113549.1.1.1",
    "ec": "1.2.840.10045.2.1",
    "ecdsa": "1.2.840.10045.2.1",
    "ecc": "1.2.840.10045.2.1",
    "dsa": "1.2.840.10040.4.1",
    "dh": "1.2.840.113549.1.3.1",
    "ed25519": "1.3.101.112",
    "ed448": "1.3.101.113",
    "x25519": "1.3.101.110",
    "x448": "1.3.101.111",
    "sha-1": "1.3.14.3.2.26",
    "md5": "1.2.840.113549.2.5",
    "des": "1.3.14.3.2.7",
    "3des": "1.2.840.113549.3.7",
}

# Classical security level (bits) lookup helpers.
_CURVE_CLASSICAL = {
    "P-192": 96, "P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256,
    "SECP256K1": 128, "PRIME256V1": 128,
}

# cryptoFunctions (CycloneDX 1.6 enum) per finding category.
_CATEGORY_FUNCTIONS = {
    "key-generation": ["keygen"],
    "signing": ["sign", "verify"],
    "encryption": ["encrypt", "decrypt"],
    "hashing": ["digest"],
    "key-exchange": ["keygen"],
}


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower() or "asset"


# Family -> OID (the rule's algorithm_family is the most reliable signal).
_FAMILY_OID = {
    "rsa": _OIDS["rsa"], "rsa-encryption": _OIDS["rsa"], "rsa-signature": _OIDS["rsa"],
    "ecdsa": _OIDS["ecdsa"], "ecc": _OIDS["ecc"], "ecdh": _OIDS["ec"],
    "ed25519": _OIDS["ed25519"], "x25519": _OIDS["x25519"],
    "dsa": _OIDS["dsa"], "dh": _OIDS["dh"],
    "sha1": _OIDS["sha-1"], "md5": _OIDS["md5"], "des": _OIDS["des"],
}


def _oid_for(algorithm: str, family: str) -> Optional[str]:
    """Resolve an OID, preferring explicit name tokens then the rule family.

    Substring matching against the flat ``_OIDS`` table is unsafe (``"eddsa"``
    contains ``"dsa"``; ``"sha1WithRSAEncryption"`` contains ``"rsa"``), so we
    match the most specific algorithm names first and fall back to the family.
    """
    up = algorithm.upper()
    if "ED25519" in up:
        return _OIDS["ed25519"]
    if "ED448" in up:
        return _OIDS["ed448"]
    if "X25519" in up:
        return _OIDS["x25519"]
    if "X448" in up:
        return _OIDS["x448"]
    if "SHA-1" in up or up.startswith("SHA1") or "SHA1WITH" in up:
        return _OIDS["sha-1"]
    if "MD5" in up:
        return _OIDS["md5"]
    if "3DES" in up:
        return _OIDS["3des"]
    return _FAMILY_OID.get(family)


def _classical_level(algorithm: str, family: str) -> Optional[int]:
    up = algorithm.upper()
    if family in ("rsa", "rsa-encryption", "rsa-signature") or up.startswith("RSA"):
        m = re.search(r"(\d{3,5})", algorithm)
        if m:
            bits = int(m.group(1))
            return {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192}.get(bits, 112)
        return 112
    for curve, level in _CURVE_CLASSICAL.items():
        if curve in up:
            return level
    if "X25519" in up or "ED25519" in up:
        return 128
    if "X448" in up or "ED448" in up:
        return 224
    if family in ("ecdsa", "ecc", "ecdh") or up.startswith(("ECDSA", "ECC", "EC-")):
        return 128
    if family == "dsa":
        return 112
    if family == "dh":
        return 112
    if "SHA-1" in up or family == "sha1":
        return 80
    if "MD5" in up or family == "md5":
        return 0
    if "3DES" in up:
        return 112
    if up == "DES" or family == "des":
        return 56
    return None


_CURVE_LABELS = {
    "P-192": "P-192", "P-224": "P-224", "P-256": "P-256", "P-384": "P-384",
    "P-521": "P-521", "SECP256K1": "secp256k1", "PRIME256V1": "prime256v1",
}


def _parameter_set(algorithm: str, family: str) -> Optional[str]:
    """Return a meaningful parameter-set identifier, or None.

    Only emits a value when there is a genuine parameter set: an RSA key size, a
    named elliptic curve, or an Edwards/Montgomery curve name. Padding scheme
    suffixes (RSA-OAEP, RSA-PKCS1v15) and bare names are deliberately omitted.
    """
    up = algorithm.upper()
    if family in ("rsa", "rsa-encryption", "rsa-signature") or up.startswith("RSA"):
        m = re.search(r"RSA-(\d{3,5})\b", up)
        return m.group(1) if m else None
    for token, label in _CURVE_LABELS.items():
        if token in up:
            return label
    if "ED25519" in up:
        return "Ed25519"
    if "ED448" in up:
        return "Ed448"
    if "X25519" in up:
        return "X25519"
    if "X448" in up:
        return "X448"
    return None


def _primitive_for(rule_primitive: str) -> str:
    # Map our internal primitive labels onto valid CycloneDX values.
    return {
        "pke": "pke",
        "signature": "signature",
        "hash": "hash",
        "key-agree": "key-agree",
        "block-cipher": "block-cipher",
    }.get(rule_primitive, "unknown")


class _Asset:
    def __init__(self, kind: str, name: str):
        self.kind = kind  # "algorithm" | "protocol" | "library"
        self.name = name
        self.primitive: str = "unknown"
        self.family: str = ""
        self.parameter_set: Optional[str] = None
        self.classical_level: Optional[int] = None
        self.oid: Optional[str] = None
        self.functions: set[str] = set()
        self.occurrences: list[tuple[str, int]] = []


def _asset_key(f: Finding) -> tuple[str, str]:
    rule = RULES.get(f.rule_id)
    if rule and rule.category == "configuration":
        return ("protocol", "TLS")
    if rule and rule.category == "dependency":
        name = f.algorithm.split(":", 1)[-1].strip() or f.algorithm
        return ("library", name)
    return ("algorithm", f.algorithm)


def _rel_location(file_path: str, root_path: str) -> str:
    """Occurrence location relative to the scan root (portable across hosts)."""
    if root_path:
        try:
            rel = os.path.relpath(file_path, root_path)
        except ValueError:
            return file_path.replace(os.sep, "/")
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    return file_path.replace(os.sep, "/")


def _collect_assets(result: ScanResult) -> list[_Asset]:
    assets: dict[tuple[str, str], _Asset] = {}
    for f in result.findings:
        kind, name = _asset_key(f)
        asset = assets.get((kind, name))
        if asset is None:
            asset = _Asset(kind, name)
            rule = RULES.get(f.rule_id)
            asset.family = rule.algorithm_family if rule else ""
            asset.primitive = _primitive_for(rule.primitive if rule else "unknown")
            if kind == "algorithm":
                asset.parameter_set = _parameter_set(f.algorithm, asset.family)
                asset.classical_level = _classical_level(f.algorithm, asset.family)
                asset.oid = _oid_for(f.algorithm, asset.family)
            assets[(kind, name)] = asset
        asset.functions.update(_CATEGORY_FUNCTIONS.get(f.category, []))
        asset.occurrences.append((_rel_location(f.file_path, result.root_path), f.line_number))
    return list(assets.values())


def _component(asset: _Asset) -> dict[str, Any]:
    occurrences = [
        {"location": loc, "line": line} for loc, line in asset.occurrences
    ]
    evidence = {"occurrences": occurrences} if occurrences else None

    if asset.kind == "library":
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"library/{_slug(asset.name)}",
            "name": asset.name,
            "properties": [
                {"name": "pqc-scan:quantum-vulnerable", "value": "true"},
            ],
        }
        if evidence:
            comp["evidence"] = evidence
        return comp

    if asset.kind == "protocol":
        comp = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/protocol/{_slug(asset.name)}",
            "name": asset.name,
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {"type": "tls"},
            },
        }
        if evidence:
            comp["evidence"] = evidence
        return comp

    algo_props: dict[str, Any] = {
        "primitive": asset.primitive,
        "cryptoFunctions": sorted(asset.functions) or ["other"],
        "nistQuantumSecurityLevel": 0,
    }
    if asset.parameter_set:
        algo_props["parameterSetIdentifier"] = asset.parameter_set
    if asset.classical_level is not None:
        algo_props["classicalSecurityLevel"] = asset.classical_level

    crypto_props: dict[str, Any] = {
        "assetType": "algorithm",
        "algorithmProperties": algo_props,
    }
    if asset.oid:
        crypto_props["oid"] = asset.oid

    comp = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{_slug(asset.name)}",
        "name": asset.name,
        "cryptoProperties": crypto_props,
    }
    if evidence:
        comp["evidence"] = evidence
    return comp


def to_cbom(result: ScanResult, *, timestamp: Optional[str] = None) -> dict[str, Any]:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assets = _collect_assets(result)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-scan",
                        "version": __version__,
                        "description": "Developer-native scanner for quantum-vulnerable cryptography",
                    }
                ]
            },
        },
        "components": [_component(a) for a in assets],
    }


def to_cbom_json(result: ScanResult, *, timestamp: Optional[str] = None, indent: int = 2) -> str:
    return json.dumps(to_cbom(result, timestamp=timestamp), indent=indent)
