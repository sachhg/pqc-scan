"""Core data model and shared scaffolding for every pqc-scan scanner.

This module is intentionally free of any tree-sitter / parsing dependency so that
the AST scanner, the config-file scanner and the dependency scanner can all share
the same ``Finding`` factory. Language rule modules compute line/column/snippet
from their own parse trees and hand the primitives to :func:`build_finding`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# Severity / confidence / category vocabularies
# --------------------------------------------------------------------------- #

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

#: Higher number == more severe. Used for thresholding and sorting.
SEVERITY_ORDER: dict[str, int] = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
}

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# Finding categories (also surface in the CBOM as crypto primitives).
CATEGORY_KEY_GENERATION = "key-generation"
CATEGORY_SIGNING = "signing"
CATEGORY_ENCRYPTION = "encryption"
CATEGORY_HASHING = "hashing"
CATEGORY_KEY_EXCHANGE = "key-exchange"
CATEGORY_CONFIGURATION = "configuration"
CATEGORY_DEPENDENCY = "dependency"


def severity_rank(severity: str) -> int:
    """Return a sortable integer for *severity* (unknown values rank lowest)."""
    return SEVERITY_ORDER.get(severity, 0)


def meets_threshold(severity: str, threshold: str) -> bool:
    """True when *severity* is at least as severe as *threshold*."""
    return severity_rank(severity) >= severity_rank(threshold)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class MigrationSuggestion:
    """Quantum-safe migration guidance attached to every finding."""

    recommended_algorithm: str
    recommended_library: str
    migration_description: str
    code_example: str
    nist_standard: str
    docs_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single quantum-vulnerable cryptography detection."""

    file_path: str
    line_number: int
    column_number: int
    algorithm: str
    category: str
    severity: str
    confidence: str
    description: str
    code_snippet: str
    migration_suggestion: MigrationSuggestion
    rule_id: str
    #: Optional hint distinguishing library-implementation code from
    #: application usage (see scanner/context.py). None when no signal fired.
    context_hint: Optional[str] = None

    # ----- convenience helpers -------------------------------------------- #

    @property
    def severity_rank(self) -> int:
        return severity_rank(self.severity)

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line_number}:{self.column_number}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


def finding_sort_key(finding: Finding) -> tuple:
    """Sort most-severe first, then by file / line / column for stable output."""
    return (
        -severity_rank(finding.severity),
        finding.file_path,
        finding.line_number,
        finding.column_number,
        finding.rule_id,
    )


# --------------------------------------------------------------------------- #
# Rule registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RuleDef:
    """Static metadata for a detection rule (PQC001 .. PQC014)."""

    rule_id: str
    name: str
    description: str
    default_severity: str
    category: str
    primitive: str  # CBOM primitive: pke | signature | hash | key-agree | block-cipher | protocol
    algorithm_family: str  # key into the migration-suggestion registry
    help_uri: str = "https://github.com/pqc-scan/pqc-scan#rules"


RULES: dict[str, RuleDef] = {
    "PQC001": RuleDef(
        rule_id="PQC001",
        name="RSA Key Generation",
        description="RSA key generation detected. RSA is broken by Shor's algorithm on a "
        "cryptographically relevant quantum computer, regardless of key size.",
        default_severity=SEVERITY_CRITICAL,
        category=CATEGORY_KEY_GENERATION,
        primitive="pke",
        algorithm_family="rsa",
    ),
    "PQC002": RuleDef(
        rule_id="PQC002",
        name="RSA Encryption / Padding",
        description="RSA-based encryption or padding (OAEP / PKCS1v15) detected. RSA "
        "encryption is broken by Shor's algorithm.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_ENCRYPTION,
        primitive="pke",
        algorithm_family="rsa-encryption",
    ),
    "PQC003": RuleDef(
        rule_id="PQC003",
        name="RSA Signature",
        description="RSA signature operation detected. RSA signatures are forgeable once a "
        "quantum computer can run Shor's algorithm.",
        default_severity=SEVERITY_CRITICAL,
        category=CATEGORY_SIGNING,
        primitive="signature",
        algorithm_family="rsa-signature",
    ),
    "PQC004": RuleDef(
        rule_id="PQC004",
        name="ECDSA Key Generation or Signing",
        description="Elliptic-curve key generation or ECDSA signing detected. Elliptic-curve "
        "cryptography is broken by Shor's algorithm.",
        default_severity=SEVERITY_CRITICAL,
        category=CATEGORY_SIGNING,
        primitive="signature",
        algorithm_family="ecdsa",
    ),
    "PQC005": RuleDef(
        rule_id="PQC005",
        name="ECDH / X25519 Key Exchange",
        description="Elliptic-curve Diffie-Hellman (ECDH / X25519) key exchange detected. "
        "ECDH shared secrets are recoverable by Shor's algorithm and are a prime "
        "'harvest now, decrypt later' target.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_KEY_EXCHANGE,
        primitive="key-agree",
        algorithm_family="ecdh",
    ),
    "PQC006": RuleDef(
        rule_id="PQC006",
        name="Ed25519 / Ed448 Key Generation",
        description="Edwards-curve signature key (Ed25519 / Ed448) detected. Although modern, "
        "it is still elliptic-curve and broken by Shor's algorithm.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_SIGNING,
        primitive="signature",
        algorithm_family="ed25519",
    ),
    "PQC007": RuleDef(
        rule_id="PQC007",
        name="Diffie-Hellman Key Exchange",
        description="Classical Diffie-Hellman (DH / DHE) key exchange detected. DH shared "
        "secrets are recoverable by Shor's algorithm.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_KEY_EXCHANGE,
        primitive="key-agree",
        algorithm_family="dh",
    ),
    "PQC008": RuleDef(
        rule_id="PQC008",
        name="DSA Key Generation or Signing",
        description="DSA key generation or signing detected. DSA is broken by Shor's algorithm.",
        default_severity=SEVERITY_CRITICAL,
        category=CATEGORY_SIGNING,
        primitive="signature",
        algorithm_family="dsa",
    ),
    "PQC009": RuleDef(
        rule_id="PQC009",
        name="SHA-1 Usage",
        description="SHA-1 detected. SHA-1 is classically broken (practical collisions) and "
        "offers no quantum margin; Grover's algorithm further halves its security.",
        default_severity=SEVERITY_MEDIUM,
        category=CATEGORY_HASHING,
        primitive="hash",
        algorithm_family="sha1",
    ),
    "PQC010": RuleDef(
        rule_id="PQC010",
        name="MD5 Usage",
        description="MD5 detected. MD5 is comprehensively broken and must not be used for any "
        "security purpose.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_HASHING,
        primitive="hash",
        algorithm_family="md5",
    ),
    "PQC011": RuleDef(
        rule_id="PQC011",
        name="Weak JWT Algorithm",
        description="JWT signed with an asymmetric algorithm (RS256 / ES256 / PS256). The "
        "underlying RSA/ECDSA key is quantum-vulnerable.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_SIGNING,
        primitive="signature",
        algorithm_family="jwt-asymmetric",
    ),
    "PQC012": RuleDef(
        rule_id="PQC012",
        name="Weak TLS Configuration",
        description="TLS/SSL configuration enables quantum-vulnerable cipher suites or "
        "outdated protocol versions.",
        default_severity=SEVERITY_MEDIUM,
        category=CATEGORY_CONFIGURATION,
        primitive="protocol",
        algorithm_family="tls-config",
    ),
    "PQC013": RuleDef(
        rule_id="PQC013",
        name="DES / 3DES Usage",
        description="DES or Triple-DES detected. Both are classically weak; their small key "
        "sizes are further eroded by Grover's algorithm.",
        default_severity=SEVERITY_HIGH,
        category=CATEGORY_ENCRYPTION,
        primitive="block-cipher",
        algorithm_family="des",
    ),
    "PQC014": RuleDef(
        rule_id="PQC014",
        name="Quantum-Vulnerable Dependency",
        description="A dependency whose primary purpose is quantum-vulnerable cryptography was "
        "declared. Verify how it is used and plan migration.",
        default_severity=SEVERITY_MEDIUM,
        category=CATEGORY_DEPENDENCY,
        primitive="pke",
        algorithm_family="dependency",
    ),
}


def all_rules() -> list[RuleDef]:
    """Return rule definitions ordered by rule id."""
    return [RULES[rid] for rid in sorted(RULES)]


# --------------------------------------------------------------------------- #
# Finding factory
# --------------------------------------------------------------------------- #


def build_finding(
    *,
    rule_id: str,
    file_path: str | Path,
    line_number: int,
    column_number: int,
    algorithm: str,
    code_snippet: str,
    severity: str | None = None,
    confidence: str = CONFIDENCE_HIGH,
    category: str | None = None,
    description: str | None = None,
    migration: MigrationSuggestion | None = None,
    context_hint: str | None = None,
) -> Finding:
    """Construct a :class:`Finding`, filling defaults from the rule registry.

    ``severity``/``category``/``description`` override the rule defaults so a
    scanner can elevate (e.g. SHA-1 in a certificate) or demote (e.g. crypto in
    test code) a finding based on local context. ``migration`` is looked up from
    the rule's ``algorithm_family`` when not supplied.
    """
    rule = RULES[rule_id]
    if migration is None:
        # Lazy import keeps this module free of the migration package at import
        # time (migration.suggestions imports MigrationSuggestion from here).
        from pqcscan.migration.suggestions import get_suggestion

        migration = get_suggestion(rule.algorithm_family)
    return Finding(
        file_path=str(file_path),
        line_number=line_number,
        column_number=column_number,
        algorithm=algorithm,
        category=category or rule.category,
        severity=severity or rule.default_severity,
        confidence=confidence,
        description=description or rule.description,
        code_snippet=code_snippet,
        migration_suggestion=migration,
        rule_id=rule_id,
        context_hint=context_hint,
    )


# --------------------------------------------------------------------------- #
# Scanner base class
# --------------------------------------------------------------------------- #


@dataclass
class ScanContext:
    """Carries cross-cutting options into individual scanners."""

    severity_threshold: str = SEVERITY_LOW
    disabled_rules: frozenset[str] = field(default_factory=frozenset)

    def rule_enabled(self, rule_id: str) -> bool:
        # Rule ids are upper-case (PQC001); normalize so a config that lists
        # "pqc010" still disables the rule.
        return rule_id.upper() not in {r.upper() for r in self.disabled_rules}


class BaseScanner(ABC):
    """Abstract base every concrete scanner implements."""

    #: Human-friendly scanner name.
    name: str = "base"

    @abstractmethod
    def supports(self, path: Path) -> bool:
        """Return True when this scanner knows how to handle *path*."""

    @abstractmethod
    def scan_file(self, path: Path) -> list[Finding]:
        """Scan a single file and return the findings it contains."""
