"""Go detection rules.

Detects quantum-vulnerable cryptography in Go source via tree-sitter node
traversal. Covers the Go standard library ``crypto/*`` packages (``rsa``,
``ecdsa``, ``ed25519``, ``dsa``, ``elliptic``, ``ecdh``, ``sha1``, ``md5``,
``des``) as well as ``golang.org/x/crypto`` packages (``curve25519``).

Public surface (consumed by ``ast_scanner``):

* ``LANGUAGE``     - language id
* ``EXTENSIONS``   - file suffixes this module handles
* ``GRAMMAR``      - the tree-sitter language factory module name
* ``analyze(root, source_text, file_path) -> list[Finding]``
"""

from __future__ import annotations

import re
from pathlib import Path

from pqcscan.scanner.base import (
    CATEGORY_CONFIGURATION,
    CATEGORY_KEY_EXCHANGE,
    CATEGORY_KEY_GENERATION,
    CATEGORY_SIGNING,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Finding,
    build_finding,
)

from . import _helpers as h

LANGUAGE = "go"
EXTENSIONS = {".go"}
GRAMMAR = "tree_sitter_go"

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #

# crypto/elliptic curve constructor -> friendly parameter-set label.
ELLIPTIC_CURVES = {
    "P224": "P-224",
    "P256": "P-256",
    "P384": "P-384",
    "P521": "P-521",
}

# crypto/ecdh curve constructors that yield NIST P-curve key-exchange keys.
ECDH_NIST_CURVES = {"P256", "P384", "P521"}

# crypto/tls protocol-version constants that pin an outdated protocol when
# assigned to MinVersion / MaxVersion (bare references, e.g. comparisons in
# feature-detection code, are deliberately not flagged).
LEGACY_TLS_VERSIONS = {
    "VersionSSL30": "SSLv3",
    "VersionTLS10": "TLS 1.0",
    "VersionTLS11": "TLS 1.1",
}
_TLS_VERSION_FIELDS = {"MinVersion", "MaxVersion"}

# JWT signing-method constants used by golang-jwt / jwt-go / go-jose wrappers.
_JWT_SIGNING_METHOD_RE = re.compile(
    r"^SigningMethod(?:(?:RS|ES|PS)(?:256|384|512)|EdDSA)$"
)

# JWT algorithm names accepted by jwt.GetSigningMethod("...").
GO_JWT_ASYMMETRIC_ALGS = {
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512", "EDDSA",
}


def _cipher_suite_severity(name: str) -> str | None:
    """Severity for a crypto/tls cipher-suite constant, or None when fine.

    TLS 1.3 suites (TLS_AES_*, TLS_CHACHA20_*) carry no key-exchange name and
    are not flagged. Static-RSA key transport and classically broken suites are
    high; ECDHE-with-RSA/ECDSA authentication is medium (PFS today, but the
    handshake is still quantum-vulnerable).
    """
    if not name.startswith("TLS_"):
        return None
    if any(tok in name for tok in ("_3DES_", "_RC4_", "_NULL_", "_EXPORT_")):
        return SEVERITY_HIGH
    if name.startswith("TLS_RSA_WITH_"):
        return SEVERITY_HIGH
    if any(tok in name for tok in ("_RSA_", "_ECDSA_", "_ECDHE_", "_DHE_")):
        return SEVERITY_MEDIUM
    return None


class _GoAnalyzer:
    def __init__(self, source_text: str, file_path: str):
        self.source = source_text
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

    # ----- finding helpers ------------------------------------------------ #

    def _add(self, rule_id: str, node, algorithm: str, **kwargs) -> None:
        line, col = h.line_col(node)
        key = (rule_id, line, col)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            build_finding(
                rule_id=rule_id,
                file_path=self.file_path,
                line_number=line,
                column_number=col,
                algorithm=algorithm,
                code_snippet=h.snippet(node),
                **kwargs,
            )
        )

    # ----- main traversal ------------------------------------------------ #

    def run(self, root) -> list[Finding]:
        for node in h.walk(root):
            ntype = node.type
            if ntype == "call_expression":
                self._inspect_call(node)
            elif ntype == "composite_literal":
                self._inspect_composite(node)
            elif ntype == "assignment_statement":
                self._inspect_assignment(node)
            elif ntype == "selector_expression":
                self._inspect_selector(node)
        return self.findings

    # ----- tls.Config literals / assignments ------------------------------ #

    def _inspect_composite(self, literal) -> None:
        """Flag MinVersion/MaxVersion pins and weak CipherSuites in tls.Config{...}."""
        type_node = h.field(literal, "type")
        parts = h.dotted_parts(type_node) if type_node is not None else []
        if len(parts) < 2 or parts[-2] != "tls" or parts[-1] != "Config":
            return
        body = h.field(literal, "body")
        if body is None:
            return
        for element in body.children:
            if element.type != "keyed_element":
                continue
            named = [c for c in element.children if c.is_named]
            if len(named) < 2:
                continue
            key_text = h.text(named[0])
            if key_text in _TLS_VERSION_FIELDS:
                self._flag_legacy_version(named[1])
            elif key_text == "CipherSuites":
                self._flag_weak_suites(named[1])

    def _inspect_assignment(self, stmt) -> None:
        """Flag cfg.MinVersion = tls.VersionTLS10 style assignments."""
        left = h.field(stmt, "left")
        right = h.field(stmt, "right")
        if left is None or right is None:
            return
        left_parts = h.dotted_parts(
            left.children[0] if left.children else left
        )
        if not left_parts:
            return
        if left_parts[-1] in _TLS_VERSION_FIELDS:
            self._flag_legacy_version(right)
        elif left_parts[-1] == "CipherSuites":
            self._flag_weak_suites(right)

    def _flag_legacy_version(self, node) -> None:
        for sel in h.walk(node):
            if sel.type != "selector_expression":
                continue
            parts = h.dotted_parts(sel)
            if len(parts) >= 2 and parts[-2] == "tls" and parts[-1] in LEGACY_TLS_VERSIONS:
                self._add(
                    "PQC012", sel,
                    f"Outdated TLS protocol pinned: {LEGACY_TLS_VERSIONS[parts[-1]]}",
                    category=CATEGORY_CONFIGURATION, severity=SEVERITY_HIGH,
                )

    def _flag_weak_suites(self, node) -> None:
        for sel in h.walk(node):
            if sel.type != "selector_expression":
                continue
            parts = h.dotted_parts(sel)
            if len(parts) >= 2 and parts[-2] == "tls":
                severity = _cipher_suite_severity(parts[-1])
                if severity is not None:
                    self._add(
                        "PQC012", sel, f"TLS cipher suite: {parts[-1]}",
                        category=CATEGORY_CONFIGURATION, severity=severity,
                    )

    # ----- golang-jwt signing methods ------------------------------------- #

    def _inspect_selector(self, sel) -> None:
        """Flag jwt.SigningMethodRS256-style constants (golang-jwt / jwt-go)."""
        attr = h.field(sel, "field")
        name = h.text(attr) if attr is not None else ""
        if _JWT_SIGNING_METHOD_RE.match(name):
            self._add(
                "PQC011", sel, f"JWT signing method: {name.removeprefix('SigningMethod')}",
                category=CATEGORY_SIGNING,
            )

    # ----- call detection ------------------------------------------------ #

    def _inspect_call(self, call) -> None:
        fn = h.call_function(call)
        parts = h.dotted_parts(fn)
        if len(parts) < 2:
            return
        method = parts[-1]
        pkg = parts[-2]
        args = h.call_arguments(call)
        positionals = h.positional_args(args)

        # --- crypto/rsa --------------------------------------------------- #
        if pkg == "rsa":
            if method == "GenerateKey":
                bits = self._int_arg(positionals)
                self._add("PQC001", call, f"RSA-{bits}" if bits else "RSA")
                return
            if method in ("EncryptOAEP", "EncryptPKCS1v15", "DecryptOAEP",
                          "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey"):
                label = "RSA-OAEP" if "OAEP" in method else "RSA-PKCS1v15"
                self._add("PQC002", call, label)
                return
            if method in ("SignPKCS1v15", "SignPSS", "VerifyPKCS1v15", "VerifyPSS"):
                label = "RSA-PSS" if "PSS" in method else "RSA-PKCS1v15"
                self._add("PQC003", call, label)
                return

        # --- crypto/ecdsa ------------------------------------------------- #
        if pkg == "ecdsa":
            if method == "GenerateKey":
                curve = self._elliptic_curve(positionals)
                self._add("PQC004", call, f"ECDSA-{curve}" if curve else "ECDSA")
                return
            if method in ("Sign", "SignASN1"):
                self._add("PQC004", call, "ECDSA", category=CATEGORY_SIGNING)
                return
            if method in ("Verify", "VerifyASN1"):
                self._add("PQC004", call, "ECDSA", category=CATEGORY_SIGNING)
                return

        # --- crypto/ecdh -------------------------------------------------- #
        if pkg == "ecdh":
            if method in ECDH_NIST_CURVES:
                curve = ELLIPTIC_CURVES.get(method, method)
                self._add("PQC005", call, f"ECDH-{curve}", category=CATEGORY_KEY_EXCHANGE)
                return
            if method == "X25519":
                self._add("PQC005", call, "X25519", category=CATEGORY_KEY_EXCHANGE)
                return

        # --- golang.org/x/crypto/curve25519 ------------------------------ #
        if pkg == "curve25519":
            # curve25519.X25519 / .ScalarMult / .ScalarBaseMult
            self._add("PQC005", call, "X25519", category=CATEGORY_KEY_EXCHANGE)
            return

        # --- crypto/ed25519 ---------------------------------------------- #
        if pkg == "ed25519":
            if method == "GenerateKey":
                self._add("PQC006", call, "Ed25519", category=CATEGORY_KEY_GENERATION)
                return
            if method in ("Sign", "Verify", "VerifyWithOptions"):
                self._add("PQC006", call, "Ed25519")
                return
            if method == "NewKeyFromSeed":
                self._add("PQC006", call, "Ed25519", category=CATEGORY_KEY_GENERATION)
                return

        # --- crypto/dsa --------------------------------------------------- #
        if pkg == "dsa":
            if method in ("GenerateKey", "GenerateParameters"):
                self._add("PQC008", call, "DSA", category=CATEGORY_KEY_GENERATION)
                return
            if method in ("Sign", "Verify"):
                self._add("PQC008", call, "DSA")
                return

        # --- crypto/sha1 -------------------------------------------------- #
        if pkg == "sha1" and method in ("New", "Sum", "Sum256"):
            self._add("PQC009", call, "SHA-1")
            return

        # --- crypto/md5 --------------------------------------------------- #
        if pkg == "md5" and method in ("New", "Sum"):
            self._add("PQC010", call, "MD5")
            return

        # --- crypto/des --------------------------------------------------- #
        if pkg == "des":
            if method == "NewTripleDESCipher":
                self._add("PQC013", call, "3DES")
                return
            if method == "NewCipher":
                self._add("PQC013", call, "DES")
                return

        # --- golang-jwt: jwt.GetSigningMethod("RS256") --------------------- #
        if method == "GetSigningMethod":
            for arg in positionals:
                val = h.string_value(arg)
                if val and val.upper() in GO_JWT_ASYMMETRIC_ALGS:
                    self._add("PQC011", call, f"JWT signing method: {val}",
                              category=CATEGORY_SIGNING)
                    return

    # ----- small extraction utilities ----------------------------------- #

    @staticmethod
    def _int_arg(positionals) -> str | None:
        """First ``int_literal`` argument's source text (e.g. RSA key size)."""
        for arg in positionals:
            if arg.type == "int_literal":
                return h.text(arg)
        return None

    @staticmethod
    def _elliptic_curve(positionals) -> str | None:
        """Map an ``elliptic.Pxxx()`` argument to a friendly curve label."""
        for arg in positionals:
            parts = h.dotted_parts(arg)
            if len(parts) >= 2 and parts[-2] == "elliptic":
                label = ELLIPTIC_CURVES.get(parts[-1])
                if label:
                    return label
            if parts and parts[-1] in ELLIPTIC_CURVES:
                return ELLIPTIC_CURVES[parts[-1]]
        return None


def analyze(root, source_text: str, file_path: str | Path) -> list[Finding]:
    """Entry point used by the AST scanner."""
    return _GoAnalyzer(source_text, str(file_path)).run(root)
