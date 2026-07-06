"""Java detection rules.

Detects quantum-vulnerable cryptography in Java source via tree-sitter node
traversal. Java's crypto surface is overwhelmingly the JCA factory pattern:
``KeyPairGenerator.getInstance("RSA")``, ``Signature.getInstance("SHA256withRSA")``,
``MessageDigest.getInstance("SHA-1")``, ``Cipher.getInstance("RSA/ECB/...")`` and
friends. The algorithm being requested is therefore (almost) always the first
quoted string argument, and the relevant factory is the receiver class name.

Public surface (consumed by ``ast_scanner``):

* ``LANGUAGE``     - language id
* ``EXTENSIONS``   - file suffixes this module handles
* ``GRAMMAR``      - the tree-sitter language factory module name
* ``analyze(root, source_text, file_path) -> list[Finding]``
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pqcscan.scanner.base import (
    CATEGORY_CONFIGURATION,
    CATEGORY_ENCRYPTION,
    CATEGORY_HASHING,
    CATEGORY_KEY_EXCHANGE,
    CATEGORY_KEY_GENERATION,
    CATEGORY_SIGNING,
    CONFIDENCE_HIGH,
    SEVERITY_HIGH,
    Finding,
    build_finding,
)

from . import _helpers as h

LANGUAGE = "java"
EXTENSIONS = {".java"}
GRAMMAR = "tree_sitter_java"

# --------------------------------------------------------------------------- #
# Lookup tables (keyed on the UPPER-CASED algorithm string, prefix-tolerant)
# --------------------------------------------------------------------------- #

# KeyPairGenerator.getInstance(...) / KeyFactory.getInstance(...): the requested
# algorithm names a public-key family. Matched by exact upper-cased token.
KEYPAIR_ALGORITHMS: dict[str, tuple[str, str]] = {
    "RSA": ("PQC001", "RSA"),
    "RSASSA-PSS": ("PQC001", "RSA"),
    "EC": ("PQC004", "EC"),
    "ECDSA": ("PQC004", "ECDSA"),
    "ECDH": ("PQC005", "ECDH"),
    "XDH": ("PQC005", "XDH"),
    "X25519": ("PQC005", "X25519"),
    "X448": ("PQC005", "X448"),
    "DSA": ("PQC008", "DSA"),
    "DH": ("PQC007", "DH"),
    "DIFFIEHELLMAN": ("PQC007", "DH"),
    "EDDSA": ("PQC006", "EdDSA"),
    "ED25519": ("PQC006", "Ed25519"),
    "ED448": ("PQC006", "Ed448"),
}

# KeyFactory only covers the asymmetric key families (no DH/DHE here in the
# task spec), but the KeyPairGenerator table is a strict superset, so we reuse
# it and simply narrow the factory class names below.

# Receiver class names (the tail of the dotted object) that act as a JCA factory.
KEYPAIR_FACTORIES = {"KeyPairGenerator"}
KEYFACTORY_FACTORIES = {"KeyFactory"}
SIGNATURE_FACTORIES = {"Signature"}
DIGEST_FACTORIES = {"MessageDigest"}
CIPHER_FACTORIES = {"Cipher"}
KEYGEN_FACTORIES = {"KeyGenerator"}
KEYAGREEMENT_FACTORIES = {"KeyAgreement"}
SSLCONTEXT_FACTORIES = {"SSLContext"}

# SSLContext.getInstance(...) protocol strings that pin an outdated protocol.
# "TLS" / "TLSv1.2" / "TLSv1.3" negotiate modern versions and are not flagged.
LEGACY_SSLCONTEXT_PROTOCOLS = {"SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}

# Bouncy Castle lightweight-API class names -> (rule, algorithm label, category).
# These names are distinctive enough that `new <Class>(...)` is high confidence.
BOUNCY_CASTLE_CLASSES: dict[str, tuple[str, str, str]] = {
    "RSAKeyGenerationParameters": ("PQC001", "RSA (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "RSAKeyPairGenerator": ("PQC001", "RSA (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "RSAEngine": ("PQC002", "RSA (Bouncy Castle engine)", CATEGORY_ENCRYPTION),
    "RSADigestSigner": ("PQC003", "RSA signature (Bouncy Castle)", CATEGORY_SIGNING),
    "PSSSigner": ("PQC003", "RSA-PSS (Bouncy Castle)", CATEGORY_SIGNING),
    "ECKeyGenerationParameters": ("PQC004", "EC (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "ECKeyPairGenerator": ("PQC004", "EC (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "ECDSASigner": ("PQC004", "ECDSA (Bouncy Castle)", CATEGORY_SIGNING),
    "ECDHBasicAgreement": ("PQC005", "ECDH (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "ECDHCBasicAgreement": ("PQC005", "ECDHC (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "X25519KeyPairGenerator": ("PQC005", "X25519 (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "X25519Agreement": ("PQC005", "X25519 (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "X448KeyPairGenerator": ("PQC005", "X448 (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "X448Agreement": ("PQC005", "X448 (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "Ed25519KeyPairGenerator": ("PQC006", "Ed25519 (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "Ed25519Signer": ("PQC006", "Ed25519 (Bouncy Castle)", CATEGORY_SIGNING),
    "Ed448KeyPairGenerator": ("PQC006", "Ed448 (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "Ed448Signer": ("PQC006", "Ed448 (Bouncy Castle)", CATEGORY_SIGNING),
    "DHKeyGenerationParameters": ("PQC007", "DH (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "DHBasicAgreement": ("PQC007", "DH (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "DHKeyPairGenerator": ("PQC007", "DH (Bouncy Castle)", CATEGORY_KEY_EXCHANGE),
    "DSAKeyPairGenerator": ("PQC008", "DSA (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "DSAParametersGenerator": ("PQC008", "DSA (Bouncy Castle)", CATEGORY_KEY_GENERATION),
    "DSASigner": ("PQC008", "DSA (Bouncy Castle)", CATEGORY_SIGNING),
    "DSADigestSigner": ("PQC008", "DSA (Bouncy Castle)", CATEGORY_SIGNING),
}

# MessageDigest.getInstance(...) hash algorithms. Note SHA-256/384/512/SHA3 are
# deliberately ABSENT — they remain acceptable.
DIGEST_ALGORITHMS: dict[str, tuple[str, str]] = {
    "SHA-1": ("PQC009", "SHA-1"),
    "SHA1": ("PQC009", "SHA-1"),
    "MD5": ("PQC010", "MD5"),
    "MD2": ("PQC010", "MD2"),
    "MD4": ("PQC010", "MD4"),
}


class _JavaAnalyzer:
    def __init__(self, source_text: str, file_path: str):
        self.source = source_text
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

    # ----- finding helper ------------------------------------------------- #

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

    # ----- main traversal ------------------------------------------------- #

    def run(self, root) -> list[Finding]:
        for node in h.walk(root):
            if node.type == "method_invocation":
                self._inspect_invocation(node)
            elif node.type == "object_creation_expression":
                self._inspect_object_creation(node)
        return self.findings

    # ----- object creation (Bouncy Castle lightweight API) ---------------- #

    def _inspect_object_creation(self, node) -> None:
        type_node = h.field(node, "type")
        if type_node is None:
            for child in node.children:
                if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                    type_node = child
                    break
        if type_node is None:
            return
        # For scoped/generic types take the trailing simple name.
        type_name = h.text(type_node).split("<", 1)[0].rsplit(".", 1)[-1]
        entry = BOUNCY_CASTLE_CLASSES.get(type_name)
        if entry is None:
            return
        rule_id, label, category = entry
        self._add(rule_id, node, label, category=category)

    # ----- invocation detection ------------------------------------------ #

    def _inspect_invocation(self, call) -> None:
        name_node = h.field(call, "name")
        method = h.text(name_node) if name_node is not None else ""
        if not method:
            return

        # The receiver: KeyPairGenerator, javax.crypto.Cipher, etc. We care about
        # its tail identifier (the actual factory class name).
        obj = h.field(call, "object")
        obj_parts = h.dotted_parts(obj)
        factory = obj_parts[-1] if obj_parts else None

        # The algorithm string is (almost always) the FIRST string argument.
        alg = self._first_string_arg(call)

        if method == "getInstance":
            self._inspect_get_instance(call, factory, alg)

    def _inspect_get_instance(self, call, factory: Optional[str], alg: Optional[str]) -> None:
        if alg is None or factory is None:
            return
        upper = alg.upper()

        # --- KeyPairGenerator.getInstance("RSA"|"EC"|"DSA"|"DH"|...) ------- #
        if factory in KEYPAIR_FACTORIES:
            self._match_keypair(call, upper, alg)
            return

        # --- KeyFactory.getInstance("RSA"|"EC"|"DSA") --------------------- #
        if factory in KEYFACTORY_FACTORIES:
            # Same lookup; KeyFactory in practice only resolves the asymmetric
            # key families, all of which live in the shared table.
            self._match_keypair(call, upper, alg)
            return

        # --- KeyAgreement.getInstance("ECDH"|"DH"|"DiffieHellman"|"X25519") - #
        if factory in KEYAGREEMENT_FACTORIES:
            # Reuses the keypair table (ECDH->PQC005, DH->PQC007, etc.); the
            # category override to key-exchange happens in _keypair_category.
            self._match_keypair(call, upper, alg)
            return

        # --- Signature.getInstance("SHA256withRSA"|...) ------------------- #
        if factory in SIGNATURE_FACTORIES:
            self._match_signature(call, upper, alg)
            return

        # --- MessageDigest.getInstance("SHA-1"|"MD5") --------------------- #
        if factory in DIGEST_FACTORIES:
            self._match_digest(call, upper, alg)
            return

        # --- Cipher.getInstance("RSA/ECB/OAEPPadding"|"DES"|"DESede") ------ #
        if factory in CIPHER_FACTORIES:
            self._match_cipher(call, upper, alg)
            return

        # --- KeyGenerator.getInstance("DES"|"DESede") --------------------- #
        if factory in KEYGEN_FACTORIES:
            self._match_keygen(call, upper, alg)
            return

        # --- SSLContext.getInstance("SSLv3"|"TLSv1"|...) ------------------- #
        if factory in SSLCONTEXT_FACTORIES:
            if upper in LEGACY_SSLCONTEXT_PROTOCOLS:
                self._add(
                    "PQC012", call, f"Outdated TLS/SSL protocol: {alg}",
                    category=CATEGORY_CONFIGURATION, severity=SEVERITY_HIGH,
                )
            return

    # ----- per-factory matchers ------------------------------------------ #

    def _match_keypair(self, call, upper: str, alg: str) -> None:
        # Prefix-tolerant exact-token match: the algorithm string for these
        # factories is a bare family name, but be defensive about suffixes.
        token = upper.split("/", 1)[0]
        entry = KEYPAIR_ALGORITHMS.get(token) or KEYPAIR_ALGORITHMS.get(upper)
        if entry is None:
            return
        rule_id, label = entry
        self._add(rule_id, call, label, category=self._keypair_category(rule_id))

    @staticmethod
    def _keypair_category(rule_id: str) -> Optional[str]:
        # KeyPairGenerator/KeyFactory are key-material generation; preserve the
        # natural category for exchange families.
        if rule_id in ("PQC005", "PQC007"):
            return CATEGORY_KEY_EXCHANGE
        if rule_id == "PQC006":
            return CATEGORY_SIGNING
        return CATEGORY_KEY_GENERATION

    def _match_signature(self, call, upper: str, alg: str) -> None:
        # Signature algorithms read "<digest>with<key>" e.g. SHA256withRSA,
        # SHA1withDSA, NONEwithECDSA. Decide by the key half (suffix).
        if (
            "WITHRSA" in upper
            or upper.endswith("RSA")
            or upper.startswith("RSASSA")   # canonical RSA-PSS name: "RSASSA-PSS"
            or upper == "RSAPSS"
        ):
            self._add("PQC003", call, f"RSA signature: {alg}", category=CATEGORY_SIGNING)
            # A SHA-1 / MD5 signature ALSO drags in a broken digest.
            self._maybe_digest_in_signature(call, upper)
            return
        if "WITHECDSA" in upper or upper.endswith("ECDSA"):
            self._add("PQC004", call, f"ECDSA signature: {alg}", category=CATEGORY_SIGNING)
            self._maybe_digest_in_signature(call, upper)
            return
        if "WITHDSA" in upper or upper.endswith("WITHDSA"):
            self._add("PQC008", call, f"DSA signature: {alg}", category=CATEGORY_SIGNING)
            self._maybe_digest_in_signature(call, upper)
            return
        if "WITHEDDSA" in upper or upper in ("ED25519", "ED448", "EDDSA"):
            self._add("PQC006", call, f"EdDSA signature: {alg}", category=CATEGORY_SIGNING)
            return

    def _maybe_digest_in_signature(self, call, upper: str) -> None:
        # SHA1withRSA / MD5withRSA: surface the weak digest as its own finding.
        head = upper.split("WITH", 1)[0]
        if head in ("SHA1", "SHA-1"):
            self._add("PQC009", call, "SHA-1", category=CATEGORY_HASHING)
        elif head in ("MD5", "MD2", "MD4"):
            self._add("PQC010", call, "MD5", category=CATEGORY_HASHING)

    def _match_digest(self, call, upper: str, alg: str) -> None:
        entry = DIGEST_ALGORITHMS.get(upper)
        if entry is None:
            return
        rule_id, label = entry
        self._add(rule_id, call, label, category=CATEGORY_HASHING)

    def _match_cipher(self, call, upper: str, alg: str) -> None:
        # Cipher transformation strings are "<alg>/<mode>/<padding>"; match on
        # the leading algorithm token, prefix-tolerant.
        token = upper.split("/", 1)[0]
        if token == "RSA":
            self._add("PQC002", call, f"RSA cipher: {alg}", category=CATEGORY_ENCRYPTION)
            return
        # DESede (Triple-DES) must be checked BEFORE DES (it startswith "DES").
        if token == "DESEDE" or token.startswith("DESEDE"):
            self._add("PQC013", call, "3DES", category=CATEGORY_ENCRYPTION)
            return
        if token == "DES" or token.startswith("DES"):
            self._add("PQC013", call, "DES", category=CATEGORY_ENCRYPTION)
            return

    def _match_keygen(self, call, upper: str, alg: str) -> None:
        token = upper.split("/", 1)[0]
        if token == "DESEDE" or token.startswith("DESEDE"):
            self._add("PQC013", call, "3DES", category=CATEGORY_ENCRYPTION)
            return
        if token == "DES" or token.startswith("DES"):
            self._add("PQC013", call, "DES", category=CATEGORY_ENCRYPTION)
            return

    # ----- argument extraction ------------------------------------------- #

    def _first_string_arg(self, call) -> Optional[str]:
        """Return the inner text of the first ``string_literal`` argument.

        ``_helpers.string_value`` does not know Java's ``string_literal`` node
        type, so we extract the ``string_fragment`` child ourselves (and fall
        back to stripping the surrounding quotes for empty strings).
        """
        args = h.call_arguments(call)
        if args is None:
            return None
        for child in args.children:
            if child.type == "string_literal":
                return _string_literal_value(child)
        return None


def _string_literal_value(node) -> str:
    """Inner text of a Java ``string_literal`` node."""
    for child in node.children:
        if child.type == "string_fragment":
            return h.text(child)
    # Empty string ("") or escape-only literal: strip the surrounding quotes.
    return h.text(node).strip('"')


def analyze(root, source_text: str, file_path: str | Path) -> list[Finding]:
    """Entry point used by the AST scanner."""
    return _JavaAnalyzer(source_text, str(file_path)).run(root)
