"""JavaScript / Node.js detection rules.

Detects quantum-vulnerable cryptography in JavaScript (and, best-effort, the
TypeScript dialects via the JS grammar's error recovery) using tree-sitter node
traversal. Covers the Node.js ``crypto`` module, the WebCrypto ``crypto.subtle``
API, ``jsonwebtoken``, ``node-forge`` and a set of precise indirect
string-literal patterns (algorithm / curve choices stored in variables).

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
    CATEGORY_KEY_EXCHANGE,
    CATEGORY_KEY_GENERATION,
    CATEGORY_SIGNING,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Finding,
    build_finding,
)

from . import _helpers as h

LANGUAGE = "javascript"
EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
GRAMMAR = "tree_sitter_javascript"

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #

# JWT/JWS asymmetric (quantum-vulnerable) algorithm identifiers. HS256 & friends
# are symmetric (HMAC) and intentionally absent.
JWT_ASYMMETRIC_ALGS = {
    "RS256", "RS384", "RS512",
    "ES256", "ES256K", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EDDSA",
    "RSA-OAEP", "RSA-OAEP-256", "RSA1_5",
}

# WebCrypto SubtleCrypto algorithm names.
WEBCRYPTO_RSA_ENC = {"RSA-OAEP"}                       # -> PQC002 (encryption)
WEBCRYPTO_RSA_SIG = {"RSA-PSS", "RSASSA-PKCS1-V1_5"}    # -> PQC003 (signature)
WEBCRYPTO_ECDSA = {"ECDSA"}                            # -> PQC004
WEBCRYPTO_ECDH = {"ECDH", "X25519"}                    # -> PQC005
WEBCRYPTO_EDDSA = {"ED25519", "ED448", "EDDSA"}        # -> PQC006

# Hash digest names worth flagging in a crypto.createHash() context.
WEAK_HASH_NAMES = {
    "md5": ("PQC010", "MD5"),
    "md5-sha1": ("PQC010", "MD5"),
    "sha1": ("PQC009", "SHA-1"),
    "sha-1": ("PQC009", "SHA-1"),
}

# Named-curve string values worth flagging in a crypto context.
EC_CURVE_STRINGS = {
    "secp256k1", "secp256r1", "secp384r1", "secp521r1", "secp224r1", "secp192r1",
    "p-256", "p-384", "p-521", "p-224", "p-192",
    "p256", "p384", "p521",
    "prime256v1", "prime192v1",
    "nistp256", "nistp384", "nistp521",
}

# Variable / property names whose string value we treat as an algorithm choice.
ALG_NAME_KEYS = {"algorithm", "algorithms", "alg", "jwtalgorithm"}
CURVE_NAME_KEYS = {"curve", "namedcurve", "ec_curve", "eccurve"}

# AWS KMS asymmetric key specs (CreateKey KeySpec / CustomerMasterKeySpec).
KEYSPEC_NAME_KEYS = {"keyspec", "customermasterkeyspec"}
AWS_KEYSPEC_VALUES = {
    "RSA_2048": ("PQC001", "RSA-2048 (AWS KMS KeySpec)"),
    "RSA_3072": ("PQC001", "RSA-3072 (AWS KMS KeySpec)"),
    "RSA_4096": ("PQC001", "RSA-4096 (AWS KMS KeySpec)"),
    "ECC_NIST_P256": ("PQC004", "ECDSA P-256 (AWS KMS KeySpec)"),
    "ECC_NIST_P384": ("PQC004", "ECDSA P-384 (AWS KMS KeySpec)"),
    "ECC_NIST_P521": ("PQC004", "ECDSA P-521 (AWS KMS KeySpec)"),
    "ECC_SECG_P256K1": ("PQC004", "ECDSA secp256k1 (AWS KMS KeySpec)"),
}


class _JavaScriptAnalyzer:
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
            elif ntype in ("variable_declarator", "assignment_expression", "pair"):
                self._inspect_binding(node)
        return self.findings

    # ----- call detection ------------------------------------------------ #

    def _inspect_call(self, call) -> None:
        fn = h.call_function(call)
        parts = h.dotted_parts(fn)
        if not parts:
            return
        method = parts[-1]
        obj_parts = parts[:-1]
        obj_set = set(obj_parts)
        args = h.call_arguments(call)
        positionals = h.positional_args(args)

        # --- node-forge key pair ----------------------------------------- #
        # forge.pki.rsa.generateKeyPair({ bits }) / forge.pki.ed25519.generateKeyPair()
        if method in ("generateKeyPair", "generateKeyPairSync") and (
            "rsa" in obj_set or "pki" in obj_set or "forge" in obj_set
        ):
            # Dispatch on the actual algorithm marker, not the generic `pki` path.
            if "ed25519" in obj_set:
                self._add("PQC006", call, "Ed25519")
                return
            if "ed448" in obj_set:
                self._add("PQC006", call, "Ed448")
                return
            if "rsa" in obj_set:
                bits = self._number_from_object(positionals, "bits")
                self._add("PQC001", call, f"RSA-{bits or '?'}")
                return
            # A bare forge.pki.generateKeyPair (no algorithm marker) defaults to
            # RSA in node-forge.
            if "pki" in obj_set or "forge" in obj_set:
                bits = self._number_from_object(positionals, "bits")
                self._add("PQC001", call, f"RSA-{bits or '?'}")
                return

        # --- node crypto: generateKeyPair / generateKeyPairSync ----------- #
        if method in ("generateKeyPair", "generateKeyPairSync"):
            self._node_generate_key_pair(call, positionals)
            return

        # --- node crypto: Diffie-Hellman --------------------------------- #
        if method in ("createDiffieHellman", "createDiffieHellmanGroup", "getDiffieHellman"):
            self._add("PQC007", call, "DH")
            return

        # --- node crypto: ECDH ------------------------------------------- #
        if method == "createECDH":
            curve = self._string_positional(positionals, 0)
            self._add("PQC005", call, f"ECDH-{curve}" if curve else "ECDH")
            return

        # --- node crypto: RSA-only primitives ----------------------------- #
        # publicEncrypt/privateDecrypt (key transport) and privateEncrypt/
        # publicDecrypt (raw RSA signature) only exist for RSA keys in Node.
        if method in ("publicEncrypt", "privateDecrypt"):
            self._add("PQC002", call, f"RSA ({method})")
            return
        if method in ("privateEncrypt", "publicDecrypt"):
            self._add("PQC003", call, f"RSA ({method})", category=CATEGORY_SIGNING)
            return

        # --- node crypto: createSign / createVerify ----------------------- #
        # 'RSA-SHA256' names the key type explicitly; a weak digest in the
        # algorithm string ('RSA-SHA1', 'md5') is flagged in its own right.
        if method in ("createSign", "createVerify"):
            name = self._string_positional(positionals, 0)
            if name:
                low = name.strip().lower()
                if low.startswith("rsa-"):
                    self._add("PQC003", call, f"RSA signature: {name}",
                              category=CATEGORY_SIGNING)
                if "md5" in low:
                    self._add("PQC010", call, "MD5")
                elif "sha1" in low or "sha-1" in low:
                    self._add("PQC009", call, "SHA-1")
            return

        # --- jose: new SignJWT().setProtectedHeader({ alg: 'RS256' }) ----- #
        if method == "setProtectedHeader":
            obj = self._first_object(positionals)
            for key, value in self._object_pairs(obj):
                if key.lower() in ("alg", "algorithm"):
                    sval = h.string_value(value)
                    if sval and sval.upper() in JWT_ASYMMETRIC_ALGS:
                        self._add("PQC011", value, f"JWT algorithm: {sval}",
                                  confidence=CONFIDENCE_HIGH)
            return

        # --- WebCrypto SubtleCrypto -------------------------------------- #
        if method == "generateKey" and ("subtle" in obj_set or "crypto" in obj_set):
            self._webcrypto_generate_key(call, positionals)
            return
        if method in ("importKey", "deriveKey", "deriveBits", "encrypt", "decrypt",
                      "sign", "verify", "wrapKey", "unwrapKey") and "subtle" in obj_set:
            self._webcrypto_operation(call, positionals)
            return

        # --- node crypto: createHash ------------------------------------- #
        if method in ("createHash", "createHmac"):
            name = self._string_positional(positionals, 0)
            if name is not None:
                hit = WEAK_HASH_NAMES.get(name.strip().lower())
                if hit:
                    rule_id, label = hit
                    self._add(rule_id, call, label)
            return

        # --- jsonwebtoken / jose ----------------------------------------- #
        if method in ("sign", "verify", "decode", "encode"):
            self._check_jwt(call, positionals)
            return

    # ----- node crypto.generateKeyPair ----------------------------------- #

    def _node_generate_key_pair(self, call, positionals) -> None:
        key_type = self._string_positional(positionals, 0)
        opts = self._first_object(positionals)
        if key_type is None:
            return
        ktype = key_type.strip().lower()
        if ktype in ("rsa", "rsa-pss"):
            modlen = self._number_from_object_node(opts, "modulusLength")
            label = "RSA-PSS" if ktype == "rsa-pss" else "RSA"
            self._add("PQC001", call, f"{label}-{modlen}" if modlen else label)
        elif ktype in ("ec",):
            curve = self._string_from_object_node(opts, "namedCurve")
            self._add("PQC004", call, f"EC-{curve}" if curve else "EC")
        elif ktype in ("ed25519",):
            self._add("PQC006", call, "Ed25519")
        elif ktype in ("ed448",):
            self._add("PQC006", call, "Ed448")
        elif ktype in ("x25519",):
            self._add("PQC005", call, "X25519")
        elif ktype in ("x448",):
            self._add("PQC005", call, "X448")
        elif ktype in ("dsa",):
            self._add("PQC008", call, "DSA")
        elif ktype in ("dh",):
            self._add("PQC007", call, "DH")

    # ----- WebCrypto SubtleCrypto ---------------------------------------- #

    def _webcrypto_generate_key(self, call, positionals) -> None:
        name = self._algorithm_name(positionals)
        if name is None:
            return
        upper = name.strip().upper()
        if upper in WEBCRYPTO_RSA_ENC:
            self._add("PQC002", call, name)
        elif upper in WEBCRYPTO_RSA_SIG:
            self._add("PQC003", call, name)
        elif upper in WEBCRYPTO_ECDSA:
            self._add("PQC004", call, name)
        elif upper in WEBCRYPTO_ECDH:
            self._add("PQC005", call, name)
        elif upper in WEBCRYPTO_EDDSA:
            self._add("PQC006", call, name)

    def _webcrypto_operation(self, call, positionals) -> None:
        # encrypt/sign/etc. take the algorithm as the first arg.
        name = self._algorithm_name(positionals)
        if name is None:
            return
        upper = name.strip().upper()
        if upper in WEBCRYPTO_RSA_ENC:
            self._add("PQC002", call, name)
        elif upper in WEBCRYPTO_RSA_SIG:
            self._add("PQC003", call, name)
        elif upper in WEBCRYPTO_ECDSA:
            self._add("PQC004", call, name)
        elif upper in WEBCRYPTO_ECDH:
            self._add("PQC005", call, name)
        elif upper in WEBCRYPTO_EDDSA:
            self._add("PQC006", call, name)

    def _algorithm_name(self, positionals) -> Optional[str]:
        """Resolve the WebCrypto algorithm identifier from the first argument.

        Accepts either ``{ name: 'RSA-OAEP' }`` or a bare ``'RSA-OAEP'`` string.
        """
        obj = self._first_object(positionals)
        if obj is not None:
            name = self._string_from_object_node(obj, "name")
            if name is not None:
                return name
        return self._string_positional(positionals, 0)

    # ----- jsonwebtoken -------------------------------------------------- #

    def _check_jwt(self, call, positionals) -> None:
        # The options object (with algorithm / algorithms) is the last object arg.
        for arg in positionals:
            obj = arg if arg.type == "object" else None
            if obj is None:
                continue
            for key, value in self._object_pairs(obj):
                if key.lower() not in ALG_NAME_KEYS:
                    continue
                # single string value
                sval = h.string_value(value)
                if sval and sval.upper() in JWT_ASYMMETRIC_ALGS:
                    self._add(
                        "PQC011", value, f"JWT algorithm: {sval}",
                        confidence=CONFIDENCE_HIGH,
                    )
                # array of strings: algorithms: ['RS256', ...]
                if value.type in ("array",):
                    for child in value.children:
                        cval = h.string_value(child)
                        if cval and cval.upper() in JWT_ASYMMETRIC_ALGS:
                            self._add(
                                "PQC011", child, f"JWT algorithm: {cval}",
                                confidence=CONFIDENCE_HIGH,
                            )

    # ----- indirect string detection ------------------------------------ #

    def _inspect_binding(self, node) -> None:
        """Flag algorithm / curve choices stored in a variable or object pair.

        Handles ``const alg = 'RS256'``, ``algorithm = 'ES384'`` and an object
        pair ``{ algorithm: 'PS512' }`` that is not itself a JWT call argument
        (the JWT path already covers call sites, deduped by line/column).
        """
        if node.type == "variable_declarator":
            name_node = h.field(node, "name")
            value_node = h.field(node, "value")
        elif node.type == "assignment_expression":
            name_node = h.field(node, "left")
            value_node = h.field(node, "right")
        else:  # pair
            name_node = h.field(node, "key")
            value_node = h.field(node, "value")
        if name_node is None or value_node is None:
            return
        name = self._binding_name(name_node)
        if name is None:
            return
        lower = name.lower()
        # Array values: { algorithms: ['RS256'] } / const algs = ['ES384'] —
        # covers option objects consumed by libraries whose call sites are not
        # individually modeled (jose's jwtVerify, fastify-jwt, ...).
        if lower in ALG_NAME_KEYS and value_node.type == "array":
            for child in value_node.children:
                cval = h.string_value(child)
                if cval and cval.upper() in JWT_ASYMMETRIC_ALGS:
                    self._add(
                        "PQC011", child, f"JWT/JWS algorithm: {cval}",
                        confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM,
                        category=CATEGORY_SIGNING,
                    )
            return
        value = h.string_value(value_node)
        if value is None:
            return
        upper = value.upper()
        if lower in ALG_NAME_KEYS and upper in JWT_ASYMMETRIC_ALGS:
            self._add(
                "PQC011", value_node, f"JWT/JWS algorithm: {value}",
                confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM,
                category=CATEGORY_SIGNING,
            )
        elif (
            node.type != "pair"
            and lower in CURVE_NAME_KEYS
            and value.lower() in EC_CURVE_STRINGS
        ):
            # Only flag standalone variable/assignment bindings — option keys
            # such as ``namedCurve`` inside an object literal are already
            # covered by the call site that consumes them.
            self._add(
                "PQC004", value_node, f"Elliptic curve: {value}",
                category=CATEGORY_KEY_GENERATION,
                confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM,
            )
        elif lower in KEYSPEC_NAME_KEYS and upper in AWS_KEYSPEC_VALUES:
            # AWS KMS CreateKey with an asymmetric KeySpec provisions a real
            # RSA/ECC key in KMS; high (not critical) because the signal is a
            # string parameter rather than a directly-observed keygen call.
            rule_id, label = AWS_KEYSPEC_VALUES[upper]
            self._add(
                rule_id, value_node, label,
                category=CATEGORY_KEY_GENERATION,
                confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_HIGH,
            )

    @staticmethod
    def _binding_name(name_node) -> Optional[str]:
        ntype = name_node.type
        if ntype in ("identifier", "property_identifier", "shorthand_property_identifier"):
            return h.text(name_node)
        if ntype in ("string",):
            return h.string_value(name_node)
        return None

    # ----- object-literal helpers ---------------------------------------- #

    @staticmethod
    def _object_pairs(obj):
        """Yield (key_text, value_node) for each ``pair`` in an ``object`` node."""
        if obj is None or obj.type != "object":
            return
        for child in obj.children:
            if child.type != "pair":
                continue
            key = h.field(child, "key")
            value = h.field(child, "value")
            if key is None or value is None:
                continue
            if key.type == "string":
                key_text = h.string_value(key) or ""
            else:  # property_identifier / computed etc.
                key_text = h.text(key)
            yield key_text, value

    @staticmethod
    def _first_object(positionals):
        for arg in positionals:
            if arg.type == "object":
                return arg
        return None

    def _string_from_object_node(self, obj, key_name: str) -> Optional[str]:
        if obj is None:
            return None
        for key, value in self._object_pairs(obj):
            if key == key_name:
                return h.string_value(value)
        return None

    def _number_from_object_node(self, obj, key_name: str) -> Optional[str]:
        if obj is None:
            return None
        for key, value in self._object_pairs(obj):
            if key == key_name and value.type == "number":
                return h.text(value)
        return None

    def _number_from_object(self, positionals, key_name: str) -> Optional[str]:
        return self._number_from_object_node(self._first_object(positionals), key_name)

    @staticmethod
    def _string_positional(positionals, index) -> Optional[str]:
        if index < len(positionals):
            return h.string_value(positionals[index])
        return None


def analyze(root, source_text: str, file_path: str | Path) -> list[Finding]:
    """Entry point used by the AST scanner."""
    return _JavaScriptAnalyzer(source_text, str(file_path)).run(root)
