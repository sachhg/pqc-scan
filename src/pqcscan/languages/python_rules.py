"""Python detection rules.

Detects quantum-vulnerable cryptography in Python source via tree-sitter node
traversal. Covers the ``cryptography`` (hazmat) library, ``pycryptodome``,
``PyJWT`` / ``python-jose``, ``paramiko``, the ``ssl`` module, ``hashlib`` and a
set of precise indirect string-literal patterns.

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
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    RULES,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Finding,
    build_finding,
)
from pqcscan.scanner.context import wrapper_context_hint

from . import _helpers as h

LANGUAGE = "python"
EXTENSIONS = {".py", ".pyi"}
GRAMMAR = "tree_sitter_python"

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #

# JWT/JWS/JWE asymmetric (quantum-vulnerable) algorithm identifiers. HS256 &
# friends are symmetric and intentionally absent.
JWT_ASYMMETRIC_ALGS = {
    "RS256", "RS384", "RS512",
    "ES256", "ES256K", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EDDSA",
    "RSA-OAEP", "RSA-OAEP-256", "RSA1_5",
}

# cryptography EC curve class -> friendly parameter set label.
EC_CURVE_CLASSES = {
    "SECP256R1": "P-256",
    "PRIME256V1": "P-256",
    "SECP384R1": "P-384",
    "SECP521R1": "P-521",
    "SECP256K1": "secp256k1",
    "SECP224R1": "P-224",
    "SECP192R1": "P-192",
    "BRAINPOOLP256R1": "brainpoolP256r1",
    "BRAINPOOLP384R1": "brainpoolP384r1",
    "BRAINPOOLP512R1": "brainpoolP512r1",
}

# Curve / key-type string-literal values worth flagging in crypto context.
EC_CURVE_STRINGS = {
    "secp256k1", "secp256r1", "secp384r1", "secp521r1",
    "p-256", "p-384", "p-521", "p256", "p384", "p521",
    "prime256v1", "nistp256", "nistp384", "nistp521",
}

# Substrings that make a TLS cipher-suite string quantum-vulnerable or broken.
WEAK_CIPHER_SUBSTRINGS = (
    "RSA", "ECDSA", "ECDHE", "DHE", "DSS",
    "RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "MD5",
)

# ssl module constants for outdated protocol versions.
WEAK_SSL_PROTOCOLS = {
    "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
}

# Variable / keyword names whose string value we treat as an algorithm choice.
ALG_NAME_KEYS = {"algorithm", "algorithms", "alg", "jwt_algorithm", "jws_alg"}
CURVE_NAME_KEYS = {"curve", "ec_curve", "named_curve"}
KEYTYPE_NAME_KEYS = {"key_type", "keytype", "key_algorithm", "kty"}

# Rules describing key material; only these get the wrapper-function hint.
_KEY_RULES = {"PQC001", "PQC004", "PQC005", "PQC006", "PQC007", "PQC008"}


class _PythonAnalyzer:
    def __init__(self, source_text: str, file_path: str):
        self.source = source_text
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()
        # local name -> dotted origin (best effort)
        self.imports: dict[str, str] = {}
        # simple module-level string constants: name -> literal value
        self.str_constants: dict[str, str] = {}

    # ----- finding helpers ------------------------------------------------ #

    def _add(self, rule_id: str, node, algorithm: str, **kwargs) -> None:
        line, col = h.line_col(node)
        key = (rule_id, line, col)
        if key in self._seen:
            return
        self._seen.add(key)
        if "context_hint" not in kwargs and rule_id in _KEY_RULES:
            kwargs["context_hint"] = wrapper_context_hint(self._enclosing_function(node))
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

    @staticmethod
    def _enclosing_function(node) -> Optional[str]:
        """Name of the nearest enclosing function definition, if any."""
        current = node.parent
        while current is not None:
            if current.type == "function_definition":
                name = h.field(current, "name")
                return h.text(name) if name is not None else None
            current = current.parent
        return None

    # ----- import resolution --------------------------------------------- #

    def _collect_imports(self, root) -> None:
        for node in h.walk(root):
            if node.type == "import_from_statement":
                module_node = h.field(node, "module_name")
                module = h.text(module_node) if module_node else ""
                # tree-sitter recreates Node wrappers per access, so identity
                # (`is`) is unreliable — compare byte ranges to skip the module.
                module_range = (
                    (module_node.start_byte, module_node.end_byte) if module_node else None
                )
                for name_node in node.children:
                    if name_node.type == "dotted_name" and (
                        (name_node.start_byte, name_node.end_byte) != module_range
                    ):
                        local = h.text(name_node)
                        self.imports[local] = f"{module}.{local}" if module else local
                    elif name_node.type == "aliased_import":
                        orig = h.field(name_node, "name")
                        alias = h.field(name_node, "alias")
                        if orig is not None and alias is not None:
                            self.imports[h.text(alias)] = (
                                f"{module}.{h.text(orig)}" if module else h.text(orig)
                            )
            elif node.type == "import_statement":
                for child in node.children:
                    if child.type == "dotted_name":
                        full = h.text(child)
                        self.imports[full.split(".")[0]] = full
                    elif child.type == "aliased_import":
                        orig = h.field(child, "name")
                        alias = h.field(child, "alias")
                        if orig is not None and alias is not None:
                            self.imports[h.text(alias)] = h.text(orig)
            elif node.type == "assignment":
                # Track plain `name = "literal"` constants so an algorithm
                # passed through a variable (algo = "RS256"; jwt.encode(...,
                # algorithm=algo)) can still be resolved at the call site.
                left = h.field(node, "left")
                right = h.field(node, "right")
                if left is not None and left.type == "identifier":
                    value = h.string_value(right)
                    if value is not None:
                        self.str_constants[h.text(left)] = value

    def _origin(self, name: Optional[str]) -> str:
        if not name:
            return ""
        return self.imports.get(name, name)

    # ----- main traversal ------------------------------------------------ #

    def run(self, root) -> list[Finding]:
        self._collect_imports(root)
        for node in h.walk(root):
            ntype = node.type
            if ntype == "call":
                self._inspect_call(node)
            elif ntype == "attribute":
                self._inspect_attribute(node)
            elif ntype == "assignment":
                self._inspect_assignment(node)
        return self.findings

    # ----- call detection ------------------------------------------------ #

    def _inspect_call(self, call) -> None:
        fn = h.call_function(call)
        parts = h.dotted_parts(fn)
        if not parts:
            return
        method = parts[-1]
        obj_parts = parts[:-1]
        obj_tail = obj_parts[-1] if obj_parts else None
        root_name = parts[0]
        origin = self._origin(root_name)
        origin_tail = origin.split(".")[-1] if origin else ""
        # Names we consider for "object" matching (handles aliases).
        obj_names = {p for p in (obj_tail, origin_tail) if p}
        args = h.call_arguments(call)
        kwargs = h.keyword_args(args)
        positionals = h.positional_args(args)

        # --- cryptography / pycryptodome / paramiko key generation -------- #
        if method == "generate_private_key":
            if obj_names & {"rsa"}:
                self._add("PQC001", call, f"RSA-{self._int_kwarg(kwargs, 'key_size') or '?'}")
                return
            if obj_names & {"ec"}:
                curve = self._curve_from_args(positionals, kwargs)
                self._add("PQC004", call, f"ECDSA-{curve}" if curve else "ECDSA")
                return
            if obj_names & {"dsa"}:
                self._add("PQC008", call, "DSA")
                return

        if method == "generate":
            # pycryptodome: RSA.generate(2048) / ECC.generate(curve='P-256') / DSA.generate
            if obj_names & {"RSA"}:
                bits = self._int_positional(positionals, 0) or self._int_kwarg(kwargs, "bits")
                self._add("PQC001", call, f"RSA-{bits or '?'}")
                return
            if obj_names & {"ECC"}:
                curve = self._string_kwarg(kwargs, "curve") or "?"
                self._add("PQC004", call, f"ECC-{curve}")
                return
            if obj_names & {"DSA"}:
                self._add("PQC008", call, "DSA")
                return
            # cryptography X25519/X448/Ed25519/Ed448 private keys
            if obj_tail in ("X25519PrivateKey", "X25519PublicKey"):
                self._add("PQC005", call, "X25519")
                return
            if obj_tail in ("X448PrivateKey", "X448PublicKey"):
                self._add("PQC005", call, "X448")
                return
            if obj_tail in ("Ed25519PrivateKey", "Ed25519PublicKey"):
                self._add("PQC006", call, "Ed25519")
                return
            if obj_tail in ("Ed448PrivateKey", "Ed448PublicKey"):
                self._add("PQC006", call, "Ed448")
                return
            # paramiko key classes
            if obj_tail == "RSAKey":
                bits = self._int_kwarg(kwargs, "bits")
                self._add("PQC001", call, f"RSA-{bits or '?'}")
                return
            if obj_tail == "ECDSAKey":
                self._add("PQC004", call, "ECDSA")
                return
            if obj_tail in ("DSSKey", "DSAKey"):
                self._add("PQC008", call, "DSA")
                return

        # --- RSA padding / encryption ------------------------------------ #
        # Require real evidence of the cryptography padding module (the receiver
        # is `padding`, or the symbol was imported from ...asymmetric.padding) so
        # that an unrelated user-defined OAEP()/PKCS1v15() is not a false positive.
        if method in ("PKCS1v15", "OAEP"):
            in_padding_ctx = bool(obj_names & {"padding"}) or "padding" in origin
            if in_padding_ctx:
                label = "RSA-PKCS1v15" if method == "PKCS1v15" else "RSA-OAEP"
                self._add("PQC002", call, label)
                return

        # --- pycryptodome signature / cipher objects ---------------------- #
        # Crypto.Signature.{pkcs1_15,pss,DSS,eddsa}.new(key) and
        # Crypto.Cipher.{PKCS1_OAEP,PKCS1_v1_5}.new(key). The module names are
        # distinctive; `pss`/`eddsa` are lower-case-generic so they additionally
        # require a resolved Crypto import origin.
        if method == "new" and obj_tail is not None:
            crypto_origin = "Crypto" in origin
            if obj_tail == "pkcs1_15":
                self._add("PQC003", call, "RSA-PKCS1v15")
                return
            if obj_tail == "pss" and crypto_origin:
                self._add("PQC003", call, "RSA-PSS")
                return
            if obj_tail == "DSS":
                self._add("PQC008", call, "DSA (DSS)")
                return
            if obj_tail == "eddsa" and crypto_origin:
                self._add("PQC006", call, "Ed25519 (EdDSA)")
                return
            if obj_tail == "PKCS1_OAEP":
                self._add("PQC002", call, "RSA-OAEP")
                return
            if obj_tail == "PKCS1_v1_5":
                # Crypto.Cipher.PKCS1_v1_5 encrypts; Crypto.Signature.PKCS1_v1_5
                # (legacy pycrypto name) signs. Resolve by import origin.
                rule_id = "PQC003" if "Signature" in origin else "PQC002"
                self._add(rule_id, call, "RSA-PKCS1v15")
                return

        # --- pyOpenSSL key generation ------------------------------------- #
        # PKey().generate_key(TYPE_RSA, 2048) / generate_key(crypto.TYPE_DSA, n)
        if method == "generate_key":
            for arg in positionals:
                arg_parts = h.dotted_parts(arg)
                tail = arg_parts[-1] if arg_parts else ""
                if tail in ("TYPE_RSA", "TYPE_DSA"):
                    bits = self._int_positional(positionals, len(positionals) - 1)
                    if tail == "TYPE_RSA":
                        self._add("PQC001", call, f"RSA-{bits or '?'} (pyOpenSSL)")
                    else:
                        self._add("PQC008", call, "DSA (pyOpenSSL)")
                    return

        # --- hashing ------------------------------------------------------ #
        if method == "SHA1" and obj_names & {"hashes", "SHA1"}:
            self._add("PQC009", call, "SHA-1")
            return
        if method in ("MD5",) and obj_names & {"hashes", "MD5"}:
            self._add("PQC010", call, "MD5")
            return
        if obj_names & {"hashlib"} or self._origin(root_name).startswith("hashlib"):
            if method == "md5":
                self._add("PQC010", call, "MD5", **self._hash_severity("PQC010", kwargs))
                return
            if method == "sha1":
                self._add("PQC009", call, "SHA-1", **self._hash_severity("PQC009", kwargs))
                return
            if method == "new":
                # hashlib.new("md5") and hashlib.new(name="md5")
                algo = self._string_positional(positionals, 0) or self._string_kwarg(kwargs, "name")
                if algo and algo.lower() in ("md5",):
                    self._add("PQC010", call, "MD5", **self._hash_severity("PQC010", kwargs))
                    return
                if algo and algo.lower() in ("sha1", "sha-1"):
                    self._add("PQC009", call, "SHA-1", **self._hash_severity("PQC009", kwargs))
                    return
        # Bare / aliased hash constructors resolved through the import map:
        #   from hashlib import md5 as m;  m(b"x")
        #   from cryptography.hazmat.primitives.hashes import SHA1 as S;  S()
        if not obj_parts:
            hash_origin = self._origin(method)
            tail = hash_origin.split(".")[-1]
            if "hashlib" in hash_origin and tail in ("md5", "sha1"):
                self._add("PQC010" if tail == "md5" else "PQC009",
                          call, "MD5" if tail == "md5" else "SHA-1")
                return
            if "hashes" in hash_origin and tail in ("SHA1", "MD5"):
                self._add("PQC009" if tail == "SHA1" else "PQC010",
                          call, "SHA-1" if tail == "SHA1" else "MD5")
                return

        # --- pycryptodome DES / 3DES ------------------------------------- #
        if method == "new" and obj_tail in ("DES3",):
            self._add("PQC013", call, "3DES")
            return
        if method == "new" and obj_tail in ("DES",):
            self._add("PQC013", call, "DES")
            return

        # --- Diffie-Hellman / DSA domain parameters ----------------------- #
        if method == "generate_parameters" and obj_names & {"dh"}:
            self._add("PQC007", call, "DH")
            return
        if method == "generate_parameters" and obj_names & {"dsa"}:
            self._add("PQC008", call, "DSA", category=CATEGORY_KEY_GENERATION)
            return
        if method == "createDiffieHellman":  # defensive (node-style, just in case)
            self._add("PQC007", call, "DH")
            return

        # --- ssl cipher configuration ------------------------------------ #
        if method == "set_ciphers":
            for arg in positionals:
                val = h.string_value(arg)
                if val and self._is_weak_cipher(val):
                    self._add(
                        "PQC012", arg, f"TLS cipher: {val[:40]}",
                        confidence=CONFIDENCE_HIGH,
                    )
            return

        # --- JWT / JWS asymmetric signing -------------------------------- #
        if method in ("encode", "sign", "decode"):
            self._check_jwt_algorithms(call, kwargs)
            # do not return: a call can both be jwt and have nested matches

    # ----- attribute detection ------------------------------------------ #

    def _inspect_attribute(self, node) -> None:
        parts = h.dotted_parts(node)
        if len(parts) < 2:
            return
        obj_tail, attr = parts[-2], parts[-1]
        root_name = parts[0]
        origin_tail = self._origin(root_name).split(".")[-1]
        if attr in WEAK_SSL_PROTOCOLS and (obj_tail == "ssl" or origin_tail == "ssl"):
            self._add(
                "PQC012", node, f"Outdated TLS/SSL protocol: {attr}",
                confidence=CONFIDENCE_HIGH,
            )

    # ----- assignment / indirect string detection ----------------------- #

    def _inspect_assignment(self, node) -> None:
        left = h.field(node, "left")
        right = h.field(node, "right")
        if left is None or right is None:
            return
        name = h.text(left).strip().lower()
        value = h.string_value(right)
        if value is None:
            return
        upper = value.upper()
        lower = value.lower()
        if name in ALG_NAME_KEYS and upper in JWT_ASYMMETRIC_ALGS:
            self._add(
                "PQC011", right, f"JWT/JWS algorithm: {value}",
                confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM,
            )
        elif name in CURVE_NAME_KEYS and lower in EC_CURVE_STRINGS:
            self._add(
                "PQC004", right, f"Elliptic curve: {value}",
                category=CATEGORY_KEY_GENERATION,
                confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM,
            )
        elif name in KEYTYPE_NAME_KEYS:
            self._keytype_string(right, lower, value)

    def _keytype_string(self, node, lower: str, value: str) -> None:
        if lower == "rsa":
            self._add("PQC001", node, "RSA", category=CATEGORY_KEY_GENERATION,
                      confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM)
        elif lower in ("ec", "ecc", "ecdsa"):
            self._add("PQC004", node, "ECDSA", category=CATEGORY_KEY_GENERATION,
                      confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM)
        elif lower == "dsa":
            self._add("PQC008", node, "DSA", category=CATEGORY_KEY_GENERATION,
                      confidence=CONFIDENCE_MEDIUM, severity=SEVERITY_MEDIUM)

    def _check_jwt_algorithms(self, call, kwargs) -> None:
        for key in ("algorithm", "algorithms", "alg"):
            value_node = kwargs.get(key)
            if value_node is None:
                continue
            # single string
            sval = h.string_value(value_node)
            if sval and sval.upper() in JWT_ASYMMETRIC_ALGS:
                self._add("PQC011", value_node, f"JWT algorithm: {sval}",
                          confidence=CONFIDENCE_HIGH)
            # algorithm passed through a module-level string constant:
            #   algo = "RS256"; jwt.encode(payload, key, algorithm=algo)
            # Names in ALG_NAME_KEYS are skipped: those assignments are already
            # reported directly, and reporting both would duplicate the finding.
            if value_node.type == "identifier":
                var_name = h.text(value_node)
                if var_name.lower() not in ALG_NAME_KEYS:
                    const = self.str_constants.get(var_name)
                    if const and const.upper() in JWT_ASYMMETRIC_ALGS:
                        self._add(
                            "PQC011", value_node,
                            f"JWT algorithm: {const} (via variable '{var_name}')",
                            confidence=CONFIDENCE_MEDIUM,
                        )
            # list/tuple/set of strings (e.g. decode(algorithms=["RS256"]))
            if value_node.type in ("list", "tuple", "set"):
                for child in value_node.children:
                    cval = h.string_value(child)
                    if cval and cval.upper() in JWT_ASYMMETRIC_ALGS:
                        self._add("PQC011", child, f"JWT algorithm: {cval}",
                                  confidence=CONFIDENCE_HIGH)

    # ----- small extraction utilities ----------------------------------- #

    @staticmethod
    def _hash_severity(rule_id: str, kwargs) -> dict:
        """Demote a weak-hash finding to LOW when usedforsecurity=False.

        Python's hashlib accepts ``usedforsecurity=False`` to mark digests used
        for non-security purposes (cache keys, checksums). The weak primitive is
        still worth surfacing in an inventory, but it is not a migration blocker,
        so the severity drops and the description says why.
        """
        node = kwargs.get("usedforsecurity")
        if node is None or h.text(node) != "False":
            return {}
        return {
            "severity": SEVERITY_LOW,
            "description": RULES[rule_id].description
            + " usedforsecurity=False is declared, so this appears to be a "
            "non-security use (cache key / checksum) — informational.",
        }

    @staticmethod
    def _int_kwarg(kwargs, key) -> Optional[str]:
        node = kwargs.get(key)
        if node is not None and node.type == "integer":
            return h.text(node)
        return None

    @staticmethod
    def _int_positional(positionals, index) -> Optional[str]:
        if index < len(positionals) and positionals[index].type == "integer":
            return h.text(positionals[index])
        return None

    @staticmethod
    def _string_kwarg(kwargs, key) -> Optional[str]:
        node = kwargs.get(key)
        return h.string_value(node) if node is not None else None

    @staticmethod
    def _string_positional(positionals, index) -> Optional[str]:
        if index < len(positionals):
            return h.string_value(positionals[index])
        return None

    def _curve_from_args(self, positionals, kwargs) -> Optional[str]:
        # ec.generate_private_key(ec.SECP384R1())  -> positional call arg
        for arg in positionals:
            parts = h.dotted_parts(arg)
            if parts:
                cls = parts[-1].upper()
                if cls in EC_CURVE_CLASSES:
                    return EC_CURVE_CLASSES[cls]
        # ec.generate_private_key(curve=ec.SECP256R1())
        cnode = kwargs.get("curve")
        if cnode is not None:
            parts = h.dotted_parts(cnode)
            if parts:
                cls = parts[-1].upper()
                if cls in EC_CURVE_CLASSES:
                    return EC_CURVE_CLASSES[cls]
        return None

    @staticmethod
    def _is_weak_cipher(value: str) -> bool:
        """True when an OpenSSL cipher string enables a weak component.

        Tokens prefixed with ``!`` or ``-`` are *removals* (``HIGH:!aNULL:!MD5``
        is a hardened string), so only additive tokens are inspected.
        """
        for token in value.upper().split(":"):
            token = token.strip()
            if not token or token[0] in "!-":
                continue
            if any(part in token for part in WEAK_CIPHER_SUBSTRINGS):
                return True
        return False


def analyze(root, source_text: str, file_path: str | Path) -> list[Finding]:
    """Entry point used by the AST scanner."""
    return _PythonAnalyzer(source_text, str(file_path)).run(root)
