"""Rust detection rules.

Covers the crates a Rust service actually reaches for: the RustCrypto family
(``rsa``, ``p256``/``p384``/``p521``/``k256``, ``ed25519-dalek``,
``x25519-dalek``, ``sha1``, ``md-5``, ``des``), ``ring``, the ``openssl``
bindings, and ``jsonwebtoken``.

Rust has no module-qualified call convention the way Go does — idiomatic code
writes ``use rsa::RsaPrivateKey;`` then ``RsaPrivateKey::new(..)``, so the bare
path carries no crate name. This module therefore resolves ``use`` declarations
first (including ``as`` aliases, brace lists and globs) and matches on the
*resolved* path. That is also the precision gate: a bare ``Sha1::new()`` with no
import that traces back to a known crate is deliberately **not** flagged, because
it is just as likely to be a local type.

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
    CATEGORY_ENCRYPTION,
    CATEGORY_KEY_EXCHANGE,
    CATEGORY_KEY_GENERATION,
    CATEGORY_SIGNING,
    SEVERITY_HIGH,
    Finding,
    build_finding,
)

from . import _helpers as h

LANGUAGE = "rust"
EXTENSIONS = {".rs"}
GRAMMAR = "tree_sitter_rust"

# --------------------------------------------------------------------------- #
# Crate registries
# --------------------------------------------------------------------------- #

# Elliptic-curve crates -> the curve they implement. Every item in these crates
# is that one curve, so the crate name alone gives the parameter set.
EC_CRATES = {
    "p256": "P-256",
    "p384": "P-384",
    "p521": "P-521",
    "k256": "secp256k1",
}

# Crate names that provide SHA-1. `sha-1` and `md-5` are published with hyphens
# but imported with underscores, so both spellings are accepted.
SHA1_CRATES = {"sha1", "sha_1", "sha1_smol"}
MD5_CRATES = {"md5", "md_5"}

# ed25519 / x25519 signing and key-agreement crates.
ED25519_CRATES = {"ed25519_dalek", "ed25519", "ed25519_compact", "ed25519_consensus"}
X25519_CRATES = {"x25519_dalek"}

# Constructors that build a fresh key (rather than merely wrapping bytes).
_ED25519_METHODS = {
    "generate", "from_bytes", "from_keypair_bytes", "new", "random", "sign",
    "verify", "verify_strict", "from_seed",
}
_X25519_METHODS = {
    "random", "random_from_rng", "new", "diffie_hellman", "x25519", "from",
}

# rsa crate: RustCrypto type names -> (rule, algorithm label).
_RSA_TYPES = {
    "RsaPrivateKey": ("PQC001", "RSA"),
    "Oaep": ("PQC002", "RSA-OAEP"),
    "Pkcs1v15Encrypt": ("PQC002", "RSA-PKCS1v15"),
    "Pkcs1v15Sign": ("PQC003", "RSA-PKCS1v15"),
}
_RSA_KEYGEN_METHODS = {"new", "new_with_exp", "from_components", "from_p_q", "generate"}

# openssl crate: (type, method) -> (rule, algorithm).
_OPENSSL_CALLS = {
    ("Rsa", "generate"): ("PQC001", "RSA"),
    ("Rsa", "generate_with_e"): ("PQC001", "RSA"),
    ("EcKey", "generate"): ("PQC004", "ECDSA"),
    ("EcKey", "from_curve_name"): ("PQC004", "ECDSA"),
    ("Dsa", "generate"): ("PQC008", "DSA"),
    ("Dsa", "generate_params"): ("PQC008", "DSA"),
    ("Dh", "get_1024_160"): ("PQC007", "DH-1024"),
    ("Dh", "get_2048_224"): ("PQC007", "DH-2048"),
    ("Dh", "get_2048_256"): ("PQC007", "DH-2048"),
    ("Dh", "params_from_pem"): ("PQC007", "DH"),
    ("Dh", "from_params"): ("PQC007", "DH"),
    ("MessageDigest", "sha1"): ("PQC009", "SHA-1"),
    ("MessageDigest", "md5"): ("PQC010", "MD5"),
    ("Signer", "new"): (None, None),  # resolved via its MessageDigest argument
}

# openssl Cipher constructors for DES / 3DES.
_OPENSSL_DES_CIPHERS = {
    "des_cbc": "DES", "des_ecb": "DES", "des_cfb64": "DES", "des_ofb": "DES",
    "des_ede3": "3DES", "des_ede3_cbc": "3DES", "des_ede3_cfb64": "3DES",
    "des_ede3_ofb": "3DES", "des_ede": "3DES", "des_ede_cbc": "3DES",
}

# openssl SslVersion constants that pin an outdated protocol.
_OPENSSL_LEGACY_TLS = {
    "SSL3": "SSLv3", "TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1",
}

# des crate cipher types.
_DES_TYPES = {
    "Des": "DES",
    "TdesEde3": "3DES", "TdesEee3": "3DES",
    "TdesEde2": "3DES", "TdesEee2": "3DES",
}

# ring: `signature::` constant prefixes and `agreement::` constants.
_RING_ECDSA_CURVE_RE = re.compile(r"^ECDSA_(P256|P384|P521)_")
_RING_AGREEMENT = {
    "ECDH_P256": "ECDH-P-256", "ECDH_P384": "ECDH-P-384", "ECDH_P521": "ECDH-P-521",
    "X25519": "X25519",
}

# jsonwebtoken / jwt-simple asymmetric algorithm variants.
_JWT_CRATES = {"jsonwebtoken", "jwt", "jwt_simple"}
_JWT_ASYMMETRIC = {
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512", "EdDSA",
}
_JWT_KEY_METHODS = {
    "from_rsa_pem", "from_rsa_der", "from_rsa_components",
    "from_ec_pem", "from_ec_der", "from_ed_pem", "from_ed_der",
}

# Node types whose scoped paths are import syntax, not a use of the item.
_USE_CONTEXT = {
    "use_declaration", "use_as_clause", "scoped_use_list", "use_list", "use_wildcard",
}

_DIGITS_RE = re.compile(r"\d+")


def _int_text(node) -> str | None:
    """Digits of a Rust integer literal (``2_048usize`` -> ``2048``)."""
    if node is None or node.type != "integer_literal":
        return None
    digits = "".join(_DIGITS_RE.findall(h.text(node)))
    return digits or None


class _RustAnalyzer:
    def __init__(self, source_text: str, file_path: str):
        self.source = source_text
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()
        #: local name -> fully-qualified path, from `use` declarations.
        self.imports: dict[str, tuple[str, ...]] = {}
        #: prefixes brought in by `use foo::bar::*;`
        self.wildcards: list[tuple[str, ...]] = []

    # ----- finding helper ------------------------------------------------- #

    def _add(self, rule_id: str, node, algorithm: str, **kwargs) -> None:
        line, col = h.line_col(node)
        last_line = h.end_line(node)
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
                end_line_number=last_line,
                **kwargs,
            )
        )

    # ----- use-declaration resolution ------------------------------------- #

    def _collect_imports(self, root) -> None:
        for node in h.walk(root):
            if node.type != "use_declaration":
                continue
            target = next((c for c in node.children if c.is_named), None)
            self._walk_use(target, ())

    def _walk_use(self, node, prefix: tuple[str, ...]) -> None:
        """Record every name a ``use`` tree binds, with its full crate path."""
        if node is None:
            return
        ntype = node.type

        if ntype in ("identifier", "type_identifier"):
            name = h.text(node)
            if name == "self":
                # `use rsa::{self, RsaPrivateKey}` binds the module itself.
                if prefix:
                    self.imports.setdefault(prefix[-1], prefix)
            elif name:
                self.imports.setdefault(name, prefix + (name,))
            return

        if ntype == "scoped_identifier":
            parts = tuple(h.dotted_parts(node))
            if parts:
                self.imports.setdefault(parts[-1], prefix + parts)
            return

        if ntype == "use_as_clause":
            named = [c for c in node.children if c.is_named]
            if len(named) >= 2:
                path = tuple(h.dotted_parts(named[0]))
                alias = h.text(named[-1])
                if path and alias:
                    self.imports[alias] = prefix + path
            return

        if ntype == "scoped_use_list":
            named = [c for c in node.children if c.is_named]
            if not named:
                return
            inner_prefix = prefix + tuple(h.dotted_parts(named[0]))
            for child in named[1:]:
                self._walk_use(child, inner_prefix)
            return

        if ntype == "use_list":
            for child in node.children:
                if child.is_named:
                    self._walk_use(child, prefix)
            return

        if ntype == "use_wildcard":
            named = [c for c in node.children if c.is_named]
            path = prefix + tuple(h.dotted_parts(named[0])) if named else prefix
            if path:
                self.wildcards.append(path)
            return

    def _candidates(self, parts: list[str]) -> list[list[str]]:
        """Every crate path *parts* could denote, most specific first.

        A name bound by an explicit ``use`` resolves to exactly one path. An
        unbound name might already be fully qualified, or might have come from a
        glob import — both are offered, and the first registry hit wins.
        """
        if not parts:
            return []
        mapped = self.imports.get(parts[0])
        if mapped is not None:
            return [list(mapped) + parts[1:]]
        candidates = [parts]
        candidates.extend(list(prefix) + parts for prefix in self.wildcards)
        return candidates

    # ----- traversal ------------------------------------------------------ #

    def run(self, root) -> list[Finding]:
        self._collect_imports(root)
        for node in h.walk(root):
            ntype = node.type
            if ntype == "call_expression":
                self._inspect_call(node)
            elif ntype == "scoped_identifier":
                self._inspect_path(node)
        return self.findings

    def _inspect_call(self, call) -> None:
        fn = h.call_function(call)
        args = h.positional_args(h.call_arguments(call))
        for parts in self._candidates(h.dotted_parts(fn)):
            if self._match_call(call, parts, args):
                return

    def _inspect_path(self, node) -> None:
        """Flag constants (``signature::ED25519``, ``Algorithm::RS256``, ...).

        Only the outermost path of a non-call expression is considered: inner
        ``scoped_identifier`` nodes repeat their parent's prefix, and a callee is
        already covered by :meth:`_inspect_call`.
        """
        parent = node.parent
        if parent is None:
            return
        if parent.type in _USE_CONTEXT or parent.type == "scoped_identifier":
            return
        if parent.type in ("call_expression", "generic_function"):
            return
        for parts in self._candidates(h.dotted_parts(node)):
            if self._match_constant(node, parts):
                return

    # ----- call matching -------------------------------------------------- #

    def _match_call(self, call, parts: list[str], args) -> bool:
        if len(parts) < 2:
            return False
        crate, tail = parts[0], parts[1:]
        method = tail[-1]

        # --- rsa ---------------------------------------------------------- #
        if crate == "rsa":
            if "Oaep" in tail:
                self._add("PQC002", call, "RSA-OAEP", category=CATEGORY_ENCRYPTION)
                return True
            if "pss" in tail or "BlindedSigningKey" in tail:
                self._add("PQC003", call, "RSA-PSS", category=CATEGORY_SIGNING)
                return True
            if "pkcs1v15" in tail and ("SigningKey" in tail or "VerifyingKey" in tail):
                self._add("PQC003", call, "RSA-PKCS1v15", category=CATEGORY_SIGNING)
                return True
            if "RsaPrivateKey" in tail and method in _RSA_KEYGEN_METHODS:
                bits = next((b for b in (_int_text(a) for a in args) if b), None)
                self._add("PQC001", call, f"RSA-{bits}" if bits else "RSA")
                return True
            return False

        # --- p256 / p384 / p521 / k256 ------------------------------------ #
        curve = EC_CRATES.get(crate)
        if curve is not None:
            if "ecdh" in tail:
                self._add("PQC005", call, f"ECDH-{curve}", category=CATEGORY_KEY_EXCHANGE)
                return True
            if "ecdsa" in tail:
                self._add("PQC004", call, f"ECDSA-{curve}", category=CATEGORY_SIGNING)
                return True
            if "SecretKey" in tail or "PublicKey" in tail:
                self._add(
                    "PQC004", call, f"ECDSA-{curve}", category=CATEGORY_KEY_GENERATION
                )
                return True
            return False

        # --- ed25519 ------------------------------------------------------ #
        if crate in ED25519_CRATES and method in _ED25519_METHODS:
            category = (
                CATEGORY_KEY_GENERATION
                if method in ("generate", "from_bytes", "from_seed", "random")
                else CATEGORY_SIGNING
            )
            self._add("PQC006", call, "Ed25519", category=category)
            return True

        # --- x25519 ------------------------------------------------------- #
        if crate in X25519_CRATES and method in _X25519_METHODS:
            self._add("PQC005", call, "X25519", category=CATEGORY_KEY_EXCHANGE)
            return True

        # --- sha1 / md5 / des --------------------------------------------- #
        if crate in SHA1_CRATES and ("Sha1" in tail or method == "digest"):
            self._add("PQC009", call, "SHA-1")
            return True
        if crate in MD5_CRATES and ("Md5" in tail or method in ("compute", "digest")):
            self._add("PQC010", call, "MD5")
            return True
        if crate == "des":
            for type_name, label in _DES_TYPES.items():
                if type_name in tail:
                    self._add("PQC013", call, label, category=CATEGORY_ENCRYPTION)
                    return True
            return False

        # --- openssl ------------------------------------------------------ #
        if crate == "openssl":
            return self._match_openssl_call(call, tail, method)

        # --- jsonwebtoken ------------------------------------------------- #
        if crate in _JWT_CRATES and method in _JWT_KEY_METHODS:
            self._add(
                "PQC011", call, f"JWT asymmetric key: {method}", category=CATEGORY_SIGNING
            )
            return True

        # --- ring --------------------------------------------------------- #
        if crate == "ring":
            return self._match_ring(call, tail)

        return False

    def _match_openssl_call(self, call, tail: list[str], method: str) -> bool:
        if "Cipher" in tail:
            label = _OPENSSL_DES_CIPHERS.get(method)
            if label:
                self._add("PQC013", call, label, category=CATEGORY_ENCRYPTION)
                return True
            return False
        for (type_name, meth), (rule_id, algorithm) in _OPENSSL_CALLS.items():
            if rule_id is None or meth != method or type_name not in tail:
                continue
            if rule_id == "PQC001":
                bits = next(
                    (b for b in (_int_text(a) for a in h.positional_args(
                        h.call_arguments(call))) if b),
                    None,
                )
                algorithm = f"RSA-{bits}" if bits else algorithm
            self._add(rule_id, call, algorithm)
            return True
        return False

    def _match_ring(self, call, tail: list[str]) -> bool:
        if "rsa" in tail or "RsaKeyPair" in tail:
            self._add("PQC001", call, "RSA")
            return True
        if "agreement" in tail:
            self._add("PQC005", call, "ECDH", category=CATEGORY_KEY_EXCHANGE)
            return True
        return False

    # ----- constant matching ---------------------------------------------- #

    def _match_constant(self, node, parts: list[str]) -> bool:
        if len(parts) < 2:
            return False
        crate, tail = parts[0], parts[1:]
        name = tail[-1]

        if crate == "ring":
            if "signature" in tail:
                if name.startswith("RSA_"):
                    self._add("PQC003", node, "RSA", category=CATEGORY_SIGNING)
                    return True
                curve_match = _RING_ECDSA_CURVE_RE.match(name)
                if curve_match:
                    curve = curve_match.group(1).replace("P", "P-")
                    self._add(
                        "PQC004", node, f"ECDSA-{curve}", category=CATEGORY_SIGNING
                    )
                    return True
                if name.upper().startswith("ED25519"):
                    self._add("PQC006", node, "Ed25519", category=CATEGORY_SIGNING)
                    return True
                return False
            if "agreement" in tail:
                label = _RING_AGREEMENT.get(name)
                if label:
                    self._add("PQC005", node, label, category=CATEGORY_KEY_EXCHANGE)
                    return True
                return False
            if "digest" in tail and name.startswith("SHA1"):
                self._add("PQC009", node, "SHA-1")
                return True
            return False

        if crate == "rsa":
            entry = _RSA_TYPES.get(name)
            if entry and entry[0] in ("PQC002", "PQC003"):
                rule_id, algorithm = entry
                category = (
                    CATEGORY_ENCRYPTION if rule_id == "PQC002" else CATEGORY_SIGNING
                )
                self._add(rule_id, node, algorithm, category=category)
                return True
            return False

        if crate in _JWT_CRATES and "Algorithm" in tail and name in _JWT_ASYMMETRIC:
            self._add(
                "PQC011", node, f"JWT algorithm: {name}", category=CATEGORY_SIGNING
            )
            return True

        if crate == "openssl" and "SslVersion" in tail:
            label = _OPENSSL_LEGACY_TLS.get(name)
            if label:
                self._add(
                    "PQC012", node, f"Outdated TLS protocol pinned: {label}",
                    category=CATEGORY_CONFIGURATION, severity=SEVERITY_HIGH,
                )
                return True
            return False

        return False


def analyze(root, source_text: str, file_path: str | Path) -> list[Finding]:
    """Entry point used by the AST scanner."""
    return _RustAnalyzer(source_text, str(file_path)).run(root)
