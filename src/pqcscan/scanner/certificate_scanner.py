"""Key-material and certificate scanner (PQC015 / PQC016).

Source code says which algorithm a program *will* use; key files say which
algorithm an organization is *already committed to*. Those are different
migration problems: a key or certificate outlives the code that produced it,
every relying party has to accept its replacement, and a key protecting
long-lived secrets is a harvest-now-decrypt-later target today. A PQC inventory
that only reads source misses all of it.

Detection reads the actual DER structure rather than trusting the PEM label,
because the label is ambiguous: a block labelled ``PRIVATE KEY`` is PKCS#8 and may
hold RSA, EC, Ed25519 — or ML-DSA, which must not be flagged. Only algorithms on
a known quantum-vulnerable OID list produce a finding, so an unrecognized or
post-quantum key is silently (and correctly) ignored.

Covered inputs:

* PEM blocks — private keys (PKCS#1 / PKCS#8 / SEC1 / OpenSSH), public keys,
  X.509 certificates, certificate requests, and DH parameters.
* OpenSSH public keys — ``id_*.pub``, ``authorized_keys``, ``known_hosts``.
* PEM blocks inlined into configuration files, where keys most often get pasted.

Encrypted private keys are deliberately skipped: their algorithm cannot be
determined without the passphrase, and guessing from the label would be wrong as
often as right.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from . import asn1
from .base import (
    CATEGORY_CERTIFICATE,
    CATEGORY_KEY_MATERIAL,
    CONFIDENCE_HIGH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    BaseScanner,
    Finding,
    ScanContext,
    build_finding,
)

# --------------------------------------------------------------------------- #
# What this scanner is offered
# --------------------------------------------------------------------------- #

KEY_SUFFIXES = {
    ".pem", ".crt", ".cer", ".key", ".pub", ".csr", ".p8", ".pk8", ".p7b", ".ca-bundle",
}
KEY_FILENAMES = {
    "authorized_keys", "authorized_keys2", "known_hosts",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ssh_host_rsa_key",
    "ssh_host_dsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key",
}
# Configuration formats get a second pass: inlined PEM blocks in Kubernetes
# secrets, Helm values, docker-compose files and .env files are common, and the
# config scanner's line patterns cannot identify a key's algorithm.
EMBEDDED_SUFFIXES = {
    ".yml", ".yaml", ".json", ".toml", ".conf", ".cnf", ".cfg", ".ini", ".env",
    ".properties",
}

# --------------------------------------------------------------------------- #
# OID tables — the single source of truth for "is this quantum-vulnerable?"
# --------------------------------------------------------------------------- #

# Public-key algorithm OIDs -> (display label, migration algorithm_family).
_PUBLIC_KEY_OIDS: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.1": ("RSA", "rsa"),            # rsaEncryption
    "1.2.840.113549.1.1.10": ("RSA-PSS", "rsa-signature"),
    "1.2.840.113549.1.1.7": ("RSA-OAEP", "rsa-encryption"),
    "1.2.840.10045.2.1": ("EC", "ecdsa"),              # id-ecPublicKey
    "1.2.840.10040.4.1": ("DSA", "dsa"),               # id-dsa
    "1.2.840.113549.1.3.1": ("DH", "dh"),              # dhKeyAgreement
    "1.2.840.10046.2.1": ("DH", "dh"),                 # dhpublicnumber (X9.42)
    "1.3.101.112": ("Ed25519", "ed25519"),
    "1.3.101.113": ("Ed448", "ed25519"),
    "1.3.101.110": ("X25519", "x25519"),
    "1.3.101.111": ("X448", "x25519"),
}

# Named-curve OIDs -> friendly parameter-set label.
_CURVE_OIDS: dict[str, str] = {
    "1.2.840.10045.3.1.1": "P-192",
    "1.3.132.0.33": "P-224",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.10": "secp256k1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
}

# Signature algorithm OIDs -> (display name, hash family or None).
# The hash family drives the separate PQC009 / PQC010 finding: a certificate
# signed with SHA-1 or MD5 is broken *today*, independent of the quantum threat.
_SIGNATURE_OIDS: dict[str, tuple[str, Optional[str]]] = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", None),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", None),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", None),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", None),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", None),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", None),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", None),
    "1.2.840.10040.4.3": ("dsa-with-SHA1", "sha1"),
    "2.16.840.1.101.3.4.3.1": ("dsa-with-SHA224", None),
    "2.16.840.1.101.3.4.3.2": ("dsa-with-SHA256", None),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", "md5"),
}

_COMMON_NAME_OID = "2.5.4.3"

# --------------------------------------------------------------------------- #
# PEM extraction
# --------------------------------------------------------------------------- #

#: PEM boundary markers. Blocks are paired in a single linear pass (see
#: :func:`_iter_pem_blocks`) rather than matched by one regex that contains the
#: body — a backreferenced ``.*?`` body makes every *unterminated* BEGIN marker
#: scan to end of file, which is quadratic in the number of markers. A 0.5 MB
#: file of bare BEGIN lines took ~39s that way; pairing makes it linear.
_PEM_BOUNDARY_RE = re.compile(r"-----(BEGIN|END) ([A-Z][A-Z0-9 ]*)-----")
# RFC 1421 headers inside a legacy encrypted PEM block ("Proc-Type: 4,ENCRYPTED").
_PEM_HEADER_RE = re.compile(r"^[A-Za-z-]+:.*$", re.MULTILINE)
# JSON and .env files carry PEM bodies with literal backslash-n separators.
_ESCAPED_NEWLINE_RE = re.compile(r"\\+[rn]")

#: Labels whose algorithm cannot be determined without a passphrase.
_UNDETERMINED_LABELS = {"ENCRYPTED PRIVATE KEY"}

_OPENSSH_MAGIC = b"openssh-key-v1\x00"

# OpenSSH key type -> (label, family). Certificate variants share the key type.
_SSH_KEY_TYPES: dict[str, tuple[str, str]] = {
    "ssh-rsa": ("RSA", "rsa"),
    "rsa-sha2-256": ("RSA", "rsa"),
    "rsa-sha2-512": ("RSA", "rsa"),
    "ssh-dss": ("DSA", "dsa"),
    "ssh-ed25519": ("Ed25519", "ed25519"),
    "ssh-ed448": ("Ed448", "ed25519"),
    "sk-ssh-ed25519@openssh.com": ("Ed25519", "ed25519"),
    "ecdsa-sha2-nistp256": ("ECDSA-P-256", "ecdsa"),
    "ecdsa-sha2-nistp384": ("ECDSA-P-384", "ecdsa"),
    "ecdsa-sha2-nistp521": ("ECDSA-P-521", "ecdsa"),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA-P-256", "ecdsa"),
}
_SSH_CERT_SUFFIX = "-cert-v01@openssh.com"

_SSH_LINE_RE = re.compile(
    r"(?<![A-Za-z0-9@.-])((?:sk-)?(?:ssh|ecdsa|rsa)[A-Za-z0-9@.-]*)\s+([A-Za-z0-9+/]{32,}={0,2})"
)


@dataclass(frozen=True)
class KeyInfo:
    """What was learned about one key or certificate."""

    algorithm: str
    family: str
    detail: str = ""


# --------------------------------------------------------------------------- #
# DER helpers
# --------------------------------------------------------------------------- #


def _rsa_modulus_bits(sequence: asn1.Node) -> Optional[int]:
    """Bit length of the RSA modulus in an RSAPublicKey / RSAPrivateKey SEQUENCE."""
    children = sequence.children()
    for index, child in enumerate(children):
        if child.tag != asn1.TAG_INTEGER:
            continue
        bits = asn1.integer_bit_length(child)
        # RSAPublicKey is {n, e}: the modulus is first. RSAPrivateKey is
        # {version, n, e, ...}: the version is a small integer, so skip it.
        if index == 0 and bits > 512:
            return bits
        if index == 1 and bits > 512:
            return bits
    return None


def _rsa_label(bits: Optional[int]) -> str:
    return f"RSA-{bits}" if bits else "RSA"


def _algorithm_identifier(algid: asn1.Node) -> Optional[KeyInfo]:
    """Decode an AlgorithmIdentifier SEQUENCE into a KeyInfo, or None if safe.

    Returning ``None`` for an unrecognized OID is the precision gate: a
    post-quantum key (ML-KEM / ML-DSA / SLH-DSA) or an algorithm we do not model
    must never be reported as quantum-vulnerable.
    """
    children = algid.children()
    if not children or children[0].tag != asn1.TAG_OID:
        return None
    try:
        oid = asn1.oid_string(children[0])
    except asn1.Asn1Error:
        return None
    entry = _PUBLIC_KEY_OIDS.get(oid)
    if entry is None:
        return None
    label, family = entry
    if label == "EC":
        curve = None
        if len(children) > 1 and children[1].tag == asn1.TAG_OID:
            try:
                curve = _CURVE_OIDS.get(asn1.oid_string(children[1]))
            except asn1.Asn1Error:
                curve = None
        return KeyInfo(f"ECDSA-{curve}" if curve else "ECDSA", family)
    return KeyInfo(label, family)


def _subject_public_key_info(spki: asn1.Node) -> Optional[KeyInfo]:
    """Decode a SubjectPublicKeyInfo, filling in the RSA key size when present."""
    children = spki.children()
    if len(children) < 2 or children[0].tag != asn1.TAG_SEQUENCE:
        return None
    info = _algorithm_identifier(children[0])
    if info is None:
        return None
    if info.family == "rsa" and children[1].tag == asn1.TAG_BIT_STRING:
        # A BIT STRING's first content byte counts unused bits; the DER-encoded
        # RSAPublicKey follows it.
        content = children[1].content
        if content and content[0] == 0:
            try:
                bits = _rsa_modulus_bits(asn1.read(content[1:]))
            except asn1.Asn1Error:
                bits = None
            if bits:
                return KeyInfo(_rsa_label(bits), info.family, info.detail)
    return info


def _looks_like_spki(node: asn1.Node) -> bool:
    if node.tag != asn1.TAG_SEQUENCE:
        return False
    children = node.children()
    return (
        len(children) == 2
        and children[0].tag == asn1.TAG_SEQUENCE
        and children[1].tag == asn1.TAG_BIT_STRING
        and bool(children[0].children())
        and children[0].children()[0].tag == asn1.TAG_OID
    )


def _common_name(name: asn1.Node) -> Optional[str]:
    """The commonName attribute of an X.501 Name, if it has one."""
    for node in asn1.walk(name):
        if node.tag != asn1.TAG_SEQUENCE:
            continue
        children = node.children()
        if len(children) != 2 or children[0].tag != asn1.TAG_OID:
            continue
        try:
            if asn1.oid_string(children[0]) != _COMMON_NAME_OID:
                continue
        except asn1.Asn1Error:
            continue
        try:
            return children[1].content.decode("utf-8", errors="replace").strip()
        except Exception:  # pragma: no cover - defensive
            return None
    return None


def _not_after(tbs: asn1.Node) -> Optional[str]:
    """The certificate's notAfter, as written (YYMMDD.. / YYYYMMDD..).

    Expiry drives migration sequencing: a certificate valid past the 2030/2035
    CNSA 2.0 deadlines has to be reissued with a post-quantum algorithm anyway.
    """
    for child in tbs.children():
        if child.tag != asn1.TAG_SEQUENCE:
            continue
        times = child.children()
        if len(times) == 2 and all(t.tag in (0x17, 0x18) for t in times):
            raw = times[1].content.decode("ascii", errors="replace")
            if len(raw) >= 6:
                if times[1].tag == 0x17:  # UTCTime: YY -> 20YY / 19YY
                    year = int(raw[0:2])
                    century = "20" if year < 50 else "19"
                    return f"{century}{raw[0:2]}-{raw[2:4]}-{raw[4:6]}"
                return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
    return None


# --------------------------------------------------------------------------- #
# OpenSSH blob helpers
# --------------------------------------------------------------------------- #


def _ssh_strings(blob: bytes) -> Iterator[bytes]:
    """Yield the length-prefixed fields of an SSH wire-format blob."""
    offset = 0
    while offset + 4 <= len(blob):
        length = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4
        if length > len(blob) - offset:
            return
        yield blob[offset : offset + length]
        offset += length


def _ssh_key_info(blob: bytes) -> Optional[KeyInfo]:
    """Identify an SSH public-key blob (``ssh-rsa AAAA...`` decoded)."""
    fields = list(_ssh_strings(blob))
    if not fields:
        return None
    key_type = fields[0].decode("ascii", errors="replace")
    base_type = key_type.replace(_SSH_CERT_SUFFIX, "")
    entry = _SSH_KEY_TYPES.get(base_type)
    if entry is None:
        return None
    label, family = entry
    if family == "rsa":
        # ssh-rsa blob is {type, e, n}; the modulus is the third field.
        if len(fields) >= 3:
            modulus = fields[2].lstrip(b"\x00")
            if modulus:
                label = _rsa_label(len(modulus) * 8 - (8 - modulus[0].bit_length()))
    detail = "OpenSSH certificate" if key_type.endswith(_SSH_CERT_SUFFIX) else ""
    return KeyInfo(label, family, detail)


def _openssh_private_key_info(der: bytes) -> Optional[KeyInfo]:
    """Identify an ``OPENSSH PRIVATE KEY`` block from its embedded public key.

    The container is ``magic || ciphername || kdfname || kdfoptions || uint32
    nkeys || publickey``. The bare ``uint32`` between the headers and the public
    key is why this needs a cursor rather than a flat run of length-prefixed
    fields — the private half is encrypted or padded, but the public key always
    names the algorithm in the clear.
    """
    if not der.startswith(_OPENSSH_MAGIC):
        return None
    offset = len(_OPENSSH_MAGIC)

    def read_string() -> Optional[bytes]:
        nonlocal offset
        if offset + 4 > len(der):
            return None
        length = int.from_bytes(der[offset : offset + 4], "big")
        offset += 4
        if length > len(der) - offset:
            return None
        value = der[offset : offset + length]
        offset += length
        return value

    for _ in range(3):  # ciphername, kdfname, kdfoptions
        if read_string() is None:
            return None
    if offset + 4 > len(der):
        return None
    offset += 4  # uint32 number of keys
    public_blob = read_string()
    if public_blob is None:
        return None
    return _ssh_key_info(public_blob)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


class CertificateScanner(BaseScanner):
    """Inventories stored key material and certificates."""

    name = "certificate"

    def __init__(self, context: ScanContext | None = None):
        self.context = context or ScanContext()

    def supports(self, path: Path) -> bool:
        return (
            path.suffix.lower() in KEY_SUFFIXES
            or path.name in KEY_FILENAMES
            or path.suffix.lower() in EMBEDDED_SUFFIXES
        )

    def scan_file(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.scan_text(text, path)

    def scan_text(self, text: str, path: Path | str) -> list[Finding]:
        if "-----BEGIN" not in text and not _SSH_LINE_RE.search(text):
            return []
        emitter = _Emitter(str(path), self.context)
        starts = _line_starts(text)
        self._scan_pem_blocks(text, starts, emitter)
        self._scan_ssh_public_keys(text, starts, emitter)
        return emitter.findings

    # ----- PEM ------------------------------------------------------------ #

    def _scan_pem_blocks(self, text: str, starts: list[int], emit: "_Emitter") -> None:
        for label, body, start_index in _iter_pem_blocks(text):
            if label in _UNDETERMINED_LABELS:
                continue
            der = _decode_pem_body(body)
            if der is None:
                continue
            line, col = _position(text, start_index, starts)
            snippet = f"-----BEGIN {label}-----"
            if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
                self._emit_certificate(der, emit, line, col, snippet, kind="certificate")
            elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                self._emit_request(der, emit, line, col, snippet)
            elif label == "OPENSSH PRIVATE KEY":
                info = _openssh_private_key_info(der)
                emit.key(info, line, col, snippet, private=True, form="OpenSSH")
            elif label == "DH PARAMETERS":
                emit.key(
                    KeyInfo("DH", "dh"), line, col, snippet,
                    private=True, form="PEM", noun="Diffie-Hellman parameters",
                )
            else:
                info = _private_or_public_key_info(label, der)
                private = "PRIVATE" in label
                emit.key(info, line, col, snippet, private=private, form="PEM")

    def _emit_certificate(
        self, der: bytes, emit: "_Emitter", line: int, col: int, snippet: str, *, kind: str
    ) -> None:
        try:
            cert = asn1.read(der)
            children = cert.children()
        except asn1.Asn1Error:
            return
        if len(children) < 2:
            return
        tbs = children[0]
        signature_name, weak_hash = _signature_algorithm(children[1])

        info = None
        for child in tbs.children():
            if _looks_like_spki(child):
                info = _subject_public_key_info(child)
                break

        subject = None
        expires = _not_after(tbs)
        for index, child in enumerate(tbs.children()):
            if _looks_like_spki(child) and index > 0:
                previous = tbs.children()[index - 1]
                if previous.tag == asn1.TAG_SEQUENCE:
                    subject = _common_name(previous)
                break

        emit.certificate(
            info, line, col, snippet,
            kind=kind, subject=subject, expires=expires, signature=signature_name,
        )
        if weak_hash:
            emit.weak_certificate_hash(weak_hash, signature_name, line, col, snippet)

    def _emit_request(
        self, der: bytes, emit: "_Emitter", line: int, col: int, snippet: str
    ) -> None:
        try:
            request = asn1.read(der)
        except asn1.Asn1Error:
            return
        info = None
        for node in asn1.walk(request):
            if _looks_like_spki(node):
                info = _subject_public_key_info(node)
                break
        emit.certificate(
            info, line, col, snippet, kind="certificate request",
            subject=None, expires=None, signature=None,
        )

    # ----- OpenSSH public keys -------------------------------------------- #

    def _scan_ssh_public_keys(self, text: str, starts: list[int], emit: "_Emitter") -> None:
        for match in _SSH_LINE_RE.finditer(text):
            try:
                blob = base64.b64decode(match.group(2), validate=True)
            except (binascii.Error, ValueError):
                continue
            info = _ssh_key_info(blob)
            if info is None:
                continue
            line, col = _position(text, match.start(), starts)
            emit.key(
                info, line, col, f"{match.group(1)} {match.group(2)[:24]}...",
                private=False, form="OpenSSH",
            )


class _Emitter:
    """Builds findings, deduplicating by (rule, line, column)."""

    def __init__(self, file_path: str, context: ScanContext):
        self.file_path = file_path
        self.context = context
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

    def _add(self, rule_id: str, line: int, col: int, **kwargs) -> None:
        if not self.context.rule_enabled(rule_id):
            return
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
                confidence=CONFIDENCE_HIGH,
                **kwargs,
            )
        )

    def key(
        self, info: Optional[KeyInfo], line: int, col: int, snippet: str, *,
        private: bool, form: str, noun: Optional[str] = None,
    ) -> None:
        if info is None:
            return
        from pqcscan.migration.suggestions import get_suggestion

        label = noun or (f"{form} private key" if private else f"{form} public key")
        detail = f" ({info.detail})" if info.detail else ""
        self._add(
            "PQC015", line, col,
            algorithm=info.algorithm,
            code_snippet=snippet,
            severity=SEVERITY_HIGH if private else SEVERITY_MEDIUM,
            category=CATEGORY_KEY_MATERIAL,
            description=(
                f"{label}{detail} using {info.algorithm}, which is broken by Shor's "
                "algorithm. Stored keys outlive the code that created them: inventory "
                "where this key is trusted, issue a post-quantum replacement, then "
                "revoke and destroy the old one."
            ),
            migration=get_suggestion(info.family),
        )

    def certificate(
        self, info: Optional[KeyInfo], line: int, col: int, snippet: str, *,
        kind: str, subject: Optional[str], expires: Optional[str],
        signature: Optional[str],
    ) -> None:
        if info is None:
            return
        from pqcscan.migration.suggestions import get_suggestion

        facts = []
        if subject:
            facts.append(f"subject CN={subject}")
        if signature:
            facts.append(f"signed with {signature}")
        if expires:
            facts.append(f"expires {expires}")
        suffix = f" ({'; '.join(facts)})" if facts else ""
        self._add(
            "PQC016", line, col,
            algorithm=info.algorithm,
            code_snippet=snippet,
            severity=SEVERITY_HIGH if kind == "certificate" else SEVERITY_MEDIUM,
            category=CATEGORY_CERTIFICATE,
            description=(
                f"X.509 {kind} with a {info.algorithm} public key{suffix}. The key and "
                "its signature are broken by Shor's algorithm, and every relying party "
                "must accept the replacement algorithm before you can reissue — start "
                "the inventory now."
            ),
            migration=get_suggestion("certificate"),
        )

    def weak_certificate_hash(
        self, family: str, signature: str, line: int, col: int, snippet: str
    ) -> None:
        rule_id = "PQC009" if family == "sha1" else "PQC010"
        algorithm = "SHA-1" if family == "sha1" else "MD5"
        self._add(
            rule_id, line, col,
            algorithm=f"{algorithm} ({signature})",
            code_snippet=snippet,
            # A certificate signature is the one place where a broken hash is
            # directly forgeable, so it outranks ordinary SHA-1/MD5 usage.
            severity=SEVERITY_CRITICAL,
            category=CATEGORY_CERTIFICATE,
            description=(
                f"Certificate signed with {signature}. {algorithm} is classically "
                "broken (practical chosen-prefix collisions), so this signature is "
                "forgeable today — no quantum computer required. Reissue the "
                "certificate with at least SHA-256 immediately."
            ),
        )


# --------------------------------------------------------------------------- #
# Shared decoding utilities
# --------------------------------------------------------------------------- #


def _iter_pem_blocks(text: str) -> Iterator[tuple[str, str, int]]:
    """Yield ``(label, body, start_index)`` for every well-formed PEM block.

    An END marker closes the most recent BEGIN with the same label, so a
    concatenated certificate chain yields one block per certificate and an
    unterminated BEGIN simply never yields. Labels that never pair are dropped.
    """
    pending: dict[str, tuple[int, int]] = {}
    for match in _PEM_BOUNDARY_RE.finditer(text):
        kind, label = match.group(1), match.group(2).strip()
        if kind == "BEGIN":
            pending[label] = (match.end(), match.start())
        else:
            entry = pending.pop(label, None)
            if entry is not None:
                body_start, begin_index = entry
                yield label, text[body_start : match.start()], begin_index


def _decode_pem_body(body: str) -> Optional[bytes]:
    """Base64-decode a PEM body, tolerating RFC 1421 headers and escaped newlines."""
    cleaned = _PEM_HEADER_RE.sub("", body)
    cleaned = _ESCAPED_NEWLINE_RE.sub("", cleaned)
    cleaned = "".join(cleaned.split())
    if not cleaned:
        return None
    # Tolerate a body whose padding was mangled by the surrounding format.
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned)
    except (binascii.Error, ValueError):
        return None


def _private_or_public_key_info(label: str, der: bytes) -> Optional[KeyInfo]:
    """Identify a PEM key block from its DER, using the label only as a hint."""
    try:
        node = asn1.read(der)
    except asn1.Asn1Error:
        return None

    if label == "RSA PRIVATE KEY":
        return KeyInfo(_rsa_label(_rsa_modulus_bits(node)), "rsa")
    if label == "RSA PUBLIC KEY":
        return KeyInfo(_rsa_label(_rsa_modulus_bits(node)), "rsa")
    if label == "DSA PRIVATE KEY":
        return KeyInfo("DSA", "dsa")
    if label == "EC PRIVATE KEY":
        # SEC1 ECPrivateKey: the curve is a tagged [0] OID.
        for child in asn1.walk(node):
            if child.tag == asn1.TAG_OID:
                try:
                    curve = _CURVE_OIDS.get(asn1.oid_string(child))
                except asn1.Asn1Error:
                    continue
                if curve:
                    return KeyInfo(f"ECDSA-{curve}", "ecdsa")
        return KeyInfo("ECDSA", "ecdsa")

    if label == "PUBLIC KEY":
        return _subject_public_key_info(node)

    if label in ("PRIVATE KEY", "PKCS8 PRIVATE KEY"):
        # PKCS#8 PrivateKeyInfo: {version, AlgorithmIdentifier, privateKey}.
        children = node.children()
        for child in children:
            if child.tag == asn1.TAG_SEQUENCE:
                info = _algorithm_identifier(child)
                if info is None:
                    return None
                if info.family == "rsa":
                    bits = _pkcs8_rsa_bits(children)
                    if bits:
                        return KeyInfo(_rsa_label(bits), info.family)
                return info
        return None

    return None


def _pkcs8_rsa_bits(children: list[asn1.Node]) -> Optional[int]:
    """RSA key size from the PKCS#8 privateKey OCTET STRING's inner PKCS#1 blob."""
    for child in children:
        if child.tag != asn1.TAG_OCTET_STRING:
            continue
        try:
            return _rsa_modulus_bits(asn1.read(child.content))
        except asn1.Asn1Error:
            return None
    return None


def _signature_algorithm(algid: asn1.Node) -> tuple[Optional[str], Optional[str]]:
    """(display name, weak-hash family) for a certificate's signatureAlgorithm."""
    children = algid.children()
    if not children or children[0].tag != asn1.TAG_OID:
        return None, None
    try:
        oid = asn1.oid_string(children[0])
    except asn1.Asn1Error:
        return None, None
    entry = _SIGNATURE_OIDS.get(oid)
    if entry is None:
        return oid, None
    return entry


def _line_starts(text: str) -> list[int]:
    """Offsets at which each line begins, built once per file.

    Resolving a position by counting newlines from byte 0 is O(offset), so
    doing it per match is quadratic in a file with many matches — the same
    trap the PEM boundary scan avoids. One index plus a binary search per
    match keeps the whole pass linear.
    """
    starts = [0]
    index = text.find("\n")
    while index != -1:
        starts.append(index + 1)
        index = text.find("\n", index + 1)
    return starts


def _position(text: str, index: int, starts: Optional[list[int]] = None) -> tuple[int, int]:
    """1-based (line, column) of *index* in *text*."""
    if starts is None:
        starts = _line_starts(text)
    line = bisect.bisect_right(starts, index)
    return line, index - starts[line - 1] + 1
