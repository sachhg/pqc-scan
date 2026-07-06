"""Configuration-file scanner (YAML / JSON / TOML / .conf / nginx / .env).

Configuration files have no single universal AST, so this scanner works line by
line with tightly-scoped patterns. Cipher tokens are only flagged inside an
actual hyphen/underscore-joined cipher suite (so a stray ``RSA`` key in YAML is
not a false positive), and TLS version detection deliberately ignores TLS 1.2 /
1.3. The goal is zero findings on a modern, hardened config.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import (
    CATEGORY_CONFIGURATION,
    CONFIDENCE_HIGH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    BaseScanner,
    Finding,
    ScanContext,
    build_finding,
)

CONFIG_SUFFIXES = {
    ".yml", ".yaml", ".json", ".toml",
    ".conf", ".cnf", ".cfg", ".ini", ".env", ".properties",
}
CONFIG_FILENAMES = {
    "nginx.conf", "apache2.conf", "httpd.conf", "ssl.conf", "tls.conf",
    ".env", "docker-compose.yml", "docker-compose.yaml",
}

# Weak / quantum-vulnerable cipher-suite parts (whole-token match).
_WEAK_CIPHER_PARTS = {
    "RSA", "ECDSA", "DSS",
    "RC4", "DES", "3DES", "NULL", "EXP", "EXPORT", "ADH", "AECDH", "ANON", "MD5",
}
# Parts that escalate a cipher finding to high severity (truly broken).
_BROKEN_CIPHER_PARTS = {"RC4", "DES", "3DES", "NULL", "EXP", "EXPORT", "ADH", "AECDH", "ANON", "MD5"}

# A cipher-suite-shaped token: an uppercase chunk with >= 1 dash/underscore join
# (so 2-part suites like RC4-MD5 / NULL-SHA are caught). False positives on
# arbitrary uppercase constants are prevented by the cipher-anchor gate below.
_SUITE_RE = re.compile(r"\b[A-Z0-9]+(?:[-_][A-Z0-9]+){1,}\b")
_PART_SPLIT_RE = re.compile(r"[-_]")

# A token that marks a string as an actual cipher suite (a real cipher / mode /
# key-exchange component), so MY-RSA-KEY-PATH or CONTENT-MD5 are not flagged.
_CIPHER_ANCHORS = {
    "GCM", "CBC", "CCM", "POLY1305", "RC4", "DES", "3DES", "NULL",
    "IDEA", "ECDHE", "DHE", "EDH", "EECDH", "EXPORT", "EXP", "KRB5",
}
_CIPHER_ANCHOR_PREFIXES = ("AES", "CAMELLIA", "ARIA", "CHACHA", "SEED")


def _has_cipher_anchor(parts: set[str]) -> bool:
    for p in parts:
        if p in _CIPHER_ANCHORS or p.startswith(_CIPHER_ANCHOR_PREFIXES):
            return True
    return False


# Outdated protocol versions (case-insensitive). The 'v' is optional and the
# negative lookahead deliberately excludes TLS 1.2 / 1.3 in dot or underscore
# form (TLSv1.2, PROTOCOL_TLSv1_3, etc.).
_TLS_LEGACY_RE = re.compile(
    r"(?<![A-Za-z0-9])TLS_?v?1(?:[._][01])?(?![A-Za-z0-9._])", re.IGNORECASE
)
_SSL_LEGACY_RE = re.compile(r"(?<![A-Za-z0-9])SSL_?v?[23](?![A-Za-z0-9])", re.IGNORECASE)

# An SSLProtocol / ssl_protocols directive line, where a leading '-' on a token
# means "disable this protocol" (e.g. Apache's `SSLProtocol all -SSLv2 -SSLv3`).
_PROTOCOL_DIRECTIVE_RE = re.compile(r"ssl[_-]?protocols?\b", re.IGNORECASE)

_MIN_VERSION_RE = re.compile(
    r"(?:tls[_-]?min(?:imum)?[_-]?version|min[_-]?tls[_-]?version|ssl[_-]?version|"
    r"minimum[_-]?protocol[_-]?version)\s*[:=]\s*['\"]?(?:TLSv?)?1[._.]?([01])\b",
    re.IGNORECASE,
)

def _is_disabled_protocol(line: str, match_start: int) -> bool:
    """In an SSLProtocol / ssl_protocols directive, a '-' immediately before a
    protocol token disables that protocol, so it must not be flagged as enabled
    (e.g. `SSLProtocol all -SSLv2 -SSLv3` is a *secure* config)."""
    if match_start > 0 and line[match_start - 1] == "-":
        return bool(_PROTOCOL_DIRECTIVE_RE.search(line))
    return False


_KEY_TYPE_RSA_RE = re.compile(r"\bkey[_-]?type\s*[:=]\s*['\"]?(rsa|ec|ecdsa|dsa)\b", re.IGNORECASE)
_CERT_SHA1_RE = re.compile(r"\bsha-?1\s*with\s*rsa", re.IGNORECASE)
_CERT_MD5_RE = re.compile(r"\bmd5\s*with\s*rsa", re.IGNORECASE)


class ConfigScanner(BaseScanner):
    name = "config"

    def __init__(self, context: ScanContext | None = None):
        self.context = context or ScanContext()

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in CONFIG_SUFFIXES or path.name in CONFIG_FILENAMES

    def scan_file(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings: list[Finding] = []
        seen: set[tuple] = set()

        def emit(rule_id, line_no, col, algorithm, snippet, severity, *, category=CATEGORY_CONFIGURATION):
            if not self.context.rule_enabled(rule_id):
                return
            key = (rule_id, line_no, col)
            if key in seen:
                return
            seen.add(key)
            findings.append(
                build_finding(
                    rule_id=rule_id,
                    file_path=str(path),
                    line_number=line_no,
                    column_number=col,
                    algorithm=algorithm,
                    code_snippet=snippet.strip()[:200],
                    severity=severity,
                    confidence=CONFIDENCE_HIGH,
                    category=category,
                )
            )

        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Cipher suites: a weak token plus a genuine cipher anchor. A '!'
            # or '-' immediately before the token is an OpenSSL cipher-string
            # *exclusion* ('HIGH:!3DES:!EXP-RC4-MD5' disables those suites), so
            # it must not be flagged as enabled.
            for m in _SUITE_RE.finditer(line):
                if m.start() > 0 and line[m.start() - 1] in "!-":
                    continue
                parts = set(_PART_SPLIT_RE.split(m.group(0).upper()))
                weak = parts & _WEAK_CIPHER_PARTS
                if weak and _has_cipher_anchor(parts):
                    sev = SEVERITY_HIGH if (parts & _BROKEN_CIPHER_PARTS) else SEVERITY_MEDIUM
                    emit("PQC012", idx, m.start() + 1, f"TLS cipher suite: {m.group(0)}",
                         line, sev)

            # Certificate signature algorithms (cert signing => critical)
            for rule_id, rx, algo in (
                ("PQC009", _CERT_SHA1_RE, "SHA-1 (sha1WithRSAEncryption)"),
                ("PQC010", _CERT_MD5_RE, "MD5 (md5WithRSAEncryption)"),
            ):
                m = rx.search(line)
                if m:
                    emit(rule_id, idx, m.start() + 1, algo, line, SEVERITY_CRITICAL)

            # Legacy protocol versions (skip tokens explicitly disabled with '-')
            for m in _TLS_LEGACY_RE.finditer(line):
                if _is_disabled_protocol(line, m.start()):
                    continue
                emit("PQC012", idx, m.start() + 1, f"Outdated protocol: {m.group(0)}",
                     line, SEVERITY_HIGH)
            for m in _SSL_LEGACY_RE.finditer(line):
                if _is_disabled_protocol(line, m.start()):
                    continue
                emit("PQC012", idx, m.start() + 1, f"Outdated protocol: {m.group(0)}",
                     line, SEVERITY_HIGH)
            mv = _MIN_VERSION_RE.search(line)
            if mv:
                emit("PQC012", idx, mv.start() + 1,
                     f"Minimum TLS version 1.{mv.group(1)} (allows TLS 1.0/1.1)",
                     line, SEVERITY_HIGH)

            # key_type: rsa / ec / dsa
            kt = _KEY_TYPE_RSA_RE.search(line)
            if kt:
                kind = kt.group(1).lower()
                rule_id, algo = {
                    "rsa": ("PQC001", "RSA"),
                    "ec": ("PQC004", "ECDSA"),
                    "ecdsa": ("PQC004", "ECDSA"),
                    "dsa": ("PQC008", "DSA"),
                }[kind]
                emit(rule_id, idx, kt.start() + 1, f"key_type: {kind}", line,
                     SEVERITY_MEDIUM)

        return findings
