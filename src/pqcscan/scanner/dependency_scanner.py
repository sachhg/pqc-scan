"""Dependency-manifest scanner.

Flags declared dependencies whose primary purpose is quantum-vulnerable
cryptography (RSA / ECC / DH / legacy hashes). A flagged dependency does not
prove a vulnerable code path is exercised, so findings stay at or below ``high``
and the message says "verify usage and plan migration".

Manifests are parsed per ecosystem rather than grepped, so a version string that
happens to contain a library name does not fire:

===============================  ====================================
Manifest                         Ecosystem
===============================  ====================================
``requirements*.txt``, ``setup.py``,
``pyproject.toml``, ``Pipfile``  Python
``package.json``                 JavaScript / npm
``Cargo.toml``                   Rust / crates.io
``go.mod``                       Go modules
``pom.xml``, ``build.gradle``,
``build.gradle.kts``             Java (Maven / Gradle)
``Gemfile``, ``*.gemspec``       Ruby
``composer.json``                PHP / Packagist
===============================  ====================================

Lock files are deliberately not scanned: they restate the manifest's direct
dependencies plus the whole transitive closure, which would bury the actionable
direct declaration under dozens of duplicates.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .base import (
    CATEGORY_DEPENDENCY,
    CONFIDENCE_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    BaseScanner,
    Finding,
    ScanContext,
    build_finding,
)

# --------------------------------------------------------------------------- #
# Flagged-library registries: normalized name -> (severity, note)
# --------------------------------------------------------------------------- #

_PYTHON_DEPS: dict[str, tuple[str, str]] = {
    "pycrypto": (SEVERITY_HIGH, "Unmaintained library providing RSA/ECC/DSA (and carrying known CVEs)."),
    "pycryptodome": (SEVERITY_LOW, "General-purpose crypto library; verify whether RSA/ECC code paths are used."),
    "pycryptodomex": (SEVERITY_LOW, "General-purpose crypto library; verify whether RSA/ECC code paths are used."),
    "pyopenssl": (SEVERITY_LOW, "Wraps OpenSSL; flagged for awareness, not removal."),
    "ecdsa": (SEVERITY_HIGH, "Pure-Python ECDSA — elliptic-curve signatures are quantum-vulnerable."),
    "rsa": (SEVERITY_HIGH, "Pure-Python RSA implementation — quantum-vulnerable."),
    "paramiko": (SEVERITY_MEDIUM, "SSH library relying on RSA/ECDSA host and user keys."),
    "pynacl": (SEVERITY_MEDIUM, "libsodium bindings — Ed25519 signatures and X25519 key exchange."),
    "python-jose": (SEVERITY_MEDIUM, "JOSE/JWT implementation supporting RS/ES/PS signatures."),
    "pyjwt": (SEVERITY_LOW, "JWT library; quantum-vulnerable only when RS/ES/PS algorithms are used."),
    "m2crypto": (SEVERITY_MEDIUM, "OpenSSL bindings exposing RSA/DSA/DH directly."),
}

_JS_DEPS: dict[str, tuple[str, str]] = {
    "node-forge": (SEVERITY_HIGH, "Implements RSA/ECC/TLS in JavaScript — quantum-vulnerable."),
    "jsrsasign": (SEVERITY_HIGH, "RSA/ECDSA crypto toolkit — quantum-vulnerable."),
    "elliptic": (SEVERITY_HIGH, "Elliptic-curve cryptography library — quantum-vulnerable."),
    "node-rsa": (SEVERITY_HIGH, "RSA implementation in JavaScript — quantum-vulnerable."),
    "ursa": (SEVERITY_HIGH, "OpenSSL RSA bindings — quantum-vulnerable."),
    "secp256k1": (SEVERITY_HIGH, "secp256k1 elliptic-curve bindings — quantum-vulnerable."),
    "@noble/secp256k1": (SEVERITY_HIGH, "secp256k1 elliptic-curve signatures — quantum-vulnerable."),
    "@noble/ed25519": (SEVERITY_HIGH, "Ed25519 signatures — Edwards curves are quantum-vulnerable."),
    "@noble/curves": (SEVERITY_MEDIUM, "Elliptic-curve toolkit; verify which curves are used."),
    "tweetnacl": (SEVERITY_MEDIUM, "NaCl port — Ed25519 signatures and X25519 key exchange."),
    "sshpk": (SEVERITY_MEDIUM, "SSH key parsing for RSA/ECDSA/Ed25519 keys."),
    "node-jose": (SEVERITY_MEDIUM, "JOSE implementation supporting RS/ES/PS signatures."),
    "jsonwebtoken": (SEVERITY_LOW, "JWT library; quantum-vulnerable only when RS/ES/PS algorithms are used."),
    "jose": (SEVERITY_LOW, "JOSE library; quantum-vulnerable only when RS/ES/PS algorithms are used."),
    "openpgp": (SEVERITY_LOW, "OpenPGP.js; flagged for awareness — verify RSA/ECC key usage."),
}

_RUST_DEPS: dict[str, tuple[str, str]] = {
    "rsa": (SEVERITY_HIGH, "Pure-Rust RSA implementation — quantum-vulnerable."),
    "ecdsa": (SEVERITY_HIGH, "ECDSA signatures — elliptic curves are quantum-vulnerable."),
    "p256": (SEVERITY_HIGH, "NIST P-256 ECDSA/ECDH — quantum-vulnerable."),
    "p384": (SEVERITY_HIGH, "NIST P-384 ECDSA/ECDH — quantum-vulnerable."),
    "p521": (SEVERITY_HIGH, "NIST P-521 ECDSA/ECDH — quantum-vulnerable."),
    "k256": (SEVERITY_HIGH, "secp256k1 ECDSA — quantum-vulnerable."),
    "secp256k1": (SEVERITY_HIGH, "secp256k1 bindings — quantum-vulnerable."),
    "ed25519-dalek": (SEVERITY_HIGH, "Ed25519 signatures — Edwards curves are quantum-vulnerable."),
    "x25519-dalek": (SEVERITY_HIGH, "X25519 key exchange — a prime harvest-now-decrypt-later target."),
    "curve25519-dalek": (SEVERITY_MEDIUM, "Curve25519 arithmetic underlying Ed25519/X25519."),
    "elliptic-curve": (SEVERITY_MEDIUM, "Generic elliptic-curve traits; verify which curves are used."),
    "sha1": (SEVERITY_HIGH, "SHA-1 is classically broken; no quantum margin."),
    "sha-1": (SEVERITY_HIGH, "SHA-1 is classically broken; no quantum margin."),
    "md-5": (SEVERITY_HIGH, "MD5 is comprehensively broken."),
    "des": (SEVERITY_HIGH, "DES / 3DES — small key sizes further eroded by Grover's algorithm."),
    "jsonwebtoken": (SEVERITY_MEDIUM, "JWT library supporting RS/ES/PS signatures."),
    "ring": (SEVERITY_LOW, "General-purpose crypto; verify whether RSA/ECDSA/ECDH paths are used."),
    "openssl": (SEVERITY_LOW, "OpenSSL bindings; flagged for awareness, not removal."),
}

# Go module paths. Matched by longest prefix, so `.../jwt/v5` hits `.../jwt`.
_GO_DEPS: dict[str, tuple[str, str]] = {
    "github.com/dgrijalva/jwt-go": (SEVERITY_HIGH, "Unmaintained JWT library (CVE-2020-26160); supports RS/ES signing."),
    "github.com/golang-jwt/jwt": (SEVERITY_MEDIUM, "JWT library supporting RS/ES/PS signing methods."),
    "github.com/go-jose/go-jose": (SEVERITY_MEDIUM, "JOSE implementation supporting RS/ES/PS signatures."),
    "github.com/square/go-jose": (SEVERITY_MEDIUM, "Unmaintained JOSE implementation supporting RS/ES/PS signatures."),
    "github.com/btcsuite/btcd/btcec": (SEVERITY_HIGH, "secp256k1 elliptic-curve library — quantum-vulnerable."),
    "github.com/decred/dcrd/dcrec/secp256k1": (SEVERITY_HIGH, "secp256k1 elliptic-curve library — quantum-vulnerable."),
    "golang.org/x/crypto": (SEVERITY_LOW, "Includes curve25519/ssh/openpgp; verify which packages are imported."),
}

# Maven/Gradle coordinates. Matched as `group:artifact`, then as bare `group`.
_JAVA_DEPS: dict[str, tuple[str, str]] = {
    "com.jcraft:jsch": (SEVERITY_HIGH, "SSH library relying on RSA/DSA/ECDSA host and user keys."),
    "com.github.mwiede:jsch": (SEVERITY_HIGH, "SSH library relying on RSA/DSA/ECDSA host and user keys."),
    "org.bitbucket.b_c:jose4j": (SEVERITY_MEDIUM, "JOSE implementation supporting RS/ES/PS signatures."),
    "com.nimbusds:nimbus-jose-jwt": (SEVERITY_MEDIUM, "JOSE/JWT implementation supporting RS/ES/PS signatures."),
    "com.auth0:java-jwt": (SEVERITY_MEDIUM, "JWT library supporting RS/ES signing."),
    "io.jsonwebtoken": (SEVERITY_MEDIUM, "jjwt — JWT library supporting RS/ES/PS signing."),
    "org.apache.sshd": (SEVERITY_MEDIUM, "Apache MINA SSHD — RSA/ECDSA host and user keys."),
    "org.bouncycastle": (SEVERITY_LOW, "Bouncy Castle also ships ML-KEM/ML-DSA; verify which algorithms are used."),
}

_RUBY_DEPS: dict[str, tuple[str, str]] = {
    "jwt": (SEVERITY_MEDIUM, "JWT library supporting RS/ES/PS signing."),
    "ed25519": (SEVERITY_HIGH, "Ed25519 signatures — Edwards curves are quantum-vulnerable."),
    "rbnacl": (SEVERITY_MEDIUM, "libsodium bindings — Ed25519 signatures and X25519 key exchange."),
    "net-ssh": (SEVERITY_MEDIUM, "SSH library relying on RSA/ECDSA host and user keys."),
    "openssl": (SEVERITY_LOW, "OpenSSL bindings; flagged for awareness, not removal."),
}

_PHP_DEPS: dict[str, tuple[str, str]] = {
    "phpseclib/phpseclib": (SEVERITY_HIGH, "Pure-PHP RSA/DSA/ECDSA and SSH implementation — quantum-vulnerable."),
    "firebase/php-jwt": (SEVERITY_MEDIUM, "JWT library supporting RS/ES signing."),
    "lcobucci/jwt": (SEVERITY_MEDIUM, "JWT library supporting RS/ES signing."),
    "web-token/jwt-framework": (SEVERITY_MEDIUM, "JOSE framework supporting RS/ES/PS signatures."),
    "paragonie/sodium_compat": (SEVERITY_MEDIUM, "libsodium polyfill — Ed25519 signatures and X25519 key exchange."),
}


@dataclass(frozen=True)
class _Ecosystem:
    """One package ecosystem: how to read its manifest and what to flag."""

    label: str
    registry: dict[str, tuple[str, str]]
    extract: Callable[[str], list[str]]
    #: Go module paths and Maven coordinates are hierarchical, so a declaration
    #: matches the longest registered prefix rather than only an exact name.
    lookup: Optional[Callable[[str, dict], Optional[str]]] = None


_PY_FILENAMES = {"setup.py", "pyproject.toml", "Pipfile"}
_REQUIREMENTS_RE = re.compile(r"requirements.*\.txt", re.IGNORECASE)
_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_GEMSPEC_RE = re.compile(r".*\.gemspec", re.IGNORECASE)


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _locate(text: str, needle: str) -> tuple[int, int]:
    """First line/column where *needle* appears as a delimited token (1-based).

    Maven splits a coordinate across ``<groupId>``/``<artifactId>`` tags, so the
    joined ``group:artifact`` never appears verbatim. Falling back to the last
    path/coordinate segment points the finding at the ``<artifactId>`` line
    instead of collapsing every Maven finding onto line 1.
    """
    candidates = [needle]
    for separator in (":", "/"):
        if separator in needle:
            candidates.append(needle.rsplit(separator, 1)[-1])
    for candidate in candidates:
        if not candidate:
            continue
        pattern = re.compile(
            r"(?<![A-Za-z0-9._-])" + re.escape(candidate) + r"(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        for idx, line in enumerate(text.splitlines(), start=1):
            m = pattern.search(line)
            if m:
                return idx, m.start() + 1
    return 1, 1


# --------------------------------------------------------------------------- #
# Hierarchical lookups
# --------------------------------------------------------------------------- #

_GO_MAJOR_SUFFIX_RE = re.compile(r"/v\d+$")


def _lookup_go(name: str, registry: dict) -> Optional[str]:
    """Longest-prefix match for a Go module path.

    ``github.com/golang-jwt/jwt/v5`` and ``golang.org/x/crypto/ssh`` both need to
    resolve to their registered root module.
    """
    norm = _GO_MAJOR_SUFFIX_RE.sub("", name.strip().lower())
    segments = norm.split("/")
    for end in range(len(segments), 0, -1):
        candidate = "/".join(segments[:end])
        if candidate in registry:
            return candidate
    return None


def _lookup_java(name: str, registry: dict) -> Optional[str]:
    """Match a Maven coordinate as ``group:artifact``, then as bare ``group``.

    Projects pull in Bouncy Castle or jjwt under several artifact ids; flagging
    the group once keeps the finding actionable without enumerating every jar.
    """
    norm = name.strip().lower()
    if norm in registry:
        return norm
    group = norm.split(":", 1)[0]
    return group if group in registry else None


# --------------------------------------------------------------------------- #
# Per-format extraction
# --------------------------------------------------------------------------- #


def _load_toml(text: str) -> Optional[dict]:
    try:
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
            import tomli as tomllib  # type: ignore
        return tomllib.loads(text)
    except Exception:
        return None


def _pep508_name(requirement: str) -> str:
    """Extract the bare package name from a PEP 508 requirement string."""
    return re.split(r"[<>=!~;\[\s(]", requirement.strip(), maxsplit=1)[0]


#: A comment runs to end of line, but only when it starts the line or follows
#: whitespace — so a URL fragment (`...#egg=name`) is not treated as a comment.
_COMMENT_RE = re.compile(r"(?:^|\s)#.*$")
_QUOTED_NAME_RE = re.compile(r"['\"]([A-Za-z0-9][A-Za-z0-9._-]*)")


def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line)


def _extract_requirements(text: str) -> list[str]:
    """``requirements*.txt``: one requirement per line, nothing else.

    Deliberately does NOT scan for quoted names. A package name quoted inside a
    trailing comment ("# replaces 'rsa' eventually") is prose about a
    dependency, not a declaration of one, and reporting it is a false positive
    on a file whose grammar is unambiguous.
    """
    names: list[str] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        stripped = line.strip()
        # pip options and includes (-r, -e, --index-url) declare nothing here.
        if not stripped or stripped.startswith("-"):
            continue
        match = _REQ_LINE_RE.match(line)
        if match:
            names.append(match.group(1))
    return names


def _extract_python_source(text: str) -> list[str]:
    """``setup.py`` / ``Pipfile``: names appear as quoted strings.

    ``install_requires=["rsa>=4.0"]`` and a Pipfile ``[packages]`` table both
    need the quoted scan, so it stays here — but comments are stripped first.
    """
    names: list[str] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        stripped = line.strip()
        if not stripped:
            continue
        match = _REQ_LINE_RE.match(line)
        if match:
            names.append(match.group(1))
        names.extend(_QUOTED_NAME_RE.findall(stripped))
    return names


def _extract_pyproject(text: str) -> list[str]:
    names: list[str] = []
    data = _load_toml(text)
    if isinstance(data, dict):
        project = data.get("project", {}) or {}
        for dep in project.get("dependencies", []) or []:
            names.append(_pep508_name(str(dep)))
        for group in (project.get("optional-dependencies", {}) or {}).values():
            for dep in group or []:
                names.append(_pep508_name(str(dep)))
        poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
        names.extend((poetry.get("dependencies", {}) or {}).keys())
        for grp in (poetry.get("group", {}) or {}).values():
            names.extend((grp.get("dependencies", {}) or {}).keys())
    else:
        names.extend(re.findall(r"['\"]([A-Za-z0-9][A-Za-z0-9._-]*)", text))
    return [n for n in names if n]


def _extract_npm(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return re.findall(r'"([A-Za-z0-9@._/-]+)"\s*:', text)
    names: list[str] = []
    for section in (
        "dependencies", "devDependencies", "peerDependencies", "optionalDependencies"
    ):
        block = data.get(section)
        if isinstance(block, dict):
            names.extend(block.keys())
    return names


def _extract_composer(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return re.findall(r'"([a-z0-9._-]+/[a-z0-9._-]+)"\s*:', text, re.IGNORECASE)
    names: list[str] = []
    for section in ("require", "require-dev"):
        block = data.get(section)
        if isinstance(block, dict):
            names.extend(block.keys())
    return names


def _extract_cargo(text: str) -> list[str]:
    """Crate names from every dependency table, including target-specific ones."""
    data = _load_toml(text)
    if not isinstance(data, dict):
        # A crate name always starts a line in the dependency tables.
        return re.findall(r"^\s*([A-Za-z0-9][A-Za-z0-9_-]*)\s*=", text, re.MULTILINE)

    names: list[str] = []

    def collect(table) -> None:
        if isinstance(table, dict):
            for key, value in table.items():
                # `foo = { package = "real-name" }` renames the crate; the
                # registry cares about the published name, not the local alias.
                if isinstance(value, dict) and value.get("package"):
                    names.append(str(value["package"]))
                else:
                    names.append(str(key))

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        collect(data.get(section))
    collect((data.get("workspace", {}) or {}).get("dependencies"))
    for target in (data.get("target", {}) or {}).values():
        if isinstance(target, dict):
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                collect(target.get(section))
    return names


_GO_REQUIRE_LINE_RE = re.compile(
    r"^\s*(?:require\s+)?([a-z0-9][\w.~-]*(?:\.[\w.~-]+)+/[^\s]+)\s+v", re.IGNORECASE
)


def _extract_gomod(text: str) -> list[str]:
    """Module paths from `require` directives (block or single-line form).

    `exclude` / `replace` directives are skipped: they constrain a dependency
    rather than declare one.
    """
    names: list[str] = []
    skip_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if re.match(r"^(exclude|replace|retract)\s*\($", stripped):
            skip_block = True
            continue
        if skip_block:
            if stripped == ")":
                skip_block = False
            continue
        if re.match(r"^(exclude|replace|retract)\s", stripped):
            continue
        m = _GO_REQUIRE_LINE_RE.match(stripped)
        if m:
            names.append(m.group(1))
    return names


_POM_DEPENDENCY_RE = re.compile(r"<dependency\b.*?</dependency>", re.DOTALL | re.IGNORECASE)
_POM_GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>", re.IGNORECASE)
_POM_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", re.IGNORECASE)


def _extract_pom(text: str) -> list[str]:
    """``group:artifact`` coordinates from each ``<dependency>`` block."""
    names: list[str] = []
    for block in _POM_DEPENDENCY_RE.findall(text):
        group = _POM_GROUP_RE.search(block)
        artifact = _POM_ARTIFACT_RE.search(block)
        if group and artifact:
            names.append(f"{group.group(1)}:{artifact.group(1)}")
    return names


_GRADLE_COORD_RE = re.compile(
    r"""['"]([A-Za-z0-9][\w.-]*:[A-Za-z0-9][\w.-]*)(?::[^'"]*)?['"]"""
)
_GRADLE_KV_RE = re.compile(
    r"""group\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*name\s*[:=]\s*['"]([^'"]+)['"]"""
)


def _extract_gradle(text: str) -> list[str]:
    """Coordinates from `implementation 'g:a:v'` and `group:.., name:..` forms."""
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        names.extend(_GRADLE_COORD_RE.findall(stripped))
        names.extend(f"{g}:{a}" for g, a in _GRADLE_KV_RE.findall(stripped))
    return names


_GEMFILE_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"]")
_GEMSPEC_RE_DEP = re.compile(
    r"add(?:_runtime|_development)?_dependency\s*\(?\s*['\"]([^'\"]+)['\"]"
)


def _extract_ruby(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = _GEMFILE_RE.match(line)
        if m:
            names.append(m.group(1))
        names.extend(_GEMSPEC_RE_DEP.findall(stripped))
    return names


# --------------------------------------------------------------------------- #
# Filename -> ecosystem routing
# --------------------------------------------------------------------------- #

_REQUIREMENTS = _Ecosystem("Python", _PYTHON_DEPS, _extract_requirements)
_PYTHON_SOURCE = _Ecosystem("Python", _PYTHON_DEPS, _extract_python_source)
_PYPROJECT = _Ecosystem("Python", _PYTHON_DEPS, _extract_pyproject)
_NPM = _Ecosystem("npm", _JS_DEPS, _extract_npm)
_CARGO = _Ecosystem("crates.io", _RUST_DEPS, _extract_cargo)
_GOMOD = _Ecosystem("Go modules", _GO_DEPS, _extract_gomod, lookup=_lookup_go)
_MAVEN = _Ecosystem("Maven", _JAVA_DEPS, _extract_pom, lookup=_lookup_java)
_GRADLE = _Ecosystem("Gradle", _JAVA_DEPS, _extract_gradle, lookup=_lookup_java)
_RUBYGEMS = _Ecosystem("RubyGems", _RUBY_DEPS, _extract_ruby)
_PACKAGIST = _Ecosystem("Packagist", _PHP_DEPS, _extract_composer)

_BY_FILENAME: dict[str, _Ecosystem] = {
    "setup.py": _PYTHON_SOURCE,
    "Pipfile": _PYTHON_SOURCE,
    "pyproject.toml": _PYPROJECT,
    "package.json": _NPM,
    "Cargo.toml": _CARGO,
    "go.mod": _GOMOD,
    "pom.xml": _MAVEN,
    "build.gradle": _GRADLE,
    "build.gradle.kts": _GRADLE,
    "settings.gradle": _GRADLE,
    "settings.gradle.kts": _GRADLE,
    "Gemfile": _RUBYGEMS,
    "composer.json": _PACKAGIST,
}


def _ecosystem_for(path: Path) -> Optional[_Ecosystem]:
    name = path.name
    eco = _BY_FILENAME.get(name)
    if eco is not None:
        return eco
    if _REQUIREMENTS_RE.fullmatch(name):
        return _REQUIREMENTS
    if _GEMSPEC_RE.fullmatch(name):
        return _RUBYGEMS
    return None


class DependencyScanner(BaseScanner):
    name = "dependency"

    def __init__(self, context: ScanContext | None = None):
        self.context = context or ScanContext()

    def supports(self, path: Path) -> bool:
        return _ecosystem_for(path) is not None

    def scan_file(self, path: Path) -> list[Finding]:
        if not self.context.rule_enabled("PQC014"):
            return []
        ecosystem = _ecosystem_for(path)
        if ecosystem is None:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for declared in ecosystem.extract(text):
            if not declared:
                continue
            if ecosystem.lookup is not None:
                key = ecosystem.lookup(declared, ecosystem.registry)
            else:
                norm = _normalize(declared)
                key = norm if norm in ecosystem.registry else None
            if key is None or key in seen:
                continue
            seen.add(key)
            severity, note = ecosystem.registry[key]
            line, col = _locate(text, declared)
            findings.append(
                build_finding(
                    rule_id="PQC014",
                    file_path=str(path),
                    line_number=line,
                    column_number=col,
                    algorithm=f"dependency: {key}",
                    code_snippet=f"{declared}  ({note})",
                    severity=severity,
                    confidence=CONFIDENCE_MEDIUM,
                    category=CATEGORY_DEPENDENCY,
                    description=f"Quantum-vulnerable {ecosystem.label} dependency "
                    f"'{key}'. {note} Verify usage and plan migration to "
                    "ML-KEM / ML-DSA.",
                )
            )
        return findings
