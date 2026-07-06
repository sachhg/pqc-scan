"""Dependency-manifest scanner.

Flags declared dependencies whose primary purpose is quantum-vulnerable
cryptography (RSA / ECC / DH). A flagged dependency does not prove a vulnerable
code path is exercised, so findings stay at or below ``high`` and the message
says "verify usage and plan migration".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

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

# name (normalized lower-case) -> (severity, note)
_PYTHON_DEPS: dict[str, tuple[str, str]] = {
    "pycrypto": (SEVERITY_HIGH, "Unmaintained library providing RSA/ECC/DSA (and carrying known CVEs)."),
    "pycryptodome": (SEVERITY_LOW, "General-purpose crypto library; verify whether RSA/ECC code paths are used."),
    "pycryptodomex": (SEVERITY_LOW, "General-purpose crypto library; verify whether RSA/ECC code paths are used."),
    "pyopenssl": (SEVERITY_LOW, "Wraps OpenSSL; flagged for awareness, not removal."),
    "ecdsa": (SEVERITY_HIGH, "Pure-Python ECDSA — elliptic-curve signatures are quantum-vulnerable."),
    "rsa": (SEVERITY_HIGH, "Pure-Python RSA implementation — quantum-vulnerable."),
    "paramiko": (SEVERITY_MEDIUM, "SSH library relying on RSA/ECDSA host and user keys."),
}

_JS_DEPS: dict[str, tuple[str, str]] = {
    "node-forge": (SEVERITY_HIGH, "Implements RSA/ECC/TLS in JavaScript — quantum-vulnerable."),
    "jsrsasign": (SEVERITY_HIGH, "RSA/ECDSA crypto toolkit — quantum-vulnerable."),
    "elliptic": (SEVERITY_HIGH, "Elliptic-curve cryptography library — quantum-vulnerable."),
    "node-rsa": (SEVERITY_HIGH, "RSA implementation in JavaScript — quantum-vulnerable."),
    "openpgp": (SEVERITY_LOW, "OpenPGP.js; flagged for awareness — verify RSA/ECC key usage."),
}

_PY_REQ_FILENAMES = {"requirements.txt", "requirements-dev.txt", "setup.py", "pyproject.toml", "Pipfile"}
_JS_FILENAMES = {"package.json"}

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _locate(text: str, needle: str) -> tuple[int, int]:
    """First line/column where *needle* appears as a delimited token (1-based)."""
    pattern = re.compile(r"(?<![A-Za-z0-9._-])" + re.escape(needle) + r"(?![A-Za-z0-9])", re.IGNORECASE)
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            return idx, m.start() + 1
    return 1, 1


class DependencyScanner(BaseScanner):
    name = "dependency"

    def __init__(self, context: ScanContext | None = None):
        self.context = context or ScanContext()

    def supports(self, path: Path) -> bool:
        name = path.name
        if name in _PY_REQ_FILENAMES or name in _JS_FILENAMES:
            return True
        # requirements-*.txt variants
        return bool(re.fullmatch(r"requirements.*\.txt", name))

    def scan_file(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        name = path.name
        if name in _JS_FILENAMES:
            declared = self._js_dependencies(text)
            registry = _JS_DEPS
        elif name == "pyproject.toml":
            declared = self._pyproject_dependencies(text)
            registry = _PYTHON_DEPS
        else:  # requirements*.txt, setup.py, Pipfile
            declared = self._py_text_dependencies(text)
            registry = _PYTHON_DEPS

        findings: list[Finding] = []
        seen: set[str] = set()
        if not self.context.rule_enabled("PQC014"):
            return findings
        for dep in declared:
            norm = _normalize(dep)
            if norm in registry and norm not in seen:
                seen.add(norm)
                severity, note = registry[norm]
                line, col = _locate(text, dep)
                findings.append(
                    build_finding(
                        rule_id="PQC014",
                        file_path=str(path),
                        line_number=line,
                        column_number=col,
                        algorithm=f"dependency: {norm}",
                        code_snippet=f"{norm}  ({note})",
                        severity=severity,
                        confidence=CONFIDENCE_MEDIUM,
                        category=CATEGORY_DEPENDENCY,
                        description=f"Quantum-vulnerable dependency '{norm}'. {note} "
                        "Verify usage and plan migration to ML-KEM / ML-DSA.",
                    )
                )
        return findings

    # ----- per-format dependency extraction ------------------------------ #

    @staticmethod
    def _py_text_dependencies(text: str) -> list[str]:
        names: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # requirements.txt style
            m = _REQ_LINE_RE.match(line)
            if m:
                names.append(m.group(1))
            # quoted names inside setup.py install_requires / Pipfile
            for q in re.findall(r"['\"]([A-Za-z0-9][A-Za-z0-9._-]*)", stripped):
                names.append(q)
        return names

    @staticmethod
    def _pyproject_dependencies(text: str) -> list[str]:
        names: list[str] = []
        data = None
        try:
            try:
                import tomllib  # Python 3.11+
            except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
                import tomli as tomllib  # type: ignore
            data = tomllib.loads(text)
        except Exception:
            data = None

        if isinstance(data, dict):
            project = data.get("project", {})
            for dep in project.get("dependencies", []) or []:
                names.append(_pep508_name(dep))
            for group in (project.get("optional-dependencies", {}) or {}).values():
                for dep in group or []:
                    names.append(_pep508_name(dep))
            poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
            names.extend((poetry.get("dependencies", {}) or {}).keys())
            for grp in (poetry.get("group", {}) or {}).values():
                names.extend((grp.get("dependencies", {}) or {}).keys())
        else:
            # Fallback: best-effort quoted-name scan
            names.extend(re.findall(r"['\"]([A-Za-z0-9][A-Za-z0-9._-]*)", text))
        return [n for n in names if n]

    @staticmethod
    def _js_dependencies(text: str) -> list[str]:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return re.findall(r'"([A-Za-z0-9@._/-]+)"\s*:', text)
        names: list[str] = []
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(section)
            if isinstance(block, dict):
                names.extend(block.keys())
        return names


def _pep508_name(requirement: str) -> str:
    """Extract the bare package name from a PEP 508 requirement string."""
    return re.split(r"[<>=!~;\[\s(]", requirement.strip(), maxsplit=1)[0]
