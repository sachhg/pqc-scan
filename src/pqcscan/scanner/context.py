"""Heuristics that classify a finding as library-implementation vs. application code.

A finding inside ``cryptography/hazmat/primitives/asymmetric/rsa.py`` is
technically correct but not actionable for someone *consuming* that library —
the actionable fix is at their own call sites. These heuristics attach a
``context_hint`` to such findings so the report says so explicitly instead of
reading like a demand to patch someone else's crypto internals.

Only positive, high-precision signals are used (a path segment or an enclosing
wrapper-function name); when nothing fires the hint stays ``None`` and the
finding renders exactly as before.
"""

from __future__ import annotations

import re
from typing import Optional

# Path segments that mark a file as (very likely) crypto-library plumbing
# rather than application code. Matched as whole path segments, never as
# substrings, so e.g. `implementations.py` or `src/backends_ui/` do not fire.
LIBRARY_PATH_SEGMENTS = {
    "hazmat",
    "primitives",
    "internal",
    "_internal",
    "internals",
    "impl",
    "backend",
    "backends",
    "vendor",
    "vendored",
    "third_party",
    "thirdparty",
    "site-packages",
}

LIBRARY_PATH_HINT = (
    "This file looks like library implementation code (path segment '{segment}'). "
    "If you consume this library rather than maintain it, you do not need to change "
    "this call — migrate your own usage of the library instead."
)

# Enclosing function names that look like a deliberate key-construction wrapper
# (generate_rsa_key, create_signing_keypair, make_host_key, ...). A vulnerable
# call inside one of these is usually the single choke point the whole codebase
# funnels through, which changes how you plan the migration.
_WRAPPER_NAME_RE = re.compile(
    r"^(?:generate|create|make|build|new)_\w*key(?:s|_?pair)?$", re.IGNORECASE
)

WRAPPER_FUNCTION_HINT = (
    "This call sits inside '{function}()', which looks like a key-construction "
    "wrapper. Migrating the wrapper migrates every caller at once — start here, "
    "then verify the wrapper's callers do not persist or exchange the old key type."
)


def path_context_hint(file_path: str) -> Optional[str]:
    """Hint when *file_path* contains a library-implementation path segment."""
    normalized = file_path.replace("\\", "/")
    for segment in normalized.split("/"):
        if segment.lower() in LIBRARY_PATH_SEGMENTS:
            return LIBRARY_PATH_HINT.format(segment=segment)
    return None


def wrapper_context_hint(function_name: Optional[str]) -> Optional[str]:
    """Hint when the enclosing function name looks like a keygen wrapper."""
    if function_name and _WRAPPER_NAME_RE.match(function_name):
        return WRAPPER_FUNCTION_HINT.format(function=function_name)
    return None


def apply_context_hints(findings, file_path_of=lambda f: f.file_path) -> None:
    """Fill ``context_hint`` in-place for findings that have none yet.

    The path signal is applied centrally (it works for every language and the
    config/dependency scanners); the wrapper-function signal is emitted by the
    language analyzers themselves, which already sit on the parse tree. A hint
    set by an analyzer wins — it is more specific than the path heuristic.
    """
    for finding in findings:
        if finding.context_hint is None:
            finding.context_hint = path_context_hint(file_path_of(finding))
