"""File discovery: walk paths, honor excludes and .gitignore, skip junk.

Glob excludes use gitignore-style semantics: ``*`` matches within a path
segment, ``**`` matches across segments, and a pattern without a ``/`` also
matches a bare basename anywhere in the tree.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

# Directories we never descend into, regardless of configuration.
DEFAULT_PRUNE_DIRS = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", "bower_components", "site-packages",
    "dist", "build", ".tox", ".eggs", ".idea", ".vscode",
}

# Skip files larger than this (likely data/blobs, not source).
MAX_FILE_BYTES = 2_000_000


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a gitignore-style glob into a compiled regex."""
    pattern = pattern.strip().rstrip("/")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 2] == "**":
                j = i + 2
                if pattern[j : j + 1] == "/":
                    out.append("(?:.*/)?")  # zero or more leading directories
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "/":
            out.append("/")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("(?s:" + "".join(out) + r")\Z")


class ExcludeMatcher:
    """Matches relative POSIX paths against a set of glob patterns."""

    def __init__(self, patterns: Iterable[str]):
        self._specs: list[tuple[re.Pattern, bool]] = []
        for pat in patterns:
            pat = pat.strip()
            if not pat or pat.startswith("#"):
                continue
            has_slash = "/" in pat.rstrip("/")
            self._specs.append((_glob_to_regex(pat), has_slash))

    def matches(self, rel_posix: str) -> bool:
        base = rel_posix.rsplit("/", 1)[-1]
        for regex, has_slash in self._specs:
            if regex.match(rel_posix):
                return True
            if not has_slash and regex.match(base):
                return True
        return False

    def __bool__(self) -> bool:
        return bool(self._specs)


def _read_gitignore(root: Path) -> list[str]:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    patterns: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.append(line)
    return patterns


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(1024)
    except OSError:
        return True
    return b"\x00" in chunk


def discover_files(
    paths: Iterable[str | Path],
    *,
    exclude: Optional[Iterable[str]] = None,
    accept: Optional[Callable[[Path], bool]] = None,
    respect_gitignore: bool = True,
) -> Iterator[Path]:
    """Yield files under *paths*.

    * Explicitly passed file paths are always yielded (subject to ``accept``).
    * Directories are walked; ``DEFAULT_PRUNE_DIRS`` and excluded directories are
      not descended into.
    * ``exclude`` are gitignore-style globs evaluated relative to each root.
    * ``accept`` lets the caller restrict to files a scanner can handle.
    """
    user_patterns = list(exclude or [])
    seen: set[Path] = set()

    for raw in paths:
        root = Path(raw)
        if root.is_file():
            resolved = root.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if accept is None or accept(root):
                yield root
            continue
        if not root.is_dir():
            continue

        patterns = list(user_patterns)
        if respect_gitignore:
            patterns += _read_gitignore(root)
        matcher = ExcludeMatcher(patterns)

        for dirpath, dirnames, filenames in os.walk(root):
            dpath = Path(dirpath)
            # Prune unwanted directories in place so os.walk skips them.
            kept = []
            for d in dirnames:
                if d in DEFAULT_PRUNE_DIRS:
                    continue
                rel = (dpath / d).relative_to(root).as_posix()
                # Match both the bare directory path and its slash-suffixed
                # form so `**/vendor/**`-style globs prune the whole subtree
                # here instead of testing every file inside it.
                if matcher and (matcher.matches(rel) or matcher.matches(rel + "/")):
                    continue
                kept.append(d)
            dirnames[:] = kept

            for fname in filenames:
                fpath = dpath / fname
                rel = fpath.relative_to(root).as_posix()
                if matcher and matcher.matches(rel):
                    continue
                resolved = fpath.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                if accept is not None and not accept(fpath):
                    continue
                try:
                    if fpath.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                if _looks_binary(fpath):
                    continue
                yield fpath
