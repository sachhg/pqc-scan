"""Minimal git integration for ``--changed-only`` (CI use).

Implemented with ``subprocess`` rather than a third-party binding so it works in
any environment that has the ``git`` executable, with no extra dependency.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


def _run_git(args: list[str], cwd: str | Path) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def is_git_repo(cwd: str | Path = ".") -> bool:
    out = _run_git(["rev-parse", "--is-inside-work-tree"], cwd)
    return bool(out and out.strip() == "true")


def repo_root(cwd: str | Path = ".") -> Optional[Path]:
    out = _run_git(["rev-parse", "--show-toplevel"], cwd)
    return Path(out.strip()) if out else None


def changed_files(cwd: str | Path = ".", base_ref: Optional[str] = None) -> list[Path]:
    """Return absolute paths of files changed in the working tree / current diff.

    Combines unstaged, staged and untracked changes. When *base_ref* is provided
    (e.g. ``origin/main`` in CI), diffs against the merge-base with that ref so a
    pull request's full change set is covered.
    """
    root = repo_root(cwd)
    if root is None:
        return []

    rel_paths: set[str] = set()

    if base_ref:
        merge_base = _run_git(["merge-base", "HEAD", base_ref], cwd)
        diff_target = merge_base.strip() if merge_base else base_ref
        out = _run_git(["diff", "--name-only", "--diff-filter=ACMR", diff_target], cwd)
        if out:
            rel_paths.update(filter(None, out.splitlines()))

    for diff_args in (
        ["diff", "--name-only", "--diff-filter=ACMR"],          # unstaged
        ["diff", "--name-only", "--diff-filter=ACMR", "--cached"],  # staged
    ):
        out = _run_git(diff_args, cwd)
        if out:
            rel_paths.update(filter(None, out.splitlines()))

    # Untracked-but-not-ignored files
    out = _run_git(["ls-files", "--others", "--exclude-standard"], cwd)
    if out:
        rel_paths.update(filter(None, out.splitlines()))

    return [(root / rel) for rel in sorted(rel_paths) if (root / rel).is_file()]
