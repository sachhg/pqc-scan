"""Tests for file discovery and exclude-glob semantics."""

from __future__ import annotations

from pqcscan.config import PqcConfig
from pqcscan.utils.file_walker import ExcludeMatcher


def test_default_excludes_skip_nested_tests():
    """Regression (Bug 1): the default tests exclude is `**/tests/**`, which must
    match test directories nested anywhere — not just at the project root."""
    cfg = PqcConfig.default()
    assert "**/tests/**" in cfg.exclude

    matcher = ExcludeMatcher(["**/tests/**"])
    assert matcher.matches("tests/test_x.py")             # root-level
    assert matcher.matches("pkg/tests/test_x.py")         # nested one level
    assert matcher.matches("a/b/c/tests/test_x.py")       # nested deep
    assert not matcher.matches("pkg/src/main.py")         # unrelated code
    assert not matcher.matches("pkg/contests/x.py")       # not a `tests` segment


def test_root_only_glob_would_miss_nested(tmp_path):
    """Documents why the fix was needed: the old `tests/**` only matched root."""
    old = ExcludeMatcher(["tests/**"])
    assert old.matches("tests/test_x.py")                 # root: matched
    assert not old.matches("pkg/tests/test_x.py")         # nested: missed (the bug)


def test_discover_files_end_to_end_excludes(tmp_path):
    """Functional check on a real tree: nested tests/vendor/site-packages are
    skipped; regular source files at any depth are found."""
    from pqcscan.utils.file_walker import discover_files

    layout = {
        "src/app.py": "x = 1\n",
        "src/deep/module.py": "y = 2\n",
        "src/deep/tests/test_module.py": "t = 3\n",       # nested tests -> excluded
        "tests/test_app.py": "t = 4\n",                    # root tests -> excluded
        "vendor/lib/blob.py": "v = 5\n",                   # vendor glob -> excluded
        "site-packages/pkg/mod.py": "s = 6\n",             # hard prune dir
    }
    for rel, content in layout.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    cfg = PqcConfig.default()
    found = {
        p.relative_to(tmp_path).as_posix()
        for p in discover_files([tmp_path], exclude=cfg.exclude)
    }
    assert found == {"src/app.py", "src/deep/module.py"}


def test_symlinked_duplicate_scanned_once(tmp_path):
    """A file reachable twice (directly and via symlink) is yielded once."""
    import os

    from pqcscan.utils.file_walker import discover_files

    real = tmp_path / "real.py"
    real.write_text("x = 1\n", encoding="utf-8")
    os.symlink(real, tmp_path / "alias.py")
    found = list(discover_files([tmp_path]))
    assert len(found) == 1
