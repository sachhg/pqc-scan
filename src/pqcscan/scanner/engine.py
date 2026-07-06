"""Scan orchestration: discover files, route each to the right scanner, collect.

Routing priority per file is dependency-manifest -> AST source -> config file, so
``package.json`` is read as a manifest rather than scanned for cipher strings.

Scanning is deliberately single-threaded. Measured on a 1,800-file tree the
serial pipeline does ~1,700 files/s end-to-end, and ~75% of per-file cost is the
pure-Python ``analyze()`` node traversal, which holds the GIL — a
ThreadPoolExecutor with per-thread parsers measured 0.94-0.96x (slower than
serial). Revisit with a process pool only if profiling on 100k-file monorepos
shows the ~1 minute serial ceiling actually hurts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from pqcscan.config import ALL_LANGUAGES, PqcConfig
from pqcscan.languages import go_rules, java_rules, javascript_rules, python_rules
from pqcscan.utils.file_walker import discover_files

from .ast_scanner import AstScanner
from .base import (
    Finding,
    ScanContext,
    finding_sort_key,
    meets_threshold,
    severity_rank,
)
from .config_scanner import ConfigScanner
from .context import apply_context_hints
from .dependency_scanner import DependencyScanner

_LANG_MODULES = {
    m.LANGUAGE: m for m in (python_rules, javascript_rules, java_rules, go_rules)
}


@dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    duration_seconds: float
    config: Optional[PqcConfig] = None
    errors: list[str] = field(default_factory=list)
    #: Resolved root of the scan (first directory scanned, or the file's
    #: parent). Outputs relativize file paths against this.
    root_path: str = "."
    #: The paths that were requested, as given by the caller.
    scanned_paths: list[str] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    @property
    def total(self) -> int:
        return len(self.findings)


def extensions_for_languages(languages: Iterable[str]) -> set[str]:
    exts: set[str] = set()
    for lang in languages:
        mod = _LANG_MODULES.get(lang)
        if mod is not None:
            exts |= set(mod.EXTENSIONS)
    return exts


def run_scan(
    paths: Iterable[str | Path],
    config: PqcConfig | None = None,
    *,
    changed_only: bool = False,
    repo_root: str | Path | None = None,
    extra_excludes: Iterable[str] | None = None,
) -> ScanResult:
    config = config or PqcConfig.default()
    context = ScanContext(
        severity_threshold=config.severity_threshold,
        disabled_rules=frozenset(config.disabled_rules),
    )

    path_list = [Path(p) for p in paths]
    root = next((p for p in path_list if p.is_dir()), None)
    if root is None and path_list:
        root = path_list[0].parent if path_list[0].is_file() else path_list[0]
    root_path = str(root.resolve()) if root is not None else "."

    languages = config.languages or list(ALL_LANGUAGES)
    allowed_exts = extensions_for_languages(languages)

    ast_scanner = AstScanner(context)
    config_scanner = ConfigScanner(context) if config.scan_configs else None
    dependency_scanner = DependencyScanner(context) if config.scan_dependencies else None

    def route(path: Path):
        if dependency_scanner is not None and dependency_scanner.supports(path):
            return dependency_scanner
        if path.suffix in allowed_exts and ast_scanner.supports(path):
            return ast_scanner
        if config_scanner is not None and config_scanner.supports(path):
            return config_scanner
        return None

    excludes = list(config.exclude)
    if extra_excludes:
        excludes.extend(extra_excludes)

    changed_set = None
    if changed_only:
        import os

        from pqcscan.utils.git import changed_files

        # In PR CI the working tree has no diff, so fall back to diffing against
        # the PR's base ref when one is advertised in the environment.
        base_ref = os.environ.get("PQC_SCAN_BASE_REF") or os.environ.get("GITHUB_BASE_REF")
        if base_ref and "/" not in base_ref:
            base_ref = f"origin/{base_ref}"
        changed_set = {
            Path(p).resolve()
            for p in changed_files(repo_root or ".", base_ref=base_ref or None)
        }

    findings: list[Finding] = []
    errors: list[str] = []
    files_scanned = 0

    for path in discover_files(path_list, exclude=excludes, accept=lambda p: route(p) is not None):
        if changed_set is not None and path.resolve() not in changed_set:
            continue
        scanner = route(path)
        if scanner is None:
            continue
        files_scanned += 1
        try:
            findings.extend(scanner.scan_file(path))
        except Exception as exc:  # never let one bad file abort the run
            errors.append(f"{path}: {exc}")

    # A grammar that failed to import means a whole language was skipped —
    # surface that instead of silently reporting zero findings for it.
    errors.extend(ast_scanner.load_errors)

    # Apply severity threshold and sort most-severe first.
    threshold = config.severity_threshold
    filtered = [f for f in findings if meets_threshold(f.severity, threshold)]
    filtered.sort(key=finding_sort_key)

    # Attach library-implementation context hints (path heuristic) to findings
    # the language analyzers did not already annotate.
    apply_context_hints(filtered)

    return ScanResult(
        findings=filtered,
        files_scanned=files_scanned,
        duration_seconds=0.0,  # set by caller via timed_scan
        config=config,
        errors=errors,
        root_path=root_path,
        scanned_paths=[str(p) for p in path_list],
    )


def timed_scan(*args, **kwargs) -> ScanResult:
    """``run_scan`` wrapper that records wall-clock duration."""
    start = time.perf_counter()
    result = run_scan(*args, **kwargs)
    result.duration_seconds = time.perf_counter() - start
    return result
