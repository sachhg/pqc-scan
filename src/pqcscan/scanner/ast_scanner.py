"""Tree-sitter AST scanning orchestrator.

Detects a file's language from its extension, parses it with the matching
tree-sitter grammar (grammars and parsers are cached), then delegates pattern
matching to the per-language rule module. Grammar packages are imported lazily so
a missing optional grammar degrades gracefully instead of breaking the whole run.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Callable, Optional

from pqcscan.languages import (
    go_rules,
    java_rules,
    javascript_rules,
    python_rules,
)

from .base import BaseScanner, Finding, ScanContext

# Order matters only for readability; lookup is by extension.
_LANGUAGE_MODULES = [python_rules, javascript_rules, java_rules, go_rules]


class _LanguageEntry:
    __slots__ = ("module", "grammar_name", "analyze")

    def __init__(self, module):
        self.module = module
        self.grammar_name: str = module.GRAMMAR
        self.analyze: Callable = module.analyze


# Build extension -> language-entry map from the registered modules.
_EXT_MAP: dict[str, _LanguageEntry] = {}
for _mod in _LANGUAGE_MODULES:
    _entry = _LanguageEntry(_mod)
    for _ext in _mod.EXTENSIONS:
        _EXT_MAP[_ext] = _entry


class AstScanner(BaseScanner):
    """Parses source files with tree-sitter and applies language rule modules."""

    name = "ast"

    def __init__(self, context: Optional[ScanContext] = None):
        self.context = context or ScanContext()
        # grammar import name -> tree-sitter Parser (lazily built, cached)
        self._parsers: dict[str, object] = {}
        # grammar import names that failed to load (warn once)
        self._unavailable: set[str] = set()
        # human-readable load failures, surfaced in ScanResult.errors so a
        # missing grammar is never a silent "0 findings" for that language
        self.load_errors: list[str] = []

    # ----- BaseScanner API ------------------------------------------------ #

    def supports(self, path: Path) -> bool:
        return path.suffix in _EXT_MAP

    def scan_file(self, path: Path) -> list[Finding]:
        entry = _EXT_MAP.get(path.suffix)
        if entry is None:
            return []
        parser = self._get_parser(entry.grammar_name)
        if parser is None:
            return []
        # Read errors propagate: the engine catches per-file exceptions and
        # records them in ScanResult.errors instead of silently skipping.
        source_bytes = path.read_bytes()
        tree = parser.parse(source_bytes)
        source_text = source_bytes.decode("utf-8", errors="replace")
        findings = entry.analyze(tree.root_node, source_text, str(path))
        return [f for f in findings if self.context.rule_enabled(f.rule_id)]

    # ----- parser management --------------------------------------------- #

    def _get_parser(self, grammar_name: str):
        if grammar_name in self._parsers:
            return self._parsers[grammar_name]
        if grammar_name in self._unavailable:
            return None
        parser = _build_parser(grammar_name)
        if parser is None:
            self._unavailable.add(grammar_name)
            pip_name = grammar_name.replace("_", "-")
            self.load_errors.append(
                f"tree-sitter grammar '{grammar_name}' failed to load — files for "
                f"this language were skipped (try: pip install {pip_name})"
            )
            return None
        self._parsers[grammar_name] = parser
        return parser


def _build_parser(grammar_name: str):
    """Construct a tree-sitter Parser for *grammar_name*, or None if unavailable."""
    try:
        from tree_sitter import Language, Parser

        grammar_module = importlib.import_module(grammar_name)
        language = Language(grammar_module.language())
        return Parser(language)
    except Exception:
        return None


def available_languages() -> list[str]:
    """Language ids whose grammar is importable in this environment."""
    available: list[str] = []
    for mod in _LANGUAGE_MODULES:
        if _build_parser(mod.GRAMMAR) is not None:
            available.append(mod.LANGUAGE)
    return available
