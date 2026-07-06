---
name: add-language
description: Use when adding support for a new programming language to pqc-scan (e.g. Rust, C#, Ruby, PHP) — installing its tree-sitter grammar, creating a `<lang>_rules.py` module that follows the analyze() contract, and registering it in the three wiring points. Not for adding a rule to an existing language (use add-detection-rule for that).
---

# Adding a new language scanner

Every language module is a thin tree-sitter analyzer following one contract. The
hardest part is the grammar's AST shape — use the **`inspect-ast`** skill heavily.

## Step 1 — Add and install the grammar

In `pyproject.toml`, add the grammar to `dependencies`:

```toml
"tree-sitter-rust>=0.23.0",
```

Then install and confirm it imports and constructs a parser:

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -c "import tree_sitter_rust as g; from tree_sitter import Language, Parser; Parser(Language(g.language())); print('grammar OK')"
```

## Step 2 — Learn the node shapes

Use the `inspect-ast` skill to dump the AST for representative vulnerable calls
in the new language. Note: call node type, how the callee/receiver decompose,
how arguments and string literals appear. The shared `_helpers.dotted_parts`
already understands `attribute / member_expression / selector_expression /
field_access / scoped_identifier / method_invocation` — check whether the new
grammar's nodes are covered; if not, extend `_helpers.py` (and
`string_value` for the grammar's string node type) rather than reinventing.

## Step 3 — Create `src/pqcscan/languages/<lang>_rules.py`

Mirror `python_rules.py` / `go_rules.py`. Required public surface:

```python
from pqcscan.scanner.base import Finding, build_finding
from . import _helpers as h

LANGUAGE = "rust"
EXTENSIONS = {".rs"}
GRAMMAR = "tree_sitter_rust"

class _RustAnalyzer:
    def __init__(self, source_text, file_path):
        self.findings = []; self._seen = set(); self.file_path = file_path
    def _add(self, rule_id, node, algorithm, **kw):
        line, col = h.line_col(node)
        if (rule_id, line, col) in self._seen: return
        self._seen.add((rule_id, line, col))
        self.findings.append(build_finding(
            rule_id=rule_id, file_path=self.file_path,
            line_number=line, column_number=col,
            algorithm=algorithm, code_snippet=h.snippet(node), **kw))
    def run(self, root):
        for node in h.walk(root):
            if node.type == "call_expression": self._inspect_call(node)
        return self.findings
    # ... detection per the spec's algorithm list, reusing PQC001..PQC014

def analyze(root, source_text, file_path) -> list[Finding]:
    return _RustAnalyzer(source_text, str(file_path)).run(root)
```

Reuse existing `PQCxxx` ids — they're language-agnostic. Only invent a new id if
the primitive genuinely isn't covered (then use the `add-detection-rule` skill).

## Step 4 — Register in the THREE wiring points

1. `src/pqcscan/scanner/ast_scanner.py` — add to the import and `_LANGUAGE_MODULES` list.
2. `src/pqcscan/scanner/engine.py` — add to the import and `_LANG_MODULES` dict.
3. `src/pqcscan/config.py` — add the id to `ALL_LANGUAGES`.

Confirm the package still imports and the language is live:

```bash
.venv/bin/python -c "from pqcscan.scanner.ast_scanner import available_languages; print(available_languages())"
```

## Step 5 — Fixtures + tests

- Create `tests/fixtures/<lang>/vulnerable.<ext>` exercising your patterns, plus a
  safe section/file that must yield zero findings.
- Add a test that scans the fixtures and asserts the expected rule ids (and zero
  on the safe case).

## Step 6 — Verify

```bash
.venv/bin/python -m pytest
.venv/bin/pqc-scan scan tests/fixtures/<lang> -s low
```

Also update the README's "what it detects" / language list if you add one.

Note: extensions can be added to an existing module's `EXTENSIONS` for dialects
(as `.ts`/`.tsx` ride on the JS grammar best-effort) — you don't always need a
new grammar.
