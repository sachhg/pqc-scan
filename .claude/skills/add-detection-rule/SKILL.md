---
name: add-detection-rule
description: Use when adding or extending a pqc-scan detection rule — a new quantum-vulnerable crypto pattern (new API call, library, JWT/TLS/cipher form), a brand-new PQCxxx rule id, or broadening an existing rule to another language. Walks through the registry, migration mapping, detection code, fixtures, and tests.
---

# Adding / extending a detection rule

A "rule" is one `PQCxxx` entry in the registry plus the per-language code that
emits it. Most work is one of two cases:

- **Extend an existing rule** (e.g. detect RSA in a new library) → skip to Step 3.
- **Add a new rule id** (a primitive not yet covered) → do all steps.

Before writing detection code, use the **`inspect-ast`** skill to learn the exact
node shapes for your target snippet.

## Step 1 — Register the rule (`src/pqcscan/scanner/base.py`)

Add a `RuleDef` to the `RULES` dict. Every field matters — SARIF, the `rules`
command, and CBOM all read it.

```python
"PQC015": RuleDef(
    rule_id="PQC015",
    name="Short Title Case Name",
    description="What was found and why it's quantum-vulnerable (one or two sentences).",
    default_severity=SEVERITY_CRITICAL,          # critical|high|medium|low (see CLAUDE.md severity model)
    category=CATEGORY_KEY_GENERATION,            # key-generation|signing|encryption|hashing|key-exchange|configuration|dependency
    primitive="pke",                             # CBOM primitive: pke|signature|hash|key-agree|block-cipher
    algorithm_family="rsa",                      # KEY into migration/suggestions.py
),
```

`default_severity` automatically maps to SARIF level (critical/high→error,
medium→warning, low→note) and `security-severity`. You don't touch SARIF/CBOM.

## Step 2 — Ensure a migration suggestion exists (`src/pqcscan/migration/suggestions.py`)

The rule's `algorithm_family` must be a key in `_SUGGESTIONS`. If it isn't, add a
`MigrationSuggestion` and map it:

```python
_MY_FAMILY = MigrationSuggestion(
    recommended_algorithm="ML-KEM-768 (CRYSTALS-Kyber)",
    recommended_library=_LIBOQS_INSTALL,     # reuse the shared liboqs caveat constant
    migration_description="Plain-English migration guidance.",
    code_example="# Before (vulnerable):\n...\n\n# After (quantum-safe):\nimport oqs\n...",
    nist_standard="FIPS 203",
    docs_url=_FIPS203,
)
# ... then add to _SUGGESTIONS:
"my-family": _MY_FAMILY,
```

An unmapped family silently falls back to `_FALLBACK` — don't rely on that for a
real rule.

## Step 3 — Detect it in the language module(s)

Edit `src/pqcscan/languages/<lang>_rules.py`. Mirror the existing structure; emit
findings only through `self._add(...)`, which dedupes by `(rule_id, line, col)`
and calls `build_finding`. Example (Python `_inspect_call`):

```python
if method == "new_vulnerable_call" and (obj_names & {"somelib"} or "somelib" in origin):
    self._add("PQC015", call, "RSA-2048")            # algorithm label is human-facing
    return
```

Conventions you must follow (see CLAUDE.md):
- node traversal only, never the query DSL;
- never compare nodes with `is` (use byte ranges);
- gate on real evidence (resolved import origin, a distinctive method name, a
  cipher anchor) so **safe code stays at zero findings**;
- `confidence="medium"` for indirect/string-literal matches.

For config/dependency rules, edit `scanner/config_scanner.py` /
`dependency_scanner.py` (these are line/regex based on purpose).

## Step 4 — Fixtures

- Add a triggering line to the matching `tests/fixtures/<lang>/vulnerable_*` file
  (or create one).
- Add a *safe* counterpart to the relevant `safe_*` fixture if your pattern is
  near something legitimate, to prove no false positive.

## Step 5 — Regression test

Add a test mirroring `tests/test_python_scanner.py` (unit-test
`<lang>_rules.analyze` directly, and/or end-to-end via `run_scan`). Always assert
the safe case is empty.

## Step 6 — Verify

```bash
.venv/bin/python -m pytest        # must be fully green
.venv/bin/pqc-scan scan tests/fixtures/<lang> -s low   # eyeball the new finding
```

Done when: target snippet → expected `PQCxxx`, safe fixtures → zero, tests green.
