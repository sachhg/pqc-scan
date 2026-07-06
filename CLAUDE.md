# pqc-scan — developer guide for Claude Code

`pqc-scan` is a developer-native static analyzer that flags **quantum-vulnerable
cryptography** (RSA, ECC/ECDSA/ECDH, DH, DSA, Ed25519/X25519, SHA-1, MD5,
DES/3DES, weak JWT/TLS) and points each finding at its NIST post-quantum
replacement (ML-KEM / ML-DSA / SLH-DSA). It ships as a CLI and a GitHub Action.
Think "Snyk for Post-Quantum Cryptography." Positioning is developer-first:
findings show up inline in PRs like a lint warning, no security team required.

## Dev environment

- Python **>=3.10**; a venv lives at `.venv` with the package installed editable.
- **Run the CLI:** `.venv/bin/pqc-scan scan <path>` (or `report`, `init`, `rules`).
- **Run tests:** `.venv/bin/python -m pytest` (40 tests, must stay green).
- **Inspect a parse tree** (the core rule-writing tool): use the `inspect-ast` skill.
- Reinstall after dependency edits: `.venv/bin/python -m pip install -e ".[dev]"`.

## Architecture: how a scan flows

```
cli.scan ─► PqcConfig.load() ─► engine.run_scan()
                                   ├─ file_walker.discover_files()      (excludes, .gitignore, binary skip)
                                   ├─ route each file:  dependency > ast > config   (first match wins)
                                   │     • AstScanner    → languages/<lang>_rules.analyze()  (tree-sitter)
                                   │     • ConfigScanner → line/regex patterns (yml/json/toml/conf/.env)
                                   │     • DependencyScanner → requirements/pyproject/package.json
                                   ├─ severity-threshold filter + sort (most severe first)
                                   └─ ScanResult ─► output/{console,sarif,cbom,json}
```

Per-file AST detection: detect language by extension → parse with the matching
tree-sitter grammar (parsers cached in `AstScanner`) → the language module walks
the AST and emits `Finding`s.

## Where things live

| Path | Responsibility |
|---|---|
| `scanner/base.py` | `Finding`, `MigrationSuggestion`, the `RULES` registry (PQC001–PQC014), `build_finding`, `ScanContext`, `BaseScanner`, severity helpers |
| `migration/suggestions.py` | `get_suggestion(algorithm_family)` → `MigrationSuggestion` per algorithm |
| `languages/_helpers.py` | shared tree-sitter **node-traversal** helpers (see below) |
| `languages/<lang>_rules.py` | per-language detection: `python`, `javascript`, `java`, `go` |
| `scanner/ast_scanner.py` | extension→module routing, grammar/parser loading & caching |
| `scanner/config_scanner.py` | config-file patterns (TLS/cipher/protocol/cert) |
| `scanner/dependency_scanner.py` | manifest parsing, flagged-library registry |
| `scanner/engine.py` | orchestration; `run_scan` / `timed_scan` → `ScanResult` |
| `output/{console,sarif,cbom,json_output}.py` | renderers |
| `config.py` | `.pqcscan.yml` loading → `PqcConfig` |
| `utils/{file_walker,git}.py` | file discovery; `--changed-only` git integration |
| `tests/fixtures/` | `vulnerable_*` and **`safe_*`** inputs the tests scan |

## Core contracts — read before editing detection or output code

**1. Never construct `Finding` by hand. Always use `build_finding(...)`** (in
`scanner/base.py`). It fills severity/category/description from the rule and looks
up the migration suggestion via the rule's `algorithm_family`. Override
`severity=` / `category=` / `confidence=` only for genuine local context (e.g. a
SHA-1 *certificate* signature is `critical`, not the default `medium`).

**2. The `RULES` registry (PQC001–PQC014)** is the single source of truth for
rule metadata: `rule_id, name, description, default_severity, category,
primitive, algorithm_family`. SARIF rule descriptors, the `rules` command, and
CBOM all derive from it. Add a rule here, not ad hoc.

**3. Every language module exposes exactly this contract** (consumed by
`ast_scanner`):
```python
LANGUAGE: str            # "python"
EXTENSIONS: set[str]     # {".py", ".pyi"}
GRAMMAR: str             # "tree_sitter_python" (import name of the grammar pkg)
def analyze(root, source_text, file_path) -> list[Finding]: ...
```
Mirror the structure of `python_rules.py`: a `_<Lang>Analyzer` class with an
`_add(rule_id, node, algorithm, **kwargs)` helper that **dedupes by
`(rule_id, line, column)`** via a `self._seen` set and routes through
`build_finding`.

**4. `_helpers` is the only sanctioned way to read nodes:** `walk`, `text`,
`line_col`, `snippet`, `field`, `call_function`, `call_arguments`,
`dotted_parts`, `string_value`, `keyword_args`, `positional_args`.

## Non-negotiable conventions (most bugs come from violating these)

- **Use tree-sitter NODE TRAVERSAL, never the query DSL.** The query syntax
  drifts across tree-sitter releases; the node API is stable. All detection is
  `node.type` / `node.children` / `child_by_field_name` based.
- **Never compare tree-sitter nodes with `is`.** Node wrappers are recreated on
  each access, so identity is meaningless. Compare `(start_byte, end_byte)` (or
  `.id`). This already bit `_collect_imports` once.
- **Positions are 1-based.** `h.line_col(node)` returns `(row+1, col+1)` to match
  editor/SARIF/CBOM conventions.
- **Precision beats recall on safe code.** `tests/fixtures/python/safe_code.py`
  and `tests/fixtures/configs/safe_config.yml` **must always yield zero
  findings.** Never flag SHA-256/384/512, SHA-3, AES, HMAC, HS256, ChaCha20,
  ML-KEM/ML-DSA, or a bare uppercase constant that merely contains a weak token.
  When in doubt, gate on real evidence (resolved import origin, a cipher anchor).
- **Confidence:** `high` for direct API calls; `medium` for indirect
  string-literal/heuristic matches.
- `config_scanner` and `dependency_scanner` are **line/regex based on purpose** —
  config files have no universal AST. The "no regex" rule applies to *source
  code* detection only.

## Severity model

`critical` RSA/ECC keygen+signing, DH/ECDH in active TLS, MD5/SHA-1 in cert
signing · `high` RSA/ECC in deps, weak JWT, Ed25519/X25519, MD5, DES/3DES ·
`medium` SHA-1 non-cert, RSA cipher suites, indirect string matches · `low`
speculative dependency flags. The root `.pqcscan.yml` sets
`severity_threshold: medium`, so `pqc-scan scan .` in this repo hides `low` —
pass `-s low` to see everything.

## Deliberate deviations from a naive spec reading — do NOT "fix" these

- **`tomllib` is not a pip dependency** (it's stdlib ≥3.11); `tomli` is only a
  `<3.11` fallback.
- **SARIF and CBOM are hand-rolled** (no `cyclonedx-python-lib`) for exact
  control and a lean install.
- **CBOM uses `nistQuantumSecurityLevel`** (the schema-correct field name), not
  the spec's `quantumSecurityLevel`; all flagged algorithms carry level `0`.
- **SARIF emits no `fixes`** — a SARIF fix requires concrete `artifactChanges`
  that a detector can't synthesize. Migration guidance lives in `message.text`,
  `rule.help`, and a structured `result.properties.migration`.
- `scanner/engine.py` is an intentional addition (keeps `cli.py` thin/testable).
- TypeScript (`.ts`/`.tsx`) is best-effort via the JS grammar's error recovery.
- `liboqs-python` is **not** a pure `pip install` (needs the compiled liboqs C
  library) — migration text says so; keep that caveat.

## Common tasks → use the skills

- **Add/extend a detection rule** (new algorithm pattern, new PQC0xx): skill
  `add-detection-rule`.
- **Add a whole new language** (Rust, C#, Ruby, …): skill `add-language`.
- **Figure out node shapes / debug a missed or false detection**: skill
  `inspect-ast`.

## Definition of done for any detection change

1. Targeted vulnerable snippet/fixture produces the expected `PQCxxx`.
2. The matching safe snippet produces **zero** findings.
3. A regression test is added (mirror the `tests/test_*` style).
4. `.venv/bin/python -m pytest` is fully green.
