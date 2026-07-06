---
name: inspect-ast
description: Use when writing or debugging a pqc-scan detection rule and you need to see the tree-sitter AST node shapes for a code snippet, or to check what a language module's analyze() actually emits (debugging a missed detection / false positive). Provides ready-to-run inspection commands for python/javascript/java/go grammars.
---

# Inspecting tree-sitter ASTs and analyzer output

Detection rules are written against concrete node shapes. Never guess them — dump
the tree first. All commands run from the repo root with the project venv.

## 1. Dump the AST for a snippet

Swap the grammar import (`tree_sitter_python` | `tree_sitter_javascript` |
`tree_sitter_java` | `tree_sitter_go`) and the `SRC` string:

```bash
.venv/bin/python - <<'PY'
import tree_sitter_python as G            # <-- change grammar here
from tree_sitter import Language, Parser
parser = Parser(Language(G.language()))

SRC = b'''
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP384R1())
'''

def walk(n, d=0):
    txt = n.text.decode() if n.text else ""
    if len(txt) > 45: txt = txt[:45] + "..."
    anon = "" if n.is_named else " (anon)"
    print("  "*d + f"{n.type}{anon}  L{n.start_point[0]}C{n.start_point[1]}  {txt!r}")
    for c in n.children: walk(c, d+1)

walk(parser.parse(SRC).root_node)
PY
```

Key things to read off: the **call node type** (`call` / `call_expression` /
`method_invocation`), how the callee decomposes (`attribute` / `member_expression`
/ `selector_expression` → object + property), how arguments appear
(`argument_list` / `arguments`, `keyword_argument`, object-literal `pair`), and
the string node type (`string` + `string_content` / `string_literal` +
`string_fragment`).

## 2. Confirm the `_helpers` API resolves your nodes

The shared helpers are the only sanctioned node accessors:
`walk, text, line_col, snippet, field, call_function, call_arguments,
dotted_parts, string_value, keyword_args, positional_args`. Sanity-check them:

```bash
.venv/bin/python - <<'PY'
import tree_sitter_python as G
from tree_sitter import Language, Parser
from pqcscan.languages import _helpers as h
parser = Parser(Language(G.language()))
root = parser.parse(b"k = ec.generate_private_key(ec.SECP384R1())").root_node
for n in h.walk(root):
    if n.type == "call":
        fn = h.call_function(n)
        print("dotted_parts(callee) =", h.dotted_parts(fn))     # ['ec', 'generate_private_key']
        print("positional args      =", [h.dotted_parts(a) for a in h.positional_args(h.call_arguments(n))])
PY
```

If `dotted_parts` returns `[]` for the new grammar, extend `dotted_parts` /
`string_value` in `_helpers.py` to handle that grammar's node types.

## 3. See exactly what a language module emits

Debug a missed detection or a false positive by running `analyze()` directly:

```bash
.venv/bin/python - <<'PY'
import tree_sitter_python as G
from tree_sitter import Language, Parser
from pqcscan.languages import python_rules as mod      # <-- module under test
parser = Parser(Language(G.language()))
SRC = "from hashlib import md5 as m\nm(b'x')\n"
findings = mod.analyze(parser.parse(SRC.encode()).root_node, SRC, "t.py")
for f in findings:
    print(f"L{f.line_number}C{f.column_number} {f.rule_id} {f.severity} {f.confidence}  {f.algorithm}")
print("total:", len(findings))
PY
```

## 4. End-to-end through the real pipeline

```bash
.venv/bin/pqc-scan scan path/to/snippet.py -o json -s low | .venv/bin/python -m json.tool
```

## Gotchas

- **Positions are 0-based in raw tree-sitter** (`start_point`), but `h.line_col`
  returns 1-based — findings are 1-based.
- **`node.text` is `bytes`**; decode with `errors="replace"` (helpers do this).
- **Don't compare nodes with `is`** — wrappers are recreated per access; compare
  `(node.start_byte, node.end_byte)`.
- tree-sitter is **error-tolerant**: a `.ts` file parsed with the JS grammar
  produces `ERROR` nodes but call detection usually still works.
