"""Tree-sitter node-traversal helpers shared by every language rule module.

We deliberately use plain node traversal (``node.type`` / ``node.children`` /
``node.child_by_field_name`` / ``node.start_point``) rather than the tree-sitter
query DSL. The query syntax has shifted across tree-sitter releases, whereas the
node API has been stable — so traversal is the portable choice.
"""

from __future__ import annotations

from typing import Iterator, Optional

# A tree-sitter Node is duck-typed here to avoid a hard import dependency.


def walk(node) -> Iterator:
    """Yield *node* and every descendant in pre-order."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # push children reversed so traversal is left-to-right
        stack.extend(reversed(current.children))


def text(node) -> str:
    """Decoded source text of *node* (empty string when unavailable)."""
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def line_col(node) -> tuple[int, int]:
    """1-based (line, column) of *node*'s start, matching editor/SARIF conventions."""
    row, col = node.start_point
    return row + 1, col + 1


def snippet(node, *, max_lines: int = 6) -> str:
    """Source text of *node*, trimmed to *max_lines* for display."""
    raw = text(node)
    lines = raw.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["..."]
    return "\n".join(lines).strip() or raw.strip()


def field(node, name: str):
    """``node.child_by_field_name(name)`` guarding against ``None`` nodes."""
    if node is None:
        return None
    return node.child_by_field_name(name)


def call_function(call):
    """The callee node of a ``call`` (field ``function``, else first named child)."""
    fn = field(call, "function")
    if fn is not None:
        return fn
    for child in call.children:
        if child.is_named:
            return child
    return None


def call_arguments(call):
    """The argument-list node of a ``call`` (field ``arguments``/``argument_list``)."""
    args = field(call, "arguments")
    if args is not None:
        return args
    for child in call.children:
        if child.type in ("argument_list", "arguments"):
            return child
    return None


def dotted_parts(node) -> list[str]:
    """Flatten a dotted access into its identifier components.

    ``rsa.generate_private_key``        -> ``["rsa", "generate_private_key"]``
    ``paramiko.RSAKey.generate``        -> ``["paramiko", "RSAKey", "generate"]``
    ``ec.SECP384R1()`` (call as object) -> ``["ec", "SECP384R1"]``

    Returns ``[]`` when the access cannot be resolved to plain identifiers.
    """
    if node is None:
        return []
    ntype = node.type
    if ntype in (
        "identifier", "property_identifier", "field_identifier",
        "type_identifier", "package_identifier",
    ):
        return [text(node)]
    if ntype in ("attribute", "member_expression", "selector_expression", "field_access"):
        obj = (
            field(node, "object")
            or field(node, "operand")
            or field(node, "value")
        )
        attr = (
            field(node, "attribute")
            or field(node, "property")
            or field(node, "field")
            or field(node, "name")
        )
        if obj is None or attr is None:
            # Fall back to first/last named children.
            named = [c for c in node.children if c.is_named]
            if len(named) >= 2:
                obj, attr = named[0], named[-1]
        return dotted_parts(obj) + dotted_parts(attr)
    if ntype in ("call", "call_expression", "method_invocation"):
        return dotted_parts(call_function(node))
    # Java a.b.C / Go pkg.Type — qualified names built from named children.
    if ntype in ("scoped_identifier", "scoped_type_identifier", "qualified_type"):
        named = [c for c in node.children if c.is_named]
        parts: list[str] = []
        for c in named:
            parts.extend(dotted_parts(c))
        return parts
    return []


def string_value(node) -> Optional[str]:
    """Inner text of a string literal node, or ``None`` if *node* is not a string."""
    if node is None:
        return None
    if node.type in ("string", "interpreted_string_literal", "raw_string_literal"):
        # Prefer an explicit content child; otherwise strip surrounding quotes.
        for child in node.children:
            if child.type in ("string_content", "string_fragment"):
                return text(child)
        raw = text(node)
        return raw.strip("\"'`")
    if node.type in ("string_content", "string_fragment"):
        return text(node)
    return None


def keyword_args(arglist) -> dict[str, object]:
    """Map keyword-argument name -> value node for a Python ``argument_list``."""
    result: dict[str, object] = {}
    if arglist is None:
        return result
    for child in arglist.children:
        if child.type == "keyword_argument":
            name = field(child, "name")
            value = field(child, "value")
            if name is not None and value is not None:
                result[text(name)] = value
    return result


def positional_args(arglist) -> list:
    """Named (non-punctuation, non-keyword) argument value nodes, in order."""
    result: list = []
    if arglist is None:
        return result
    for child in arglist.children:
        if not child.is_named:
            continue
        if child.type in ("keyword_argument", "comment"):
            continue
        result.append(child)
    return result
