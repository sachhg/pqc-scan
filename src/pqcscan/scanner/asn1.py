"""A minimal DER reader — just enough to identify a key's algorithm.

pqc-scan reports *which* algorithm a stored key or certificate uses, which means
reading the ASN.1 structure rather than guessing from the PEM label: a
PEM block labelled ``PRIVATE KEY`` is PKCS#8 and can hold RSA, EC, Ed25519 —
or ML-DSA, which must **not** be flagged. The label alone cannot tell them apart.

This is deliberately a reader, not a full ASN.1 implementation: it decodes DER
tag/length/value triples, object identifiers and integers, and refuses anything
malformed by raising :class:`Asn1Error`. It never executes, verifies or decrypts
anything, and it is bounded by the input buffer — a truncated or hostile file
raises rather than looping.

Using a real X.509 library instead would mean a heavyweight dependency (and, for
``cryptography``, a Rust toolchain) for what amounts to reading two OIDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

# Universal ASN.1 tag numbers we care about.
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

#: Guard against pathological nesting in a malformed or hostile file.
_MAX_DEPTH = 32


class Asn1Error(ValueError):
    """Raised when the input is not well-formed DER."""


@dataclass(frozen=True)
class Node:
    """One decoded DER tag/length/value triple."""

    tag: int
    start: int  # offset of the tag byte
    content_start: int
    content_end: int
    data: bytes

    @property
    def content(self) -> bytes:
        return self.data[self.content_start : self.content_end]

    @property
    def end(self) -> int:
        return self.content_end

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list["Node"]:
        """Decode the immediate children of a constructed node."""
        if not self.is_constructed:
            return []
        return list(_read_all(self.data, self.content_start, self.content_end))


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise Asn1Error("truncated length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise Asn1Error("indefinite lengths are not valid DER")
    if count > 4 or offset + count > len(data):
        raise Asn1Error("unsupported or truncated long-form length")
    value = int.from_bytes(data[offset : offset + count], "big")
    return value, offset + count


def read(data: bytes, offset: int = 0) -> Node:
    """Decode the DER element starting at *offset*."""
    if offset >= len(data):
        raise Asn1Error("truncated element")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("high-tag-number form is not supported")
    length, content_start = _read_length(data, offset + 1)
    content_end = content_start + length
    if content_end > len(data):
        raise Asn1Error("element length exceeds buffer")
    return Node(
        tag=tag,
        start=offset,
        content_start=content_start,
        content_end=content_end,
        data=data,
    )


def _read_all(data: bytes, start: int, end: int) -> Iterator[Node]:
    offset = start
    while offset < end:
        node = read(data, offset)
        yield node
        if node.end <= offset:  # zero-length loop guard
            raise Asn1Error("non-advancing element")
        offset = node.end


def oid_string(node: Node) -> str:
    """Decode an OBJECT IDENTIFIER node to dotted-decimal form."""
    if node.tag != TAG_OID:
        raise Asn1Error(f"expected OID, got tag 0x{node.tag:02x}")
    content = node.content
    if not content:
        raise Asn1Error("empty OID")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for index, byte in enumerate(content[1:], start=1):
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
        elif index == len(content) - 1:
            raise Asn1Error("truncated OID arc")
    return ".".join(parts)


def integer_bit_length(node: Node) -> int:
    """Bit length of an INTEGER, ignoring the DER sign padding byte.

    This is how an RSA key size is read: the modulus is the first INTEGER after
    the version field, and its bit length *is* the advertised key size.
    """
    if node.tag != TAG_INTEGER:
        raise Asn1Error(f"expected INTEGER, got tag 0x{node.tag:02x}")
    raw = node.content.lstrip(b"\x00")
    return len(raw) * 8 - (8 - raw[0].bit_length()) if raw else 0


def walk(node: Node, depth: int = 0) -> Iterator[Node]:
    """Yield *node* and every descendant, depth-first."""
    yield node
    if depth >= _MAX_DEPTH:
        return
    for child in node.children():
        yield from walk(child, depth + 1)


def first_oid(node: Node) -> Optional[str]:
    """The first OBJECT IDENTIFIER at or below *node*, in document order."""
    for candidate in walk(node):
        if candidate.tag == TAG_OID:
            try:
                return oid_string(candidate)
            except Asn1Error:
                return None
    return None
