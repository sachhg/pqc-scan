"""Fixture: a whole file waived with a single file-level directive.

pqc-scan: ignore-file -- vendored reference implementation, not shipped
"""

from cryptography.hazmat.primitives.asymmetric import rsa


def build_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign(key, data):
    return key.sign(data, None, None)
