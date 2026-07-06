"""Fixture: JWT signing with quantum-vulnerable asymmetric algorithms (PQC011)."""

import jwt
from jose import jwt as jose_jwt


def issue_rs256(payload: dict, private_key) -> str:
    # PQC011 — RS256 (RSA signature) JWT.
    return jwt.encode(payload, private_key, algorithm="RS256")


def issue_es256(payload: dict, private_key) -> str:
    # PQC011 — ES256 (ECDSA signature) JWT.
    return jwt.encode(payload, private_key, algorithm="ES256")


def issue_ps256(payload: dict, private_key) -> str:
    # PQC011 — PS256 (RSA-PSS signature) JWT.
    return jwt.encode(payload, private_key, algorithm="PS256")


def verify_rs256(token: str, public_key):
    # PQC011 — decoding restricted to an asymmetric algorithm.
    return jwt.decode(token, public_key, algorithms=["RS256"])


def jose_rs256(payload: dict, key) -> str:
    # PQC011 — python-jose with an RSA algorithm.
    return jose_jwt.encode(payload, key, algorithm="RS256")
