"""Fixture: quantum-resistant cryptography only. MUST produce ZERO findings.

Used to validate pqc-scan's false-positive rate.
"""

import hashlib
import hmac
import secrets

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, associated_data: bytes) -> tuple[bytes, bytes, bytes]:
    # AES-256-GCM — symmetric, quantum-resistant.
    key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, associated_data)
    return key, nonce, ciphertext


def digest(data: bytes) -> str:
    # SHA-256 / SHA3-256 — quantum-resistant for hashing.
    return hashlib.sha256(data).hexdigest()


def digest_sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def mac(key: bytes, message: bytes) -> str:
    # HMAC-SHA256 — quantum-resistant.
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def issue_token(payload: dict) -> str:
    # HS256 — symmetric JWT signature, quantum-resistant.
    key = secrets.token_bytes(32)
    return jwt.encode(payload, key, algorithm="HS256")
