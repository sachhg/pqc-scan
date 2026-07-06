"""Fixture: RSA usage that pqc-scan must flag (PQC001, PQC002, PQC003)."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from Crypto.PublicKey import RSA


def generate_key():
    # PQC001 — RSA key generation (critical), even at 4096 bits.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def generate_big_key():
    # PQC001 — still flagged: all RSA is quantum-vulnerable.
    return RSA.generate(4096)


def encrypt(public_key, message: bytes) -> bytes:
    # PQC002 — RSA-OAEP encryption.
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign(private_key, message: bytes) -> bytes:
    # PQC002/PQC003 — RSA PKCS1v15 signature padding.
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
