"""Fixture: elliptic-curve usage that pqc-scan must flag (PQC004, PQC005, PQC006)."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.PublicKey import ECC


def ecdsa_p256():
    # PQC004 — ECDSA key generation on P-256.
    return ec.generate_private_key(ec.SECP256R1())


def ecdsa_p384():
    # PQC004 — ECDSA key generation on P-384.
    return ec.generate_private_key(ec.SECP384R1())


def ecdsa_secp256k1():
    # PQC004 — ECC key generation on secp256k1 (pycryptodome).
    return ECC.generate(curve="secp256k1")


def ecdh_exchange(peer_public_key):
    # PQC005 — X25519 key exchange (harvest-now-decrypt-later target).
    private_key = X25519PrivateKey.generate()
    return private_key.exchange(peer_public_key)


def ed25519_signing_key():
    # PQC006 — Ed25519 signing key (modern, still elliptic-curve).
    return Ed25519PrivateKey.generate()
