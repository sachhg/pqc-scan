"""pqc-scan: a developer-native scanner for quantum-vulnerable cryptography.

Think "Snyk for Post-Quantum Cryptography": a zero-friction CLI and GitHub Action
that flags RSA, ECC, ECDSA, DH, SHA-1, MD5 and friends right inside the pull
request, and points each finding at its NIST-standardized post-quantum
replacement (ML-KEM, ML-DSA, SLH-DSA).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
