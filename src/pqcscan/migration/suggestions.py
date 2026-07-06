"""Per-algorithm post-quantum migration guidance.

Each quantum-vulnerable algorithm family maps to a :class:`MigrationSuggestion`
that names the NIST-standardized replacement, the library to reach for, a plain
English explanation and a concrete before/after code example.

Note on liboqs-python: ``oqs`` is a thin wrapper over the liboqs C library, so it
is **not** a pure ``pip install``. The compiled liboqs shared library must be
available (``pip install liboqs`` builds it from source via CMake, or install the
distro package / build from https://github.com/open-quantum-safe/liboqs). The
install hints below say so explicitly.
"""

from __future__ import annotations

from pqcscan.scanner.base import MigrationSuggestion

# Reusable install hint that captures the liboqs caveat once.
_LIBOQS_INSTALL = (
    "liboqs-python (requires the compiled liboqs C library — not a pure pip "
    "install: `pip install liboqs` builds it via CMake, or install the distro "
    "package / build from https://github.com/open-quantum-safe/liboqs)"
)

_OQS_DOCS = "https://github.com/open-quantum-safe/liboqs-python"
_FIPS203 = "https://csrc.nist.gov/pubs/fips/203/final"
_FIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"
_FIPS205 = "https://csrc.nist.gov/pubs/fips/205/final"


_RSA_KEYGEN = MigrationSuggestion(
    recommended_algorithm="ML-KEM-768 (CRYSTALS-Kyber) for encryption / key "
    "establishment, or ML-DSA-65 (CRYSTALS-Dilithium) if the key is used for signing",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "RSA key pairs are broken by Shor's algorithm at every key size, including "
        "RSA-4096. If the key protects data confidentiality (encryption / key "
        "transport), replace it with the ML-KEM key-encapsulation mechanism. If it "
        "signs data, replace it with the ML-DSA signature scheme."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n\n"
        "# After (quantum-safe key establishment):\n"
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        "public_key = kem.generate_keypair()\n"
        "ciphertext, shared_secret = oqs.KeyEncapsulation('ML-KEM-768').encap_secret(public_key)"
    ),
    nist_standard="FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)",
    docs_url=_FIPS203,
)

_RSA_ENCRYPTION = MigrationSuggestion(
    recommended_algorithm="ML-KEM-768 (CRYSTALS-Kyber)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "RSA encryption and RSA padding schemes (OAEP, PKCS1v15) are broken by Shor's "
        "algorithm. Stop using RSA to wrap/transport keys; establish a shared secret "
        "with the ML-KEM key-encapsulation mechanism and encrypt payloads with AES-256-GCM."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
        "ciphertext = public_key.encrypt(data, padding.OAEP(...))\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        "public_key = kem.generate_keypair()\n"
        "ciphertext, shared_secret = kem.encap_secret(public_key)\n"
        "# derive an AES-256-GCM key from shared_secret and encrypt the payload"
    ),
    nist_standard="FIPS 203",
    docs_url=_FIPS203,
)

_RSA_SIGNATURE = MigrationSuggestion(
    recommended_algorithm="ML-DSA-65 (CRYSTALS-Dilithium)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "RSA signatures (PSS or PKCS1v15) become forgeable once Shor's algorithm runs. "
        "Replace RSA signing with the ML-DSA signature scheme; SLH-DSA (SPHINCS+) is a "
        "conservative hash-based alternative."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "sig = oqs.Signature('ML-DSA-65')\n"
        "public_key = sig.generate_keypair()\n"
        "signature = sig.sign(message)"
    ),
    nist_standard="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
    docs_url=_FIPS204,
)

_ECDSA = MigrationSuggestion(
    recommended_algorithm="ML-DSA-65 (CRYSTALS-Dilithium)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "ECDSA and all elliptic-curve keys (P-256, P-384, P-521, secp256k1) are broken "
        "by Shor's algorithm. Replace ECDSA signing with the ML-DSA signature scheme; "
        "FALCON or SLH-DSA are alternatives where signature size or statefulness matters."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "private_key = ec.generate_private_key(ec.SECP256R1())\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "sig = oqs.Signature('ML-DSA-65')\n"
        "public_key = sig.generate_keypair()\n"
        "signature = sig.sign(message)"
    ),
    nist_standard="FIPS 204",
    docs_url=_FIPS204,
)

_ECDH = MigrationSuggestion(
    recommended_algorithm="ML-KEM-768 (CRYSTALS-Kyber)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "ECDH / ECDHE / X25519 key exchange is a prime 'harvest now, decrypt later' "
        "target: captured handshakes can be decrypted once a quantum computer exists. "
        "Replace the ephemeral ECDH exchange with the ML-KEM key-encapsulation "
        "mechanism (or a hybrid X25519+ML-KEM construction during transition)."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\n"
        "private_key = X25519PrivateKey.generate()\n"
        "shared = private_key.exchange(peer_public_key)\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        "public_key = kem.generate_keypair()\n"
        "ciphertext, shared_secret = kem.encap_secret(public_key)"
    ),
    nist_standard="FIPS 203",
    docs_url=_FIPS203,
)

_ED25519 = MigrationSuggestion(
    recommended_algorithm="ML-DSA-65 (CRYSTALS-Dilithium)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "Ed25519 / Ed448 are modern but still Edwards-curve signatures, broken by Shor's "
        "algorithm. Replace with the ML-DSA signature scheme; SLH-DSA (SPHINCS+) if you "
        "prefer hash-based security assumptions."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "private_key = Ed25519PrivateKey.generate()\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "sig = oqs.Signature('ML-DSA-65')\n"
        "public_key = sig.generate_keypair()\n"
        "signature = sig.sign(message)"
    ),
    nist_standard="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
    docs_url=_FIPS204,
)

_DH = MigrationSuggestion(
    recommended_algorithm="ML-KEM-768 (CRYSTALS-Kyber)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "Classical Diffie-Hellman is broken by Shor's algorithm. Replace the DH/DHE key "
        "agreement with the ML-KEM key-encapsulation mechanism."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "parameters = dh.generate_parameters(generator=2, key_size=2048)\n"
        "private_key = parameters.generate_private_key()\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        "public_key = kem.generate_keypair()\n"
        "ciphertext, shared_secret = kem.encap_secret(public_key)"
    ),
    nist_standard="FIPS 203",
    docs_url=_FIPS203,
)

_DSA = MigrationSuggestion(
    recommended_algorithm="ML-DSA-65 (CRYSTALS-Dilithium)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "DSA is broken by Shor's algorithm. Replace it with the ML-DSA signature scheme."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "private_key = dsa.generate_private_key(key_size=2048)\n\n"
        "# After (quantum-safe):\n"
        "import oqs\n"
        "sig = oqs.Signature('ML-DSA-65')\n"
        "public_key = sig.generate_keypair()\n"
        "signature = sig.sign(message)"
    ),
    nist_standard="FIPS 204",
    docs_url=_FIPS204,
)

_SHA1 = MigrationSuggestion(
    recommended_algorithm="SHA-256 or SHA3-256",
    recommended_library="hashlib (Python standard library)",
    migration_description=(
        "SHA-1 is classically broken (practical collisions) and offers no quantum margin. "
        "Switch to SHA-256 or SHA3-256, which remain quantum-resistant for hashing "
        "(Grover only halves preimage security, leaving a comfortable 128-bit margin)."
    ),
    code_example=(
        "# Before (broken):\n"
        "import hashlib\n"
        "digest = hashlib.sha1(data).hexdigest()\n\n"
        "# After (safe):\n"
        "digest = hashlib.sha256(data).hexdigest()\n"
        "# or: hashlib.sha3_256(data).hexdigest()"
    ),
    nist_standard="FIPS 180-4 (SHA-2) / FIPS 202 (SHA-3)",
    docs_url="https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
)

_MD5 = MigrationSuggestion(
    recommended_algorithm="SHA-256 or SHA3-256",
    recommended_library="hashlib (Python standard library)",
    migration_description=(
        "MD5 is comprehensively broken and unsuitable for any security purpose. Replace "
        "it with SHA-256 or SHA3-256."
    ),
    code_example=(
        "# Before (broken):\n"
        "import hashlib\n"
        "digest = hashlib.md5(data).hexdigest()\n\n"
        "# After (safe):\n"
        "digest = hashlib.sha256(data).hexdigest()"
    ),
    nist_standard="FIPS 180-4 (SHA-2) / FIPS 202 (SHA-3)",
    docs_url="https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
)

_JWT = MigrationSuggestion(
    recommended_algorithm="HS256 (symmetric) for internal services; await ML-DSA "
    "JOSE registration for external-facing tokens",
    recommended_library="PyJWT / jose (existing) — no PQC JOSE algorithm is standardized yet",
    migration_description=(
        "RS256 / ES256 / PS256 sign JWTs with quantum-vulnerable RSA or ECDSA keys. "
        "ML-DSA JWT algorithms are not yet standardized in JOSE. For internal services, "
        "migrate to HS256 with a 256-bit symmetric key (quantum-resistant). For "
        "external-facing JWTs, monitor the IETF JOSE working group for PQC algorithm "
        "registration before switching."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "import jwt\n"
        "token = jwt.encode(payload, private_key, algorithm='RS256')\n\n"
        "# After (internal services — symmetric, quantum-resistant):\n"
        "import jwt, secrets\n"
        "key = secrets.token_bytes(32)  # 256-bit shared secret\n"
        "token = jwt.encode(payload, key, algorithm='HS256')"
    ),
    nist_standard="N/A (track IETF JOSE WG for PQC algorithm registration)",
    docs_url="https://datatracker.ietf.org/wg/jose/about/",
)

_TLS_CONFIG = MigrationSuggestion(
    recommended_algorithm="TLS 1.3 with a hybrid X25519+ML-KEM-768 key exchange group",
    recommended_library="OpenSSL 3.5+ / BoringSSL / oqs-provider",
    migration_description=(
        "The configured cipher suites or protocol versions rely on quantum-vulnerable RSA "
        "or ECDHE key exchange (or on broken DES/RC4/NULL suites). Require TLS 1.3, drop "
        "legacy ciphers, and enable a hybrid post-quantum key-exchange group such as "
        "X25519MLKEM768 so captured handshakes cannot be decrypted later."
    ),
    code_example=(
        "# Before (quantum-vulnerable):\n"
        "ssl_protocols TLSv1.1 TLSv1.2;\n"
        "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n\n"
        "# After (TLS 1.3 with hybrid PQC key exchange):\n"
        "ssl_protocols TLSv1.3;\n"
        "ssl_ecdh_curve X25519MLKEM768:X25519;  # OpenSSL 3.5+ / oqs-provider"
    ),
    nist_standard="FIPS 203 (ML-KEM)",
    docs_url="https://openquantumsafe.org/applications/tls.html",
)

_DES = MigrationSuggestion(
    recommended_algorithm="AES-256-GCM",
    recommended_library="cryptography (Python) / hazmat ciphers",
    migration_description=(
        "DES and Triple-DES have small key sizes that are classically weak and further "
        "eroded by Grover's algorithm. Replace them with AES-256-GCM, which remains "
        "quantum-resistant (Grover leaves an effective 128-bit security level)."
    ),
    code_example=(
        "# Before (weak):\n"
        "from Crypto.Cipher import DES3\n"
        "cipher = DES3.new(key, DES3.MODE_CBC)\n\n"
        "# After (safe):\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "key = AESGCM.generate_key(bit_length=256)\n"
        "ciphertext = AESGCM(key).encrypt(nonce, data, associated_data)"
    ),
    nist_standard="FIPS 197 (AES)",
    docs_url="https://csrc.nist.gov/pubs/fips/197/final",
)

_DEPENDENCY = MigrationSuggestion(
    recommended_algorithm="Audit usage, then migrate to ML-KEM / ML-DSA (liboqs)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "This dependency's primary purpose is quantum-vulnerable cryptography. It does not "
        "necessarily mean vulnerable code paths are exercised — verify how the library is "
        "used and plan migration of any RSA/ECC/DH operations to ML-KEM / ML-DSA."
    ),
    code_example=(
        "# Review where this dependency performs key generation, signing, or key\n"
        "# exchange, then migrate those call sites to liboqs (ML-KEM / ML-DSA).\n"
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')  # replaces RSA/ECDH key transport\n"
        "sig = oqs.Signature('ML-DSA-65')          # replaces RSA/ECDSA signatures"
    ),
    nist_standard="FIPS 203 / FIPS 204",
    docs_url=_OQS_DOCS,
)


#: Algorithm family -> migration suggestion. ``build_finding`` looks up by the
#: ``algorithm_family`` recorded on each rule.
_SUGGESTIONS: dict[str, MigrationSuggestion] = {
    "rsa": _RSA_KEYGEN,
    "rsa-encryption": _RSA_ENCRYPTION,
    "rsa-signature": _RSA_SIGNATURE,
    "ecdsa": _ECDSA,
    "ecc": _ECDSA,
    "ecdh": _ECDH,
    "x25519": _ECDH,
    "ed25519": _ED25519,
    "dh": _DH,
    "dsa": _DSA,
    "sha1": _SHA1,
    "md5": _MD5,
    "jwt-asymmetric": _JWT,
    "tls-config": _TLS_CONFIG,
    "des": _DES,
    "dependency": _DEPENDENCY,
}

# Generic fallback so an unmapped family never crashes finding construction.
_FALLBACK = MigrationSuggestion(
    recommended_algorithm="A NIST-standardized post-quantum algorithm (ML-KEM / ML-DSA / SLH-DSA)",
    recommended_library=_LIBOQS_INSTALL,
    migration_description=(
        "This algorithm is quantum-vulnerable. Migrate key establishment to ML-KEM "
        "(FIPS 203) and signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."
    ),
    code_example=(
        "import oqs\n"
        "kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        "sig = oqs.Signature('ML-DSA-65')"
    ),
    nist_standard="FIPS 203 / FIPS 204 / FIPS 205",
    docs_url=_OQS_DOCS,
)


def get_suggestion(algorithm_family: str) -> MigrationSuggestion:
    """Return the migration suggestion for *algorithm_family* (never ``None``)."""
    return _SUGGESTIONS.get(algorithm_family, _FALLBACK)


def all_families() -> list[str]:
    """All algorithm families that have a dedicated suggestion."""
    return sorted(_SUGGESTIONS)
