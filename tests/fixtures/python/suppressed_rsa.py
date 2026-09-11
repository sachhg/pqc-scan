"""Fixture: quantum-vulnerable calls that are waived by inline directives.

Every finding in this file is covered by a `pqc-scan: ignore` directive, so a
default scan must report ZERO findings here while still recording them as
suppressed.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


def legacy_rsa_key():
    # Same-line form, scoped to one rule, with a reason.
    return rsa.generate_private_key(  # pqc-scan: ignore[PQC001] -- legacy peer, tracked in JIRA-42
        public_exponent=65537,
        key_size=2048,
    )


def legacy_ec_key():
    # pqc-scan: ignore-next-line[PQC004] -- pinned by an external protocol spec
    return ec.generate_private_key(ec.SECP256R1())


def legacy_dsa_key():
    # Bare form (no rule list) suppresses every rule on this line.
    return dsa.generate_private_key(key_size=2048)  # pqc-scan: ignore


def legacy_digest(data: bytes) -> str:
    # pqc-scan: ignore-next-line
    return hashlib.sha1(data).hexdigest()
