"""Fixture: weak TLS / hashing / cipher usage (PQC009, PQC010, PQC012, PQC013)."""

import hashlib
import ssl

import paramiko
from Crypto.Cipher import DES3


def legacy_context():
    # PQC012 — outdated TLS protocol constant.
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    # PQC012 — RSA/ECDHE cipher suite string.
    context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    return context


def weak_digests(data: bytes):
    # PQC010 — MD5 (broken).
    md5_digest = hashlib.md5(data).hexdigest()
    # PQC009 — SHA-1 (broken, no quantum margin).
    sha1_digest = hashlib.sha1(data).hexdigest()
    return md5_digest, sha1_digest


def triple_des(key: bytes):
    # PQC013 — 3DES.
    return DES3.new(key, DES3.MODE_CBC)


def ssh_host_key():
    # PQC001 — paramiko RSA host key.
    return paramiko.RSAKey.generate(bits=2048)
