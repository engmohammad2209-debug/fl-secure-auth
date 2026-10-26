"""Cryptographic primitives used by the protocol.

Everything is built on the `cryptography` library:
  - Elliptic curve: NIST P-256 (secp256r1)
  - Signatures:     ECDSA with SHA-256
  - Key exchange:   ephemeral ECDH
  - KDF:            HKDF-SHA256
  - MAC:            HMAC-SHA256
  - AEAD:           AES-256-GCM
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()
NONCE_LEN = 16
KEY_LEN = 32


# ---------------------------------------------------------------- keys
def generate_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def pub_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    """Compressed SEC1 encoding (33 bytes)."""
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def load_pub(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)


# ---------------------------------------------------------- signatures
def sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub: ec.EllipticCurvePublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------- key agreement
def ecdh(priv: ec.EllipticCurvePrivateKey, peer_pub: ec.EllipticCurvePublicKey) -> bytes:
    return priv.exchange(ec.ECDH(), peer_pub)


def hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 2 * KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


# ---------------------------------------------------------- utilities
def h(*parts: bytes) -> bytes:
    """Length-prefixed SHA-256, so concatenations can't be ambiguous."""
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def mac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(key, data), tag)


def nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------- AEAD
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if tampered."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
