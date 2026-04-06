import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYS_DIR = Path("keys")
KDF_ITERATIONS = 100_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode())


def generate_keypair(name: str, passphrase: str):
    KEYS_DIR.mkdir(exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (KEYS_DIR / f"{name}.pub").write_bytes(pub_bytes)

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    derived = _derive_key(passphrase, salt)
    aesgcm = AESGCM(derived)
    ct = aesgcm.encrypt(nonce, priv_bytes, None)
    (KEYS_DIR / f"{name}.priv").write_bytes(salt + nonce + ct)


def load_public_key(name: str):
    pub_path = KEYS_DIR / f"{name}.pub"
    if not pub_path.exists():
        print("file not found")
        raise SystemExit(1)
    return serialization.load_pem_public_key(pub_path.read_bytes())


def load_private_key(name: str, passphrase: str):
    priv_path = KEYS_DIR / f"{name}.priv"
    if not priv_path.exists():
        print("file not found")
        raise SystemExit(1)
    raw = priv_path.read_bytes()
    salt = raw[:16]
    nonce = raw[16:28]
    ct = raw[28:]
    derived = _derive_key(passphrase, salt)
    aesgcm = AESGCM(derived)
    try:
        priv_bytes = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        print("bad passphrase")
        raise SystemExit(1)
    return serialization.load_der_private_key(priv_bytes, password=None)
