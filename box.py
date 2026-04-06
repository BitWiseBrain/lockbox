import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys import load_public_key, load_private_key

NONCE_LEN = 16


def encrypt_file(recipient: str, filepath: str):
    src = Path(filepath)
    if not src.exists():
        print("file not found")
        raise SystemExit(1)

    plaintext = src.read_bytes()
    pub_key = load_public_key(recipient)

    session_key = os.urandom(32)

    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_key = pub_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    header = struct.pack(">I", len(encrypted_key))
    out_path = src.with_name(src.name + ".enc")
    out_path.write_bytes(header + encrypted_key + nonce + ciphertext)


def decrypt_file(key_name: str, passphrase: str, filepath: str):
    src = Path(filepath)
    if not src.exists():
        print("file not found")
        raise SystemExit(1)

    raw = src.read_bytes()
    priv_key = load_private_key(key_name, passphrase)

    enc_key_len = struct.unpack(">I", raw[:4])[0]
    encrypted_key = raw[4 : 4 + enc_key_len]
    nonce = raw[4 + enc_key_len : 4 + enc_key_len + NONCE_LEN]
    ciphertext = raw[4 + enc_key_len + NONCE_LEN :]

    try:
        session_key = priv_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        print("decryption failed")
        raise SystemExit(1)

    try:
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print("decryption failed")
        raise SystemExit(1)

    out_name = src.name
    if out_name.endswith(".enc"):
        out_name = out_name[:-4]
    else:
        out_name = out_name + ".dec"
    out_path = src.with_name(out_name)
    out_path.write_bytes(plaintext)
