# hybrid-enc

File encryption from the terminal. RSA-2048 for key exchange, AES-256-GCM for the data — same idea as TLS.

## install

```bash
pip install cryptography
```

## usage

**generate a keypair**
```bash
python run.py genkeys --name alice --passphrase hunter2
```

**encrypt a file**
```bash
python run.py encrypt --to alice --file secret.txt
# outputs secret.txt.enc
```

**decrypt a file**
```bash
python run.py decrypt --key alice --passphrase hunter2 --file secret.txt.enc
# outputs secret.txt
```

## how it works

1. random 32-byte AES session key is generated
2. file is encrypted with AES-256-GCM (random 16-byte nonce)
3. session key is wrapped with recipient's RSA public key (OAEP + SHA-256)
4. output is packed as `[4B key length][encrypted key][nonce][ciphertext]`

private keys are stored encrypted — passphrase is stretched with PBKDF2 (100k iterations, SHA-256) before being used to AES-GCM wrap the key material.

## files

```
keys.py   — keypair generation, keystore (pbkdf2 + aes-gcm)
box.py    — encrypt/decrypt logic
run.py    — CLI
keys/     — generated keys land here
```

## errors

bad passphrase, wrong key, missing file — all fail loudly with a message and exit code 1.
