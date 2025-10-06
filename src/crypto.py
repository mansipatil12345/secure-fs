# always remember to go into the folder , activate the virtual environment #.\venv\Scripts\Activate.ps1 (by this command)
#venv keeps the virtual env fr this project their own installed packages in venv for this project not to mess with other projects working on lang python.

"""
src/crypto.py

Simple key & AEAD helpers for the secure-fs prototype.

- MK = Master Key (32 bytes) - keep this OFF-REPO in production
- KEK = Key Encryption Key (derived from MK or passphrase)
- CEK = Content Encryption Key (one per file, 32 bytes)
- AEAD = AES-GCM or XChaCha20-Poly1305 (confidentiality + integrity)
"""

import os
import base64
from typing import Tuple

# cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, XChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# argon2 for passphrase-derived keys (optional)
from argon2.low_level import hash_secret_raw, Type as Argon2Type

# -------------------------
# Basic helpers
# -------------------------
def b64e(b: bytes) -> str:
    """Base64-encode bytes -> string (useful for storing in metadata)."""
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """Base64-decode string -> bytes."""
    return base64.b64decode(s.encode('utf-8'))


# -------------------------
# Master Key helpers
# -------------------------
def generate_mk(path: str) -> bytes:
    """
    Generate a 32-byte MK and write to path.
    IMPORTANT: keep this file out of your Git repo and protect file permission.
    """
    mk = os.urandom(32)  # 32 bytes = 256 bits -> AES-256 strength
    with open(path, "wb") as f:
        f.write(mk)
    try:
        # On POSIX, restrict permissions to owner-only
        os.chmod(path, 0o600)
    except Exception:
        # On Windows os.chmod has limited effect; recommend using OS key store in production
        pass
    return mk


def load_mk(path: str) -> bytes:
    """Load MK from disk (raises if not found)."""
    with open(path, "rb") as f:
        mk = f.read()
    if len(mk) < 32:
        raise ValueError("MK looks too short.")
    return mk


# -------------------------
# KEK derivation
# -------------------------
def derive_kek_hkdf(mk: bytes, info: bytes = b'') -> bytes:
    """
    Derive a KEK from the MK using HKDF-SHA256.
    - info is application-specific context (e.g., b'volume:main' or b'user:alice').
    - HKDF is safe for deriving keys from a uniformly random MK.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,   # derive a 32-byte KEK (AES-256)
        salt=None,   # optional salt; with a random MK salt is less important
        info=info,
    )
    return hkdf.derive(mk)


def derive_kek_from_passphrase(passphrase: str, salt: bytes, time_cost: int = 2,
                               memory_cost: int = 102400, parallelism: int = 8) -> bytes:
    """
    Derive a KEK from a passphrase using Argon2id (recommended for passphrase->key).
    - salt must be random and stored along with the derived key reference.
    - returns 32 raw bytes.
    """
    # hash_secret_raw returns raw bytes (not encoded string)
    return hash_secret_raw(
        secret=passphrase.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )


# -------------------------
# CEK generation
# -------------------------
def generate_cek() -> bytes:
    """Generate a per-file CEK (32 bytes)."""
    return os.urandom(32)


# -------------------------
# AEAD encrypt/decrypt helpers
# -------------------------
def encrypt_chunk(cek: bytes, plaintext: bytes, aad: bytes = b'', algorithm: str = 'aesgcm') -> Tuple[bytes, bytes]:
    """
    Encrypt a chunk with CEK using AEAD.
    Returns: (nonce, ciphertext)
    algorithm: 'aesgcm' (12-byte nonce) or 'xchacha20' (24-byte nonce)
    """
    if algorithm == 'aesgcm':
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM (recommended)
        aes = AESGCM(cek)
        ct = aes.encrypt(nonce, plaintext, aad)  # ciphertext contains tag appended
        return nonce, ct
    elif algorithm == 'xchacha20':
        nonce = os.urandom(24)  # XChaCha20 uses 192-bit nonce
        x = XChaCha20Poly1305(cek)
        ct = x.encrypt(nonce, plaintext, aad)
        return nonce, ct
    else:
        raise ValueError("Unsupported algorithm")


def decrypt_chunk(cek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b'', algorithm: str = 'aesgcm') -> bytes:
    """Decrypt AEAD chunk (reverse of encrypt_chunk)."""
    if algorithm == 'aesgcm':
        aes = AESGCM(cek)
        return aes.decrypt(nonce, ciphertext, aad)
    elif algorithm == 'xchacha20':
        x = XChaCha20Poly1305(cek)
        return x.decrypt(nonce, ciphertext, aad)
    else:
        raise ValueError("Unsupported algorithm")


# -------------------------
# Key wrap/unwrap (wrap CEK with KEK)
# -------------------------
def wrap_key(kek: bytes, cek: bytes, aad: bytes = b'', algorithm: str = 'aesgcm') -> Tuple[bytes, bytes]:
    """
    Wrap a CEK using the KEK with AEAD. Return (nonce, wrapped_cek_bytes).
    Storing wrapped CEK (plus nonce) in metadata allows later unwrapping.
    """
    # We use the same AEAD API as chunk encryption
    return encrypt_chunk(kek, cek, aad, algorithm=algorithm)


def unwrap_key(kek: bytes, wrapped_cek: bytes, nonce: bytes, aad: bytes = b'', algorithm: str = 'aesgcm') -> bytes:
    """Unwrap (decrypt) a wrapped CEK."""
    return decrypt_chunk(kek, nonce, wrapped_cek, aad, algorithm=algorithm)


# -------------------------
# Small demonstration when run directly
# -------------------------
if __name__ == "__main__":
    # Demo: generate MK (for demo we write to project; in real life keep off-repo!)
    demo_mk_path = os.path.join(os.path.dirname(__file__), "..", "master_demo.key")
    demo_mk_path = os.path.normpath(demo_mk_path)

    print("1) Generating MK (demo) ->", demo_mk_path)
    mk = generate_mk(demo_mk_path)
    print("   MK (base64):", b64e(mk))

    # Derive a KEK for this volume
    info = b'volume:demo'  # context string that namespaces the derived key
    kek = derive_kek_hkdf(mk, info=info)
    print("2) Derived KEK from MK (HKDF). KEK (b64):", b64e(kek))

    # Generate CEK for a file and wrap it
    cek = generate_cek()
    print("3) Generated CEK per-file (b64):", b64e(cek))

    nonce_wrap, wrapped = wrap_key(kek, cek, aad=b'file:example.txt')
    print("   Wrapped CEK nonce (b64):", b64e(nonce_wrap))
    print("   Wrapped CEK (b64):", b64e(wrapped))

    # Simulate writing a file: encrypt a chunk with CEK
    plaintext = b"Hello secure filesystem - secret file content!"
    nonce_chunk, ciphertext = encrypt_chunk(cek, plaintext, aad=b'file-chunk:0')
    print("4) Encrypted chunk nonce (b64):", b64e(nonce_chunk))
    print("   Ciphertext (b64):", b64e(ciphertext))

    # Now unwrap CEK (using the KEK) and decrypt the chunk
    cek_unwrapped = unwrap_key(kek, wrapped, nonce_wrap, aad=b'file:example.txt')
    recovered = decrypt_chunk(cek_unwrapped, nonce_chunk, ciphertext, aad=b'file-chunk:0')
    print("5) Decrypted plaintext:", recovered.decode('utf-8'))

    assert recovered == plaintext
    print("✅ Demo success: encrypt -> wrap -> unwrap -> decrypt works.")


