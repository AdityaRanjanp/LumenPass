"""
security.py — QR-Secure AES-256 Encryption Module
Handles all cryptographic operations for the visitor management system.

Encryption: AES-256-CBC with PKCS7 padding.
Key:        Stored in a hidden file (.secret.key) alongside this script.
            Auto-generated on first run; reused on subsequent runs.
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ── Key Management ─────────────────────────────────────────────
# The key file is kept in the same directory as this script.
# Prefix with '.' to make it hidden on Unix; on Windows it simply
# stays out of casual sight.
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret.key")
KEY_SIZE = 32   # 256 bits
IV_SIZE  = 16   # AES block size


def _load_or_create_key() -> bytes:
    """
    Load the AES-256 key from disk. If the key file does not exist,
    generate a cryptographically secure key and persist it.

    Returns:
        32-byte key suitable for AES-256.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) != KEY_SIZE:
            raise ValueError(f"Corrupted key file: expected {KEY_SIZE} bytes, got {len(key)}")
        return key

    # First-run: generate a new key
    key = get_random_bytes(KEY_SIZE)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(f"[OK] New AES-256 key generated and saved to {KEY_FILE}")
    return key


# Load once at module import time so every call reuses the same key.
_KEY = _load_or_create_key()


# ── Encryption / Decryption ────────────────────────────────────

def encrypt_data(plain_text: str) -> str:
    """
    Encrypt a plain-text string with AES-256-CBC.

    Process:
        1. Generate a random 16-byte IV (initialisation vector).
        2. Pad the plain text to a multiple of the AES block size (PKCS7).
        3. Encrypt with AES-256-CBC.
        4. Prepend the IV to the cipher text (IV is not secret).
        5. Base64-encode the result so it can be stored as text / in a QR.

    Args:
        plain_text: The string to encrypt.

    Returns:
        Base64-encoded string containing [IV + ciphertext].

    Raises:
        ValueError : If plain_text is empty.
        Exception  : Propagates any cryptographic errors.
    """
    if not plain_text:
        raise ValueError("Cannot encrypt empty data.")

    try:
        iv = get_random_bytes(IV_SIZE)
        cipher = AES.new(_KEY, AES.MODE_CBC, iv)
        padded = pad(plain_text.encode("utf-8"), AES.block_size)
        encrypted = cipher.encrypt(padded)
        # IV + ciphertext → base64
        return base64.b64encode(iv + encrypted).decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Encryption error: {e}")
        raise


def decrypt_data(encoded_text: str) -> str:
    """
    Decrypt a Base64-encoded AES-256-CBC cipher string.

    Process:
        1. Base64-decode the input.
        2. Split the first 16 bytes (IV) from the rest (ciphertext).
        3. Decrypt and un-pad.

    Args:
        encoded_text: The base64 string produced by encrypt_data().

    Returns:
        The original plain-text string.

    Raises:
        ValueError : If the encoded_text is empty or malformed.
        Exception  : Propagates any cryptographic / padding errors.
    """
    if not encoded_text:
        raise ValueError("Cannot decrypt empty data.")

    try:
        raw = base64.b64decode(encoded_text)
        iv         = raw[:IV_SIZE]
        ciphertext = raw[IV_SIZE:]
        cipher = AES.new(_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Decryption error: {e}")
        raise


# ── Quick Self-Test ────────────────────────────────────────────
if __name__ == "__main__":
    samples = ["9876543210", "Meeting with Director", "Parcel delivery for Room 301"]
    print("--- AES-256 Self-Test ---")
    for text in samples:
        enc = encrypt_data(text)
        dec = decrypt_data(enc)
        status = "OK" if dec == text else "FAIL"
        print(f"  [{status}] '{text}'")
        print(f"       Encrypted -> {enc[:48]}...")
        print(f"       Decrypted -> {dec}")
    print("--- Done ---")
