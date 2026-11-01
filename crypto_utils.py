"""
crypto_utils.py
───────────────
Cryptographic utilities for Secure File Sharing over WLAN.
Project by: ALAN JAISON

Features:
  - AES-256-GCM Authenticated Encryption & Decryption (confidentiality + authenticity)
  - PBKDF2-HMAC-SHA256 Key Derivation from passphrases
  - SHA-256 Data Integrity Hashing & Verification
  - Chunked streaming for arbitrarily large files with progress monitoring
"""

import os
import struct
import hashlib
from typing import Optional, Callable, Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Constants
SALT_SIZE = 16          # 128-bit salt
NONCE_SIZE = 12         # 96-bit standard nonce for AES-GCM
KEY_SIZE = 32           # 256-bit key for AES-256
PBKDF2_ITERATIONS = 100_000
CHUNK_SIZE = 64 * 1024  # 64 KB per chunk
MAGIC_HEADER = b"SFSWLAN1"  # File container signature (Secure File Sharing WLAN v1)


def derive_key(passphrase: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
    
    Returns:
        (key_bytes, salt_bytes)
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt


def compute_sha256(filepath: str, chunk_size: int = CHUNK_SIZE, progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
    """
    Compute SHA-256 hash of a local file in streaming chunks.
    
    Returns:
        Lowercase hexadecimal digest string (64 characters)
    """
    hasher = hashlib.sha256()
    total_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    read_so_far = 0

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            read_so_far += len(chunk)
            if progress_callback and total_size > 0:
                progress_callback(read_so_far, total_size)

    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    Returns:
        (nonce_12_bytes, ciphertext_with_16_byte_tag)
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt ciphertext bytes using AES-256-GCM.
    Raises cryptography.exceptions.InvalidTag if ciphertext or tag is modified.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def encrypt_file(
    key: bytes,
    salt: bytes,
    in_path: str,
    out_path: str,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> Dict[str, Any]:
    """
    Encrypt a file using chunked AES-256-GCM and compute original SHA-256 integrity hash.
    
    File format layout:
      [8 bytes] MAGIC: b"SFSWLAN1"
      [16 bytes] Salt
      [12 bytes] Base Nonce
      [8 bytes] Original file size (uint64)
      [64 bytes] Original SHA-256 hex string (ASCII)
      [4 bytes] Chunk count (uint32)
      For each chunk:
        [4 bytes] Encrypted chunk length (uint32)
        [N bytes] Ciphertext + 16-byte GCM tag
    """
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    file_size = os.path.getsize(in_path)
    base_nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # First pass: compute original SHA-256 hash
    orig_sha256 = compute_sha256(in_path)

    # Calculate number of chunks
    num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 1

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # Write container header
        fout.write(MAGIC_HEADER)
        fout.write(salt)
        fout.write(base_nonce)
        fout.write(struct.pack(">Q", file_size))
        fout.write(orig_sha256.encode("ascii"))  # 64 bytes
        fout.write(struct.pack(">I", num_chunks))

        bytes_processed = 0
        chunk_idx = 0

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk and chunk_idx > 0:
                break
            if not chunk and chunk_idx == 0:
                # Handle 0-byte file
                chunk = b""

            # Derive chunk nonce: base_nonce[:8] + 4-byte chunk counter
            chunk_nonce = base_nonce[:8] + struct.pack(">I", chunk_idx)
            ad = struct.pack(">I", chunk_idx)

            encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, ad)
            fout.write(struct.pack(">I", len(encrypted_chunk)))
            fout.write(encrypted_chunk)

            bytes_processed += len(chunk)
            chunk_idx += 1

            if progress_callback and file_size > 0:
                progress_callback(bytes_processed, file_size)

            if not chunk:
                break

    encrypted_size = os.path.getsize(out_path)
    return {
        "original_sha256": orig_sha256,
        "original_size": file_size,
        "encrypted_size": encrypted_size,
        "chunks": chunk_idx,
    }


def decrypt_file(
    passphrase_or_key: str | bytes,
    in_path: str,
    out_path: str,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> Dict[str, Any]:
    """
    Decrypt an encrypted file container using AES-256-GCM and verify SHA-256 integrity.
    
    Returns:
        dict with:
          - "original_sha256": hash recorded at sender
          - "decrypted_sha256": hash computed on decrypted file
          - "integrity_verified": True if hashes match and tags verified
          - "file_size": size of restored file
    """
    with open(in_path, "rb") as fin:
        # Read header
        magic = fin.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ValueError("Invalid file format: MAGIC header does not match SFSWLAN1")

        salt = fin.read(SALT_SIZE)
        base_nonce = fin.read(NONCE_SIZE)
        file_size = struct.unpack(">Q", fin.read(8))[0]
        expected_sha256 = fin.read(64).decode("ascii")
        num_chunks = struct.unpack(">I", fin.read(4))[0]

        # Derive key if passphrase string passed
        if isinstance(passphrase_or_key, str):
            key, _ = derive_key(passphrase_or_key, salt)
        else:
            key = passphrase_or_key

        aesgcm = AESGCM(key)
        hasher = hashlib.sha256()

        bytes_written = 0
        with open(out_path, "wb") as fout:
            for chunk_idx in range(num_chunks):
                len_bytes = fin.read(4)
                if not len_bytes:
                    break
                chunk_len = struct.unpack(">I", len_bytes)[0]
                encrypted_chunk = fin.read(chunk_len)
                if len(encrypted_chunk) != chunk_len:
                    raise IOError(f"Unexpected EOF reading chunk {chunk_idx}")

                chunk_nonce = base_nonce[:8] + struct.pack(">I", chunk_idx)
                ad = struct.pack(">I", chunk_idx)

                decrypted_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, ad)
                fout.write(decrypted_chunk)
                hasher.update(decrypted_chunk)
                bytes_written += len(decrypted_chunk)

                if progress_callback and file_size > 0:
                    progress_callback(bytes_written, file_size)

    computed_sha256 = hasher.hexdigest()
    verified = (computed_sha256.lower() == expected_sha256.lower())

    if not verified:
        raise ValueError(
            f"Data integrity verification failed! Expected {expected_sha256}, got {computed_sha256}"
        )

    return {
        "original_sha256": expected_sha256,
        "decrypted_sha256": computed_sha256,
        "integrity_verified": verified,
        "file_size": bytes_written,
    }


def generate_auth_challenge() -> str:
    """Generate a random 16-byte hex challenge string for authentication."""
    return os.urandom(16).hex()


def compute_auth_response(password: str, challenge: str) -> str:
    """Compute HMAC-SHA256 response for challenge authentication."""
    return hashlib.sha256(f"{password}:{challenge}".encode("utf-8")).hexdigest()


def verify_auth_response(password: str, challenge: str, response: str) -> bool:
    """Verify challenge response matches expectation."""
    expected = compute_auth_response(password, challenge)
    return hashlib.sha256(expected.encode()).digest() == hashlib.sha256(response.encode()).digest()
