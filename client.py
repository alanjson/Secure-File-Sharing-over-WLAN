"""
client.py
─────────
WLAN Sender (Client) for Secure File Sharing over WLAN.
Project Abstract by: ALAN JAISON

Implements:
  - Local WLAN Connection to Receiver
  - Challenge-Response Authentication
  - File Selection & Pre-transfer SHA-256 Hash Computation
  - AES-256-GCM Authenticated Encryption & Chunked Streaming
  - Real-Time Transfer Monitoring (Progress, Speed, Bytes)
  - Cryptographic Delivery Confirmation Reception
"""

import os
import time
import socket
import struct
from typing import Optional, Callable, Dict, Any, List

import crypto_utils
from protocol import send_json_message, recv_json_message, recv_all

CHUNK_SIZE = 64 * 1024  # 64 KB


def format_size(size_bytes: int) -> str:
    """Format bytes into readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


class SecureWLANClient:
    """
    Client for transmitting files securely over WLAN.
    Authenticates, encrypts files with AES-256-GCM, and verifies delivery confirmation.
    """

    def __init__(
        self,
        receiver_ip: str,
        port: int = 8765,
        auth_key: str = "",
        client_name: str = "WLAN Sender",
    ):
        self.receiver_ip = receiver_ip
        self.port = port
        self.auth_key = auth_key
        self.client_name = client_name

    def send_file(
        self,
        filepath: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Authenticate, encrypt with AES-256-GCM, and transmit file to receiver over WLAN.
        """
        def _log(level: str, msg: str):
            if log_callback:
                log_callback(level, msg)
            else:
                print(f"[{level.upper()}] {msg}")

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Selected file not found: {filepath}")

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        _log("info", f"[CLIENT] Connecting to receiver at {self.receiver_ip}:{self.port}...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15.0)

        try:
            sock.connect((self.receiver_ip, self.port))
            _log("info", f"[CLIENT] Connected to receiver. Initiating authentication...")

            # 1. Authentication Handshake
            challenge_msg = recv_json_message(sock, timeout=10.0)
            if not challenge_msg or challenge_msg.get("type") != "AUTH_CHALLENGE":
                raise ConnectionError("Invalid or missing authentication challenge from receiver")

            challenge = challenge_msg["challenge"]
            auth_response = crypto_utils.compute_auth_response(self.auth_key, challenge)

            send_json_message(sock, {
                "type": "AUTH_RESPONSE",
                "response": auth_response,
                "client_name": self.client_name,
            })

            auth_result = recv_json_message(sock, timeout=10.0)
            if not auth_result or auth_result.get("type") != "AUTH_OK":
                error_msg = auth_result.get("message", "Authentication rejected by receiver") if auth_result else "Authentication timeout"
                _log("error", f"[AUTH] {error_msg}")
                raise PermissionError(f"Authentication failed: {error_msg}")

            _log("info", f"[AUTH] [OK] Authenticated with receiver successfully!")

            # 2. SHA-256 Hash Computation
            _log("info", f"[INTEGRITY] Computing SHA-256 hash for '{filename}' ({format_size(filesize)})...")
            orig_sha256 = crypto_utils.compute_sha256(filepath)
            _log("info", f"[INTEGRITY] Original SHA-256: {orig_sha256}")

            # 3. Cryptographic Key Derivation (PBKDF2-HMAC-SHA256) & AES-256-GCM Init
            salt = os.urandom(crypto_utils.SALT_SIZE)
            base_nonce = os.urandom(crypto_utils.NONCE_SIZE)
            derived_key, _ = crypto_utils.derive_key(self.auth_key, salt)
            aesgcm = crypto_utils.AESGCM(derived_key)

            num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 1

            _log("info", f"[ENCRYPT] Initialized AES-256-GCM (256-bit key, {num_chunks} chunks)")

            # 4. Transfer Request
            send_json_message(sock, {
                "type": "TRANSFER_REQ",
                "filename": filename,
                "filesize": filesize,
                "sha256": orig_sha256,
                "salt": salt.hex(),
                "base_nonce": base_nonce.hex(),
                "num_chunks": num_chunks,
            })

            accept_msg = recv_json_message(sock, timeout=15.0)
            if not accept_msg or accept_msg.get("type") != "TRANSFER_ACCEPT":
                raise ConnectionError("Receiver declined transfer request")

            _log("info", f"[TRANSFER] Receiver accepted. Transmitting encrypted stream over WLAN...")

            # 5. Encrypted Streaming Transmission
            bytes_sent = 0
            start_time = time.time()

            with open(filepath, "rb") as fin:
                chunk_idx = 0
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk and chunk_idx > 0:
                        break
                    if not chunk and chunk_idx == 0:
                        chunk = b""

                    # AES-256-GCM Chunk Encryption
                    chunk_nonce = base_nonce[:8] + struct.pack(">I", chunk_idx)
                    ad = struct.pack(">I", chunk_idx)
                    encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, ad)

                    # Send 4-byte length prefix + encrypted data
                    sock.sendall(struct.pack(">I", len(encrypted_chunk)) + encrypted_chunk)

                    bytes_sent += len(chunk)
                    chunk_idx += 1

                    elapsed = max(0.001, time.time() - start_time)
                    speed_mbps = (bytes_sent / (1024 * 1024)) / elapsed

                    if progress_callback:
                        progress_callback({
                            "filename": filename,
                            "bytes_sent": bytes_sent,
                            "total_bytes": filesize,
                            "percent": int((bytes_sent / filesize) * 100) if filesize > 0 else 100,
                            "speed_mbps": speed_mbps,
                            "chunk": chunk_idx,
                            "total_chunks": num_chunks,
                        })

                    if not chunk:
                        break

            total_elapsed = max(0.001, time.time() - start_time)
            avg_speed = (filesize / (1024 * 1024)) / total_elapsed
            _log("info", f"[TRANSFER] Transmission finished in {total_elapsed:.2f}s (Average: {avg_speed:.2f} MB/s)")
            _log("info", f"[CONFIRM] Waiting for receiver delivery confirmation & SHA-256 verification...")

            # 6. Delivery Confirmation Reception
            confirm_msg = recv_json_message(sock, timeout=30.0)
            if not confirm_msg or confirm_msg.get("type") != "DELIVERY_CONFIRM":
                raise ConnectionError("No delivery confirmation received from receiver")

            status = confirm_msg.get("status")
            verified = confirm_msg.get("verified", False)
            rx_sha256 = confirm_msg.get("sha256", "")

            if status == "SUCCESS" and verified:
                _log("info", f"[CONFIRM] [OK] DELIVERY CONFIRMED! Receiver verified SHA-256 match.")
                return {
                    "success": True,
                    "filename": filename,
                    "original_sha256": orig_sha256,
                    "receiver_sha256": rx_sha256,
                    "integrity_verified": True,
                    "filesize": filesize,
                    "elapsed_seconds": total_elapsed,
                    "speed_mbps": avg_speed,
                    "message": "File transmitted securely, decrypted via AES-256-GCM, and verified with SHA-256 integrity!"
                }
            else:
                _log("error", f"[CONFIRM] [FAIL] Delivery confirmation failed: {confirm_msg.get('message', 'Integrity check mismatch')}")
                return {
                    "success": False,
                    "filename": filename,
                    "original_sha256": orig_sha256,
                    "receiver_sha256": rx_sha256,
                    "integrity_verified": False,
                    "filesize": filesize,
                    "elapsed_seconds": total_elapsed,
                    "speed_mbps": avg_speed,
                    "message": confirm_msg.get("message", "Integrity mismatch or decryption error")
                }

        finally:
            try:
                sock.close()
            except Exception:
                pass
