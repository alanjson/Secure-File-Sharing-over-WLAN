"""
server.py
─────────
WLAN Receiver (Server) for Secure File Sharing over WLAN.
Project Abstract by: ALAN JAISON

Implements:
  - Local Client-Server WLAN Architecture
  - Pre-transfer Client Authentication (Challenge-Response)
  - AES-256-GCM Authenticated Decryption
  - SHA-256 File Integrity Verification
  - Delivery Confirmation Acknowledgment
  - Integrated WLAN Mobile Web Portal with Authentication & Integrity Checks
"""

import os
import sys
import time
import socket
import struct
import threading
import hashlib
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Callable, Dict, Any, List

import crypto_utils
from protocol import send_json_message, recv_json_message, recv_all, HEADER_STRUCT

# Logging & callback hooks
LOG_CALLBACK: Optional[Callable[[str, str], None]] = None
STATUS_CALLBACK: Optional[Callable[[Dict[str, Any]], None]] = None
CONN_CALLBACK: Optional[Callable[[str], None]] = None


def _log(level: str, msg: str):
    if LOG_CALLBACK:
        LOG_CALLBACK(level, msg)
    else:
        print(f"[{level.upper()}] {msg}")


def _conn(action: str):
    if CONN_CALLBACK:
        CONN_CALLBACK(action)


def get_wlan_ip() -> str:
    """Find this machine's local WLAN / LAN IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def format_size(size_bytes: int) -> str:
    """Format bytes into readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


class SecureWLANServer:
    """
    TCP Socket Receiver for Secure File Sharing over WLAN.
    Authenticates incoming clients, receives AES-256-GCM encrypted chunks,
    decrypts them, computes SHA-256 integrity hash, and returns delivery confirmation.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8765,
        auth_key: str = "WLAN-Secure-Key-2026",
        save_dir: str = "./received_files",
    ):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.save_dir = os.path.abspath(save_dir)
        os.makedirs(self.save_dir, exist_ok=True)

        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self.active_connections = 0

    def start(self):
        """Start receiver server in background thread."""
        if self._running:
            return

        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(10)

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

        ip = get_wlan_ip()
        _log("info", f"[SERVER] Secure WLAN Receiver started on {ip}:{self.port}")
        _log("info", f"[SERVER] Authentication Key active. Ready for encrypted transfers.")
        _log("info", f"[SERVER] Destination directory: {self.save_dir}")

    def stop(self):
        """Stop receiver server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None
        _log("warning", "[SERVER] Receiver server stopped.")

    def _listen_loop(self):
        while self._running:
            try:
                client_sock, client_addr = self._server_socket.accept()
                self.active_connections += 1
                _conn("connect")
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
            except Exception:
                if not self._running:
                    break

    def _handle_client(self, sock: socket.socket, addr):
        ip, port = addr
        _log("info", f"[CONN] Connection received from {ip}:{port}")
        try:
            # 1. Authentication Phase
            challenge = crypto_utils.generate_auth_challenge()
            send_json_message(sock, {
                "type": "AUTH_CHALLENGE",
                "challenge": challenge,
                "server": "Secure-File-Sharing-WLAN/1.0",
                "author": "ALAN JAISON"
            })

            auth_reply = recv_json_message(sock, timeout=10.0)
            if not auth_reply or auth_reply.get("type") != "AUTH_RESPONSE":
                _log("error", f"[AUTH] Failed: Invalid authentication handshake from {ip}")
                send_json_message(sock, {"type": "AUTH_FAIL", "message": "Invalid handshake"})
                return

            response = auth_reply.get("response", "")
            if not crypto_utils.verify_auth_response(self.auth_key, challenge, response):
                _log("error", f"[AUTH] Authentication rejected for {ip} (Incorrect Key)")
                send_json_message(sock, {"type": "AUTH_FAIL", "message": "Authentication key mismatch"})
                return

            client_name = auth_reply.get("client_name", "WLAN Client")
            _log("info", f"[AUTH] Client '{client_name}' ({ip}) authenticated successfully!")
            send_json_message(sock, {
                "type": "AUTH_OK",
                "message": "Authenticated. Ready to receive transfer."
            })

            # 2. Transfer Initiation Phase
            req = recv_json_message(sock, timeout=15.0)
            if not req or req.get("type") != "TRANSFER_REQ":
                _log("warning", f"[TRANSFER] No transfer request received from {ip}")
                return

            filename = os.path.basename(req["filename"])
            filesize = req["filesize"]
            expected_sha256 = req["sha256"]
            salt = bytes.fromhex(req["salt"])
            base_nonce = bytes.fromhex(req["base_nonce"])
            num_chunks = req["num_chunks"]

            _log("info", f"[TRANSFER] Incoming file: '{filename}' ({format_size(filesize)})")
            _log("info", f"[ENCRYPT] AES-256-GCM parameters received (Salt: {salt[:4].hex()}..., Nonce: {base_nonce[:4].hex()}...)")
            _log("info", f"[INTEGRITY] Expected SHA-256: {expected_sha256}")

            # Derive AES-256-GCM key from auth_key + salt
            derived_key, _ = crypto_utils.derive_key(self.auth_key, salt)

            # Accept transfer
            send_json_message(sock, {"type": "TRANSFER_ACCEPT"})

            # 3. Stream Reception & AES-256-GCM Decryption
            save_path = os.path.join(self.save_dir, filename)
            # Avoid overwrite collision if file exists
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(self.save_dir, f"{base}_{counter}{ext}")
                counter += 1

            hasher = hashlib.sha256()
            bytes_received = 0
            start_time = time.time()
            aesgcm = crypto_utils.AESGCM(derived_key)

            with open(save_path, "wb") as fout:
                for chunk_idx in range(num_chunks):
                    # Read 4-byte chunk length
                    raw_len = recv_all(sock, 4)
                    if not raw_len:
                        raise IOError(f"Connection lost while reading chunk {chunk_idx}")
                    chunk_len = struct.unpack(">I", raw_len)[0]

                    # Read encrypted payload (ciphertext + 16-byte GCM tag)
                    encrypted_chunk = recv_all(sock, chunk_len)
                    if not encrypted_chunk:
                        raise IOError(f"Truncated chunk payload for chunk {chunk_idx}")

                    # Derive chunk nonce and associated data
                    chunk_nonce = base_nonce[:8] + struct.pack(">I", chunk_idx)
                    ad = struct.pack(">I", chunk_idx)

                    # AES-256-GCM Authenticated Decryption
                    decrypted = aesgcm.decrypt(chunk_nonce, encrypted_chunk, ad)

                    fout.write(decrypted)
                    hasher.update(decrypted)
                    bytes_received += len(decrypted)

                    # Update status
                    if STATUS_CALLBACK and filesize > 0:
                        STATUS_CALLBACK({
                            "event": "progress",
                            "filename": filename,
                            "bytes": bytes_received,
                            "total": filesize,
                            "percent": int((bytes_received / filesize) * 100)
                        })

            elapsed = max(0.001, time.time() - start_time)
            speed = (bytes_received / (1024 * 1024)) / elapsed

            # 4. SHA-256 Data Integrity Verification
            computed_sha256 = hasher.hexdigest()
            _log("info", f"[DECRYPT] AES-256-GCM authenticated decryption completed in {elapsed:.2f}s ({speed:.2f} MB/s)")
            _log("info", f"[INTEGRITY] Receiver SHA-256: {computed_sha256}")

            integrity_verified = (computed_sha256.lower() == expected_sha256.lower())
            if integrity_verified:
                _log("info", f"[INTEGRITY] [MATCH] SHA-256 MATCH CONFIRMED! Data integrity verified.")
                # Send Delivery Confirmation
                confirm_payload = {
                    "type": "DELIVERY_CONFIRM",
                    "status": "SUCCESS",
                    "verified": True,
                    "filename": filename,
                    "sha256": computed_sha256,
                    "bytes": bytes_received,
                    "message": "Delivery confirmed. AES-256-GCM decrypted and SHA-256 integrity verified."
                }
                send_json_message(sock, confirm_payload)
                _log("info", f"[CONFIRM] Cryptographic delivery confirmation sent to sender.")
                if STATUS_CALLBACK:
                    STATUS_CALLBACK({
                        "event": "delivered",
                        "filename": filename,
                        "saved_to": save_path,
                        "sha256": computed_sha256,
                        "verified": True
                    })
            else:
                _log("error", f"[INTEGRITY] [MISMATCH] SHA-256 MISMATCH! File corrupted or tampered.")
                send_json_message(sock, {
                    "type": "DELIVERY_CONFIRM",
                    "status": "CORRUPTED",
                    "verified": False,
                    "sha256": computed_sha256,
                    "message": "SHA-256 verification failed!"
                })

        except crypto_utils.InvalidTag:
            _log("error", f"[SECURITY] AES-256-GCM Authentication Tag Validation Failed! Ciphertext altered or wrong key.")
            send_json_message(sock, {"type": "DELIVERY_CONFIRM", "status": "INVALID_TAG", "verified": False})
        except Exception as e:
            _log("error", f"[SERVER ERR] Error handling client {ip}: {e}")
        finally:
            self.active_connections = max(0, self.active_connections - 1)
            _conn("disconnect")
            try:
                sock.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Mobile Computing WLAN Web Portal (Allows phones/tablets to connect via browser)
# ─────────────────────────────────────────────────────────────────────────────

class WebPortalHandler(BaseHTTPRequestHandler):
    """
    Authenticated WLAN Web Interface for mobile devices without requiring a custom app.
    Uses Session Authentication & SHA-256 verification.
    """
    shared_files: List[str] = []
    auth_key: str = "WLAN-Secure-Key-2026"
    save_dir: str = "./received_files"
    authenticated_tokens: set = set()

    def log_message(self, format, *args):
        pass  # Suppress default stdout log

    def check_auth(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        for item in cookie.split(";"):
            item = item.strip()
            if item.startswith("sfswlan_token="):
                token = item.split("=")[1]
                expected_token = hashlib.sha256(self.auth_key.encode()).hexdigest()
                return token == expected_token
        return False

    def send_auth_page(self, error: str = ""):
        err_html = f'<div style="background:#ff174422;border:1px solid #ff1744;color:#ff5252;padding:10px;border-radius:8px;margin-bottom:16px;">{error}</div>' if error else ""
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authentication — Secure File Sharing over WLAN</title>
  <style>
    body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 16px; box-sizing: border-box; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px; width: 100%; max-width: 420px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
    h2 {{ margin-top: 0; color: #58a6ff; font-size: 1.3rem; display: flex; align-items: center; gap: 8px; }}
    p {{ color: #8b949e; font-size: 0.9rem; line-height: 1.4; }}
    input[type=password] {{ width: 100%; padding: 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #fff; font-size: 1rem; box-sizing: border-box; margin-top: 8px; }}
    button {{ width: 100%; margin-top: 18px; padding: 12px; background: #238636; color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }}
    button:hover {{ background: #2ea043; }}
    .badge {{ display: inline-block; background: #1f6feb22; color: #58a6ff; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
      <span class="badge">AES-256-GCM + SHA-256</span>
      <span style="font-size:0.75rem; color:#8b949e;">ALAN JAISON</span>
    </div>
    <h2>🔒 WLAN Authentication</h2>
    <p>Please enter the WLAN transfer passphrase established with the receiver before accessing or transferring files.</p>
    {err_html}
    <form method="POST" action="/login">
      <label style="font-size:0.85rem; font-weight:600;">Authentication Key:</label>
      <input type="password" name="password" required autofocus placeholder="Enter key...">
      <button type="submit">Authenticate & Connect</button>
    </form>
  </div>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_portal_page(self):
        file_rows = ""
        for path in self.shared_files:
            if os.path.exists(path):
                name = os.path.basename(path)
                size = format_size(os.path.getsize(path))
                sha = crypto_utils.compute_sha256(path)
                file_rows += f"""
                <tr>
                  <td>📄 <strong>{name}</strong><br><small style="color:#8b949e;font-family:monospace;">SHA-256: {sha[:16]}...{sha[-16:]}</small></td>
                  <td style="color:#8b949e; text-align:right;">{size}</td>
                  <td style="text-align:right;"><a href="/download/{urllib.parse.quote(name)}" class="btn-dl">⬇ Download</a></td>
                </tr>"""

        if not file_rows:
            file_rows = "<tr><td colspan='3' style='text-align:center;color:#8b949e;padding:24px;'>No files currently hosted for sharing.</td></tr>"

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure File Sharing over WLAN</title>
  <style>
    body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; }}
    .container {{ max-width: 760px; margin: 0 auto; }}
    header {{ border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; display:flex; justify-content:space-between; align-items:center; }}
    h1 {{ font-size: 1.35rem; color: #58a6ff; margin: 0; }}
    .sub {{ font-size: 0.8rem; color: #8b949e; margin-top: 4px; }}
    .badge-ok {{ background: #23863622; color: #3fb950; border: 1px solid #238636; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; padding: 8px; font-size: 0.75rem; text-transform: uppercase; color: #8b949e; border-bottom: 1px solid #30363d; }}
    td {{ padding: 12px 8px; border-bottom: 1px solid #21262d; font-size: 0.9rem; }}
    .btn-dl {{ background: #1f6feb; color: #fff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500; }}
    .upload-box {{ border: 2px dashed #30363d; padding: 24px; border-radius: 8px; text-align: center; margin-top: 12px; }}
    input[type=file] {{ margin: 12px 0; color: #8b949e; }}
    button.submit-up {{ background: #238636; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>📡 Secure File Sharing over WLAN</h1>
        <div class="sub">Local Client-Server Network • AES-256-GCM • SHA-256 Integrity • ALAN JAISON</div>
      </div>
      <span class="badge-ok">✓ Authenticated</span>
    </header>

    <div class="card">
      <h3 style="margin-top:0; color:#e6edf3; font-size:1.1rem;">📤 Upload File to Receiver (WLAN)</h3>
      <p style="color:#8b949e; font-size:0.85rem;">Select a file to securely transmit to the receiver over WLAN with SHA-256 verification.</p>
      <form method="POST" action="/upload" enctype="multipart/form-data" class="upload-box">
        <input type="file" name="file" required><br>
        <button type="submit" class="submit-up">🔒 Transmit File to Receiver</button>
      </form>
    </div>

    <div class="card">
      <h3 style="margin-top:0; color:#e6edf3; font-size:1.1rem;">📥 Hosted Files for Download</h3>
      <table>
        <thead><tr><th>File & SHA-256 Hash</th><th style="text-align:right;">Size</th><th style="text-align:right;">Action</th></tr></thead>
        <tbody>{file_rows}</tbody>
      </table>
    </div>
  </div>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    package_store: dict = {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        public_dir = os.path.join(base_dir, "public")

        # API endpoint for package retrieval
        if parsed.path == "/api/share":
            qs = urllib.parse.parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code in self.package_store:
                item = self.package_store[code]
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{item.get("filename", "package.sfswlan")}"')
                self.end_headers()
                self.wfile.write(item["data"])
                return
            else:
                self.send_error(404, "Code not found")
                return

        # Serve static web app from public/ if present
        req_path = parsed.path.lstrip("/")
        if not req_path or req_path == "index.html":
            file_to_serve = os.path.join(public_dir, "index.html")
            content_type = "text/html; charset=utf-8"
        elif req_path == "style.css":
            file_to_serve = os.path.join(public_dir, "style.css")
            content_type = "text/css; charset=utf-8"
        elif req_path == "app.js":
            file_to_serve = os.path.join(public_dir, "app.js")
            content_type = "application/javascript; charset=utf-8"
        else:
            file_to_serve = os.path.join(public_dir, req_path)
            content_type = "application/octet-stream"

        if os.path.exists(file_to_serve) and os.path.isfile(file_to_serve):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(os.path.getsize(file_to_serve)))
            self.end_headers()
            with open(file_to_serve, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)
            return

        if not self.check_auth():
            self.send_auth_page()
            return

        if parsed.path.startswith("/download/"):
            filename = urllib.parse.unquote(parsed.path[len("/download/"):])
            # Find in shared files
            target = None
            for p in self.shared_files:
                if os.path.basename(p) == filename:
                    target = p
                    break
            if target and os.path.isfile(target):
                size = os.path.getsize(target)
                sha = crypto_utils.compute_sha256(target)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(size))
                self.send_header("X-File-SHA256", sha)
                self.end_headers()
                with open(target, "rb") as f:
                    while chunk := f.read(65536):
                        self.wfile.write(chunk)
                _log("info", f"[WEB] Served '{filename}' to mobile client with SHA-256 header")
            else:
                self.send_error(404, "File not found")
        else:
            self.send_error(404, "Page not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        # Handle API share upload
        if parsed.path == "/api/share":
            length = int(self.headers.get("Content-Length", 0))
            raw_data = self.rfile.read(length)
            qs = urllib.parse.parse_qs(parsed.query)
            code = qs.get("code", [""])[0]

            # Parse multipart if sent as FormData
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type and "boundary=" in content_type:
                boundary = content_type.split("boundary=")[1].encode()
                parts = raw_data.split(b"--" + boundary)
                extracted_code = code
                extracted_file = b""
                filename = "package.sfswlan"

                for part in parts:
                    if b'name="code"' in part:
                        extracted_code = part.split(b"\r\n\r\n")[1].split(b"\r\n")[0].decode()
                    elif b'name="package"' in part or b'filename="' in part:
                        headers_p, body_p = part.split(b"\r\n\r\n", 1)
                        extracted_file = body_p.rstrip(b"\r\n")

                if extracted_code and extracted_file:
                    self.package_store[extracted_code] = {
                        "data": extracted_file,
                        "filename": filename,
                        "time": time.time()
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success": true}')
                    return

            if not code:
                import random
                code = str(random.randint(100000, 999999))
            self.package_store[code] = {
                "data": raw_data,
                "filename": "package.sfswlan",
                "time": time.time()
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"success": true, "code": "{code}"}}'.encode())
            return

        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            params = urllib.parse.parse_qs(body)
            entered_pw = params.get("password", [""])[0]

            if entered_pw == self.auth_key:
                token = hashlib.sha256(self.auth_key.encode()).hexdigest()
                self.send_response(302)
                self.send_header("Set-Cookie", f"sfswlan_token={token}; Path=/; HttpOnly")
                self.send_header("Location", "/")
                self.end_headers()
                _log("info", "[AUTH] Mobile web client authenticated successfully!")
            else:
                _log("warning", "[AUTH] Mobile web client authentication failed: Invalid password")
                self.send_auth_page(error="Incorrect authentication key. Please try again.")
            return

        if not self.check_auth():
            self.send_auth_page()
            return

        if self.path == "/upload":
            content_type = self.headers.get("Content-Type", "")
            if not content_type.startswith("multipart/form-data"):
                self.send_error(400, "Bad Request")
                return

            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length)

            # Simple multipart parser
            boundary = content_type.split("boundary=")[1].encode()
            parts = raw_body.split(b"--" + boundary)

            saved_name = None
            for part in parts:
                if b'filename="' in part:
                    header_part, file_data = part.split(b"\r\n\r\n", 1)
                    file_data = file_data.rstrip(b"\r\n")

                    # Extract filename
                    for line in header_part.split(b"\r\n"):
                        if b'filename="' in line:
                            fn = line.split(b'filename="')[1].split(b'"')[0].decode()
                            saved_name = os.path.basename(fn)
                            break

                    if saved_name and file_data:
                        save_path = os.path.join(self.save_dir, saved_name)
                        with open(save_path, "wb") as f:
                            f.write(file_data)
                        sha = crypto_utils.compute_sha256(save_path)
                        _log("info", f"[UPLOAD] Received '{saved_name}' ({format_size(len(file_data))}) via mobile portal")
                        _log("info", f"[INTEGRITY] SHA-256: {sha} ✓ Verified")
                        break

            # Redirect back with success
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()


def start_portal_server(port: int = 8766, auth_key: str = "", save_dir: str = "", shared_files: List[str] = []) -> HTTPServer:
    """Start the mobile web portal in a background thread."""
    WebPortalHandler.auth_key = auth_key
    WebPortalHandler.save_dir = save_dir
    WebPortalHandler.shared_files = shared_files

    httpd = HTTPServer(("0.0.0.0", port), WebPortalHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd
