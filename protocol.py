"""
protocol.py
───────────
Communication Protocol and Frame Serialization for
Secure File Sharing over WLAN.
Author: ALAN JAISON
"""

import json
import struct
import socket
from typing import Dict, Any, Optional

BUFFER_SIZE = 64 * 1024  # 64 KB
HEADER_STRUCT = struct.Struct(">I")  # 4-byte message length prefix


def send_json_message(sock: socket.socket, payload: Dict[str, Any]):
    """Send a length-prefixed JSON message over a TCP socket."""
    encoded = json.dumps(payload).encode("utf-8")
    sock.sendall(HEADER_STRUCT.pack(len(encoded)) + encoded)


def recv_json_message(sock: socket.socket, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Receive a length-prefixed JSON message from a TCP socket."""
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        raw_len = recv_all(sock, HEADER_STRUCT.size)
        if not raw_len:
            return None
        msg_len = HEADER_STRUCT.unpack(raw_len)[0]
        data = recv_all(sock, msg_len)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))
    except socket.timeout:
        return None


def recv_all(sock: socket.socket, n_bytes: int) -> Optional[bytes]:
    """Helper to receive exactly n_bytes from socket."""
    data = bytearray()
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

