"""
main.py
───────
Secure File Sharing over WLAN
Project Abstract by: ALAN JAISON

Entry point for GUI & Command Line Interface.
Supports:
  - GUI Mode (Default: python main.py or python gui.py)
  - Receiver Mode CLI (python main.py receive ...)
  - Sender Mode CLI (python main.py send ...)
  - SHA-256 Integrity Hash Verification CLI (python main.py verify ...)
"""

import sys
import os
import argparse
import time

import crypto_utils
from server import SecureWLANServer, get_wlan_ip, format_size
from client import SecureWLANClient

# Backward-compatible hook variables
LOG_CALLBACK = None
CONNECTION_CALLBACK = None


def get_local_ip() -> str:
    """Compatibility wrapper for get_wlan_ip()."""
    return get_wlan_ip()


def run_gui():
    """Launch Graphical User Interface."""
    from gui import SecureFileSharingApp
    app = SecureFileSharingApp()
    app.run()


def cli_receive(args):
    """Run receiver server from command line."""
    ip = get_wlan_ip()
    print("=" * 60)
    print("SECURE FILE SHARING OVER WLAN — RECEIVER MODE")
    print("Author: ALAN JAISON")
    print(f"Local WLAN IP: {ip}")
    print(f"Listening Port: {args.port}")
    print(f"Authentication Key: {args.key}")
    print(f"Save Directory: {os.path.abspath(args.save)}")
    print("Security: AES-256-GCM Decryption + SHA-256 Integrity Verification")
    print("=" * 60)

    srv = SecureWLANServer(
        host="0.0.0.0",
        port=args.port,
        auth_key=args.key,
        save_dir=args.save
    )
    srv.start()
    print("\n[INFO] Receiver is running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping receiver server...")
        srv.stop()
        print("[INFO] Receiver server stopped cleanly.")


def cli_send(args):
    """Send files from command line."""
    print("=" * 60)
    print("SECURE FILE SHARING OVER WLAN — SENDER MODE")
    print("Author: ALAN JAISON")
    print(f"Target Receiver: {args.host}:{args.port}")
    print(f"File to transmit: {args.file}")
    print("Security: AES-256-GCM Encryption + SHA-256 Integrity Verification")
    print("=" * 60)

    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    c = SecureWLANClient(
        receiver_ip=args.host,
        port=args.port,
        auth_key=args.key,
        client_name=args.name
    )

    def progress(p):
        sys.stdout.write(f"\r[TRANSFER] {p['percent']}% ({p['speed_mbps']:.2f} MB/s) chunk {p['chunk']}/{p['total_chunks']}")
        sys.stdout.flush()

    res = c.send_file(args.file, progress_callback=progress)
    print("\n" + "=" * 60)
    if res["success"]:
        print("[CONFIRM] DELIVERY CONFIRMED!")
        print(f"  File: {res['filename']} ({format_size(res['filesize'])})")
        print(f"  Sender SHA-256:   {res['original_sha256']}")
        print(f"  Receiver SHA-256: {res['receiver_sha256']}")
        print(f"  Integrity Verified: {res['integrity_verified']}")
        print(f"  Time Elapsed: {res['elapsed_seconds']:.2f}s ({res['speed_mbps']:.2f} MB/s)")
    else:
        print(f"[FAIL] Delivery confirmation failed: {res['message']}")
    print("=" * 60)


def cli_verify(args):
    """Compute and verify SHA-256 integrity hash."""
    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    computed = crypto_utils.compute_sha256(args.file)
    print("=" * 60)
    print(f"File: {args.file}")
    print(f"SHA-256 Hash: {computed}")

    if args.hash:
        match = (computed.lower() == args.hash.lower())
        print(f"Expected:     {args.hash}")
        print(f"Integrity Match: {'[OK] VERIFIED' if match else '[FAIL] MISMATCH'}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Secure File Sharing over WLAN — Project by ALAN JAISON",
        epilog="Run without arguments to launch the Graphical User Interface."
    )
    subparsers = parser.add_subparsers(dest="command")

    # GUI subparser
    subparsers.add_parser("gui", help="Launch Graphical User Interface (default)")

    # Receive subparser
    p_rx = subparsers.add_parser("receive", help="Run in Receiver (Server) mode")
    p_rx.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    p_rx.add_argument("--key", type=str, default="AlanJaisonWLAN2026", help="Authentication & Encryption key")
    p_rx.add_argument("--save", type=str, default="./received_files", help="Folder to store received files")

    # Send subparser
    p_tx = subparsers.add_parser("send", help="Run in Sender (Client) mode")
    p_tx.add_argument("--host", type=str, required=True, help="Receiver IP address on WLAN")
    p_tx.add_argument("--port", type=int, default=8765, help="Receiver port (default: 8765)")
    p_tx.add_argument("--key", type=str, default="AlanJaisonWLAN2026", help="Authentication & Encryption key")
    p_tx.add_argument("--file", type=str, required=True, help="Path to file to transmit")
    p_tx.add_argument("--name", type=str, default="CLI Sender", help="Client sender name")

    # Verify subparser
    p_vf = subparsers.add_parser("verify", help="Verify SHA-256 integrity of a file")
    p_vf.add_argument("--file", type=str, required=True, help="Path to file")
    p_vf.add_argument("--hash", type=str, default=None, help="Expected SHA-256 hash to compare against")

    args = parser.parse_args()

    if args.command == "receive":
        cli_receive(args)
    elif args.command == "send":
        cli_send(args)
    elif args.command == "verify":
        cli_verify(args)
    else:
        # Default: Launch GUI
        run_gui()


if __name__ == "__main__":
    main()
