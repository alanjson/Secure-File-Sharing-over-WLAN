"""
test_all.py
───────────
Automated validation script testing all components of Secure File Sharing over WLAN.
"""
import os
import sys
import time
import hashlib
import subprocess

def run_tests():
    print("=" * 65)
    print("RUNNING ALL MODULE VALIDATIONS — SECURE FILE SHARING OVER WLAN")
    print("Project Abstract by: ALAN JAISON")
    print("=" * 65)

    # 1. Cryptography Tests
    print("\n[1/4] Testing Cryptographic Primitives...")
    import crypto_utils

    # PBKDF2 Key Derivation
    key, salt = crypto_utils.derive_key("AlanJaisonSecret2026")
    assert len(key) == 32, f"Key length must be 32 bytes (256 bits), got {len(key)}"
    print("  [OK] PBKDF2-HMAC-SHA256 Key Derivation (256-bit key verified)")

    # AES-256-GCM
    plaintext = b"Confidential payload over local WLAN"
    nonce, ct = crypto_utils.encrypt_bytes(key, plaintext)
    decrypted = crypto_utils.decrypt_bytes(key, nonce, ct)
    assert decrypted == plaintext
    print("  [OK] AES-256-GCM Authenticated Encryption & Decryption")

    # Anti-Tampering Tag Verification
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF
    try:
        crypto_utils.decrypt_bytes(key, nonce, bytes(tampered_ct))
        assert False, "Tampered ciphertext should have raised InvalidTag"
    except crypto_utils.InvalidTag:
        print("  [OK] AES-256-GCM Tampering Detection (Authentication Tag Validated)")

    # SHA-256 Integrity Hashing
    hash_test = crypto_utils.compute_sha256_bytes(plaintext)
    expected_hash = hashlib.sha256(plaintext).hexdigest()
    assert hash_test == expected_hash
    print(f"  [OK] SHA-256 Integrity Hashing (Digest: {hash_test[:16]}...)")

    # Challenge-Response Authentication
    challenge = crypto_utils.generate_auth_challenge()
    valid_resp = crypto_utils.compute_auth_response("SecretKey123", challenge)
    assert crypto_utils.verify_auth_response("SecretKey123", challenge, valid_resp) is True
    assert crypto_utils.verify_auth_response("WrongKey", challenge, valid_resp) is False
    print("  [OK] Pre-transfer Challenge-Response Authentication Handshake")

    # 2. End-to-End File Encryption/Decryption
    print("\n[2/4] Testing File-Level Chunked Encryption & Integrity...")
    test_src = "scratch_test_file.bin"
    test_enc = "scratch_test_enc.bin"
    test_dec = "scratch_test_dec.bin"

    dummy_data = b"WLAN Secure Packet Data " * 4096  # ~96 KB (crosses 64 KB chunk boundary)
    with open(test_src, "wb") as f:
        f.write(dummy_data)

    enc_meta = crypto_utils.encrypt_file(key, salt, test_src, test_enc)
    dec_meta = crypto_utils.decrypt_file("AlanJaisonSecret2026", test_enc, test_dec)

    with open(test_dec, "rb") as f:
        restored_data = f.read()

    assert restored_data == dummy_data
    assert dec_meta["integrity_verified"] is True
    assert enc_meta["original_sha256"] == dec_meta["decrypted_sha256"]
    print("  [OK] Multi-chunk AES-256-GCM Streaming & Decryption")
    print(f"  [OK] SHA-256 Integrity Verified ({dec_meta['decrypted_sha256'][:24]}...)")

    for p in [test_src, test_enc, test_dec]:
        if os.path.exists(p):
            os.remove(p)

    # 3. Client-Server WLAN Network Transfer
    print("\n[3/4] Testing WLAN Client-Server Network Transfer...")
    from server import SecureWLANServer
    from client import SecureWLANClient

    save_folder = "test_network_received"
    os.makedirs(save_folder, exist_ok=True)

    transfer_src = "network_payload.dat"
    with open(transfer_src, "wb") as f:
        f.write(b"Live WLAN transfer test content " * 2000)

    # Start Receiver Server
    server = SecureWLANServer(
        host="127.0.0.1",
        port=19870,
        auth_key="AlanJaisonTestKey",
        save_dir=save_folder
    )
    server.start()
    time.sleep(0.5)

    # Start Sender Client & Transfer
    client = SecureWLANClient(
        receiver_ip="127.0.0.1",
        port=19870,
        auth_key="AlanJaisonTestKey",
        client_name="TestSender"
    )

    result = client.send_file(transfer_src)
    assert result["success"] is True
    assert result["integrity_verified"] is True
    assert result["original_sha256"] == result["receiver_sha256"]

    print(f"  [OK] Network Transfer Completed in {result['elapsed_seconds']:.2f}s ({result['speed_mbps']:.2f} MB/s)")
    print(f"  [OK] Sender SHA-256:   {result['original_sha256']}")
    print(f"  [OK] Receiver SHA-256: {result['receiver_sha256']}")
    print(f"  [OK] Delivery Confirmation Verified Match!")

    server.stop()
    time.sleep(0.3)

    if os.path.exists(transfer_src):
        os.remove(transfer_src)
    for f in os.listdir(save_folder):
        os.remove(os.path.join(save_folder, f))
    os.rmdir(save_folder)

    # 4. CLI Verification
    print("\n[4/4] Testing Command Line Interfaces...")
    out = subprocess.check_output([sys.executable, "main.py", "verify", "--file", "icon.ico"]).decode()
    assert "SHA-256 Hash:" in out
    print("  [OK] CLI verification command tested successfully")

    print("\n" + "=" * 65)
    print("ALL MODULES & PROTOCOLS TESTED AND FULLY OPERATIONAL!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()

