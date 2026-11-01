"""
test_e2e_browser.py
───────────────────
End-to-End Automated Browser Test with Playwright:
Simulates a real Sender on Device A and a real Receiver on Device B.
Verifies AES-256-GCM encryption, QR/Direct Link generation, decryption,
and SHA-256 integrity match. Takes screenshots of both devices.
"""

import os
import time
import hashlib
from playwright.sync_api import sync_playwright

from server import start_portal_server

def run_e2e_test():
    print("=" * 65)
    print("STARTING END-TO-END SENDER & RECEIVER BROWSER VALIDATION")
    print("Author: ALAN JAISON")
    print("=" * 65)

    # 1. Start local server
    port = 18990
    server_inst = start_portal_server(port=port, auth_key="AlanJaisonWLAN2026", save_dir=".")
    time.sleep(1)
    base_url = f"http://127.0.0.1:{port}"
    print(f"[OK] Web server running on {base_url}")

    # 2. Create sample test file
    test_filename = "Confidential_Report_AlanJaison.txt"
    test_content = (
        "SECURE FILE SHARING OVER WLAN\n"
        "Project Abstract by ALAN JAISON\n"
        "Encrypted with AES-256-GCM and verified with SHA-256.\n"
        + ("A" * 1024 * 16) + "\nEnd of Secure Document."
    ).encode("utf-8")

    with open(test_filename, "wb") as f:
        f.write(test_content)

    expected_sha256 = hashlib.sha256(test_content).hexdigest()
    print(f"[OK] Test file created: '{test_filename}' ({len(test_content)} bytes)")
    print(f"[OK] Original SHA-256: {expected_sha256}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # ─────────────────────────────────────────────────────────────
        # SENDER (DEVICE A)
        # ─────────────────────────────────────────────────────────────
        print("\n--- [STEP 1: SENDER (DEVICE A)] ---")
        sender_context = browser.new_context(viewport={"width": 1280, "height": 800})
        sender_page = sender_context.new_page()

        print(f"Loading {base_url}...")
        sender_page.goto(base_url)
        # Wait for page JS to initialize
        sender_page.wait_for_load_state("networkidle")
        sender_page.wait_for_selector("#sendDropzone", state="visible")
        time.sleep(0.5)

        # Select file directly (hidden input works with set_input_files without visibility check)
        print("Selecting file on sender...")
        sender_page.set_input_files("#fileInput", test_filename)
        # Wait for hash preview to appear (file has been selected)
        sender_page.wait_for_selector("#hashPreviewBox", state="visible", timeout=5000)
        time.sleep(1.5)  # Allow SHA-256 computation to complete

        computed_preview = sender_page.text_content("#originalShaPreview").strip()
        print(f"Sender computed SHA-256: {computed_preview}")
        # SHA-256 might still be computing (shows "Calculating..." for large files) - wait for hex
        retries = 0
        while ("Calculating" in computed_preview or "Computing" in computed_preview) and retries < 10:
            time.sleep(0.5)
            computed_preview = sender_page.text_content("#originalShaPreview").strip()
            retries += 1
        print(f"Sender final SHA-256: {computed_preview}")
        assert computed_preview.lower() == expected_sha256.lower(), f"SHA-256 preview mismatch! Got: {computed_preview}"

        # Fill passphrase
        passphrase = "AlanJaisonSecretPass2026"
        sender_page.fill("#sendPassphrase", passphrase)

        # Click Encrypt & Transmit
        print("Encrypting with AES-256-GCM and preparing transfer package...")
        sender_page.click("#btnEncryptAndSend")

        # Wait for delivery confirmed result card
        sender_page.wait_for_selector("#sendResultCard", state="visible", timeout=10000)
        time.sleep(1)

        # Get generated Direct Share URL
        direct_url = sender_page.input_value("#shareUrlInput")
        print(f"[PASS] Direct Share Link generated successfully!")
        print(f"       Link: {direct_url[:80]}...")

        # Screenshot Sender Screen
        os.makedirs("images", exist_ok=True)
        sender_page.screenshot(path="images/sender_working_demo.png")
        print("[PASS] Sender screen captured -> images/sender_working_demo.png")

        # Also download encrypted .sfswlan package
        with sender_page.expect_download() as download_info:
            sender_page.click("#btnDownloadEncPackage")
        download = download_info.value
        enc_pkg_path = "downloaded_package.sfswlan"
        download.save_as(enc_pkg_path)
        print(f"[PASS] Encrypted .sfswlan package downloaded ({os.path.getsize(enc_pkg_path)} bytes)")

        # ─────────────────────────────────────────────────────────────
        # RECEIVER (DEVICE B - SIMULATING MOBILE PHONE / ANOTHER PC)
        # ─────────────────────────────────────────────────────────────
        print("\n--- [STEP 2: RECEIVER (DEVICE B)] ---")
        # Separate, completely isolated browser context (simulates a mobile device)
        receiver_context = browser.new_context(viewport={"width": 430, "height": 932}) # iPhone viewport
        receiver_page = receiver_context.new_page()

        print(f"Receiver opening Direct Link on phone...")
        receiver_page.goto(direct_url)
        receiver_page.wait_for_load_state("networkidle")
        receiver_page.wait_for_selector("#btnDecrypt", state="visible", timeout=10000)
        time.sleep(1.5)

        # Verify package auto-loaded from URL fragment
        badge_text = receiver_page.text_content("#encSelectedName")
        print(f"Receiver status: {badge_text}")
        assert "Encrypted Package Loaded" in badge_text, f"Unexpected badge text: {badge_text}"

        # Enter passphrase
        print("Receiver entering passphrase & clicking Decrypt...")
        receiver_page.fill("#receivePassphrase", passphrase)
        receiver_page.click("#btnDecrypt")

        # Wait for Decrypt Result Card
        receiver_page.wait_for_selector("#decryptResultCard", state="visible", timeout=10000)
        time.sleep(1)

        dec_sha = receiver_page.text_content("#decryptedShaDisplay").strip()
        dec_name = receiver_page.text_content("#decryptedFileName").strip()
        print(f"[PASS] Receiver Decrypted Filename: '{dec_name}'")
        print(f"[PASS] Receiver Verified SHA-256:   {dec_sha}")
        assert dec_sha.lower() == expected_sha256.lower(), "Decrypted SHA-256 mismatch!"

        # Screenshot Receiver Screen
        receiver_page.screenshot(path="images/receiver_working_demo.png")
        print("[PASS] Receiver screen captured -> images/receiver_working_demo.png")

        # Download decrypted file & verify contents
        with receiver_page.expect_download() as rx_download_info:
            receiver_page.click("#btnDownloadDecrypted")
        rx_download = rx_download_info.value
        restored_file_path = "restored_decrypted_output.txt"
        rx_download.save_as(restored_file_path)

        with open(restored_file_path, "rb") as f:
            restored_content = f.read()

        assert restored_content == test_content, "Restored content does not match original!"
        print("[PASS] Downloaded decrypted file is 100% IDENTICAL byte-for-byte to original!")

        # ─────────────────────────────────────────────────────────────
        # RECEIVER METHOD B: TESTING DRAG & DROP OF .SFSWLAN FILE
        # ─────────────────────────────────────────────────────────────
        print("\n--- [STEP 3: TESTING MANUAL .SFSWLAN FILE UPLOAD ON RECEIVER] ---")
        print(f"Receiver opening {base_url}...")
        receiver_page.goto(base_url)
        receiver_page.wait_for_load_state("networkidle")
        receiver_page.click('[data-tab="receive"]')
        receiver_page.wait_for_selector("#encryptedFileInput", timeout=5000)
        receiver_page.set_input_files("#encryptedFileInput", enc_pkg_path)
        time.sleep(0.5)
        receiver_page.fill("#receivePassphrase", passphrase)
        receiver_page.click("#btnDecrypt")
        receiver_page.wait_for_selector("#decryptResultCard", state="visible", timeout=10000)
        print("[PASS] Manual .sfswlan file upload and decryption verified successfully!")

        browser.close()

    server_inst.shutdown()

    # Clean up test files
    for p in [test_filename, enc_pkg_path, restored_file_path]:
        if os.path.exists(p):
            os.remove(p)

    print("\n" + "=" * 65)
    print("ALL SENDER & RECEIVER TESTS PASSED 100% WITH ZERO ERRORS!")
    print("=" * 65)

if __name__ == "__main__":
    run_e2e_test()

