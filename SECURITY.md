# Security Policy — Secure File Sharing over WLAN

**Project Title**: Secure File Sharing over WLAN  
**Submitted by**: ALAN JAISON  

## Cryptographic & Security Architecture

This application is designed specifically for secure local peer-to-peer file transfer across devices connected to the same Wireless Local Area Network (WLAN), eliminating reliance on external cloud or internet-based third-party file servers.

### 1. Pre-Transfer Authentication
- **Challenge-Response Handshake**: The receiver issues a cryptographically random 128-bit challenge upon client connection.
- **HMAC-SHA256 Response**: Senders must authenticate using a shared passkey / secret before any transfer request is accepted. Unauthorized connection attempts are terminated immediately.

### 2. AES-256-GCM Authenticated Encryption
- **Cipher**: Advanced Encryption Standard in Galois/Counter Mode (AES-256-GCM).
- **Confidentiality & Integrity**: AES-256 provides military-grade confidentiality, while GCM provides authenticated encryption with an embedded 128-bit authentication tag per chunk. Any tampering or packet corruption immediately triggers an `InvalidTag` rejection.
- **Key Derivation**: 256-bit AES session keys are securely derived using PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique 128-bit cryptographic salt per transfer.
- **Non-repeating Nonces**: Every chunk utilizes a distinct 96-bit nonce derived from a cryptographically random base nonce and an incremental chunk counter.

### 3. SHA-256 End-to-End Data Integrity
- Prior to encryption, the sender computes the full SHA-256 cryptographic digest of the original file.
- After on-the-fly AES-256-GCM decryption, the receiver computes the SHA-256 digest of the restored file.
- The receiver compares both digests to confirm exact, uncorrupted, bit-for-bit delivery.
- A cryptographic delivery confirmation status is returned to the sender.

### 4. Local WLAN Scope & Threat Model
- Traffic is confined strictly to the local WLAN/LAN subnet.
- Even if wireless packets are captured by an eavesdropper on the local WiFi network, file contents remain completely protected by AES-256-GCM.
