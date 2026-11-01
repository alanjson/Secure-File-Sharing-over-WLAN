# 🛡️ Secure File Sharing over WLAN

**Project Abstract & Universal Cross-Platform System (Web, WLAN & Desktop)**  
**Submitted by:** ALAN JAISON  

<div align="center">
  <img src="https://img.shields.io/badge/Vercel-Ready-black?style=for-the-badge&logo=vercel" alt="Vercel">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-238636.svg?style=for-the-badge" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/Integrity-SHA--256-1f6feb.svg?style=for-the-badge" alt="SHA-256">
  <img src="https://img.shields.io/badge/Network-Local_WLAN-d29922.svg?style=for-the-badge" alt="WLAN">
  <img src="https://img.shields.io/badge/Web_Crypto_API-Hardware_Accelerated-8957e5.svg?style=for-the-badge" alt="Web Crypto">
</div>

<br>

## 📄 Abstract

> **Secure File Sharing over WLAN** is a software application designed to enable secure and efficient file transfer between devices connected to the same Wireless Local Area Network (WLAN). The system eliminates the need for external internet-based file-sharing services by allowing devices on the same network to communicate through a local client-server architecture. Users can authenticate before initiating a transfer, select files for sharing, and transmit them securely over the WLAN.
>
> To enhance security, the proposed system employs **AES-256-GCM** encryption to protect file contents during transmission. At the receiving end, the encrypted data is decrypted using the appropriate key. **SHA-256** hashing can additionally be used to verify file integrity by comparing the hash values of the original and received files. The application provides a simple interface for connecting to the receiver, selecting files, monitoring transfers, and confirming successful delivery. The project demonstrates the practical application of WLAN communication, client-server networking, authentication, encryption, and data integrity in mobile computing.

**Keywords:** WLAN, Secure File Transfer, Client-Server Architecture, Authentication, AES-256-GCM, SHA-256, Data Integrity, Mobile Computing.

---

## ✨ Features & User Experience

- **⚡ Zero-Knowledge Client-Side Encryption**: Files are encrypted with **AES-256-GCM** directly in the sender's browser or device using hardware-accelerated Web Crypto API before transmission.
- **☁️ 100% Vercel & Cloud Compatible**: Includes `vercel.json` and serverless API handlers for instant 1-click deployment on Vercel.
- **📱 Universal WLAN Mobile Support**: Any smartphone, tablet, or PC on the same Wi-Fi network can transfer files instantly without installing any app.
- **🔐 Pre-Transfer Authentication**: Challenge-response handshake and PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations.
- **✔️ Real-Time SHA-256 Verification**: Computes original hash and compares against decrypted hash for automatic 100% bit-for-bit delivery confirmation.
- **🎯 6-Digit Quick Transfer Code**: Senders can generate a simple 6-digit code or direct link for receivers to fetch and decrypt the file in seconds.
- **🖥️ Dual Deployment**: Run as a modern web app on Vercel/LAN or as a desktop GUI via Python.

---

## 🌐 Deploy to Vercel (1-Click or CLI)

This repository is pre-configured with `vercel.json`, `package.json`, and serverless functions in `/api/`.

### Method A: Deploy via GitHub (Recommended)
1. Push this repository to your **GitHub** account.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your repository and click **Deploy**.
4. That's it! Your secure file sharing web app is live on your `.vercel.app` domain.

### Method B: Deploy via Vercel CLI
```bash
npm install -g vercel
vercel
```

---

## 💻 Running Locally

### Option 1: Modern Web App via Node.js
```bash
npm start
# Opens on http://localhost:3000
```

### Option 2: Run via Python (Local WLAN Server + Web Portal)
```bash
python main.py
# or
python gui.py
```
This automatically launches the desktop application and hosts the modern web portal on your WLAN at `http://<YOUR_IP>:8766`.

### Option 3: Command Line Interface (CLI)
```bash
# Start receiver
python main.py receive --port 8765 --key MySecretKey

# Send file
python main.py send --host 192.168.1.48 --port 8765 --key MySecretKey --file document.pdf

# Verify SHA-256
python main.py verify --file document.pdf --hash <expected_hash>
```

---

## 🏗️ Architecture & Transfer Workflow

```
[ Sender (Client) ]
  ├── 1. Drag & drop or select file
  ├── 2. Compute Original SHA-256 Hash
  ├── 3. Derive 256-bit AES Key via PBKDF2-HMAC-SHA256 (100,000 rounds)
  └── 4. Encrypt file contents using AES-256-GCM (96-bit unique IV + 128-bit tag)
          │
          ▼ [ Local WLAN / Vercel Serverless Relay ]
          │
[ Receiver (Server) ]
  ├── 1. Fetch encrypted container via 6-digit Transfer Code or WLAN IP
  ├── 2. Input Authentication Key & derive AES-256 key
  ├── 3. Decrypt with AES-256-GCM (Hardware-verified authentication tag)
  ├── 4. Compute Decrypted File's SHA-256 Hash
  ├── 5. Compare Hashes: (Original SHA-256 == Decrypted SHA-256)
  └── 6. Confirm Delivery: Show "✓ Delivery Confirmed" & Download Decrypted File
```

---

## 📁 Repository Structure

```
├── public/                     # Modern, User-Friendly Web Application (Vercel & WLAN)
│   ├── index.html              # Drag-and-drop UI with progress bars & status cards
│   ├── style.css               # Clean dark-mode responsive styling
│   └── app.js                  # Native Web Crypto API (AES-256-GCM & SHA-256)
├── api/
│   └── share.js                # Vercel Serverless Function for encrypted package relay
├── vercel.json                 # Vercel configuration for static + serverless deployment
├── package.json                # Node.js manifest & Vercel build script
├── server.js                   # Lightweight Node.js local runner
├── crypto_utils.py             # Python AES-256-GCM & PBKDF2 & SHA-256 engine
├── protocol.py                 # TCP framing & challenge-response handshake
├── server.py                   # WLAN receiver & integrated web portal
├── client.py                   # WLAN sender client
├── gui.py                      # Desktop GUI application
├── main.py                     # Unified entry point (GUI + CLI)
├── test_all.py                 # Automated end-to-end verification test suite
└── Secure-File-Sharing-WLAN.spec # PyInstaller Windows .exe build spec
```

---

## 📜 Credits & Author

- **Project Title:** Secure File Sharing over WLAN
- **Author / Submitted by:** ALAN JAISON
- **Standards:** AES-256-GCM (NIST SP 800-38D), PBKDF2 (RFC 8018), SHA-256 (FIPS 180-4)
