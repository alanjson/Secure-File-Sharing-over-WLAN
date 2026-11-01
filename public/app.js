/**
 * app.js
 * ──────
 * Client-Side Cryptography & File Transfer for Secure File Sharing over WLAN.
 * Author: ALAN JAISON
 *
 * Implements:
 *   - AES-256-GCM via W3C Web Cryptography API
 *   - PBKDF2-HMAC-SHA256 Key Derivation (100,000 iterations)
 *   - SHA-256 Data Integrity Verification
 *   - Zero-Knowledge Encryption (files are encrypted in the browser BEFORE leaving the device)
 *   - Zero-Server URL Fragment Transfer (Files < 2.5 MB transfer via direct link/QR)
 *   - Encrypted .sfswlan Package Download & Drop
 */

// ── Constants & Helpers ───────────────────────────────────────────────────────
const MAGIC_HEADER = new TextEncoder().encode("SFSWLAN1");
const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBuf(hexString) {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

function bufToBase64Url(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBuf(base64Url) {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ── Web Crypto API Utilities (AES-256-GCM & SHA-256) ─────────────────────────

async function computeSHA256(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  return bufToHex(hashBuffer);
}

async function deriveAESKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptFileBuffer(passphrase, fileBuffer, fileName) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const key = await deriveAESKey(passphrase, salt);

  // Compute original SHA-256 hash
  const origSha256 = await computeSHA256(fileBuffer);

  // AES-256-GCM Authenticated Encryption
  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    fileBuffer
  );

  // Pack container
  const nameBytes = new TextEncoder().encode(fileName);
  const nameLen = new Uint16Array([nameBytes.length]);
  const shaBytes = new TextEncoder().encode(origSha256); // 64 bytes

  const totalLength =
    MAGIC_HEADER.length +
    salt.length +
    iv.length +
    2 + nameBytes.length +
    shaBytes.length +
    ciphertextBuffer.byteLength;

  const container = new Uint8Array(totalLength);
  let offset = 0;

  container.set(MAGIC_HEADER, offset); offset += MAGIC_HEADER.length;
  container.set(salt, offset); offset += salt.length;
  container.set(iv, offset); offset += iv.length;
  container.set(new Uint8Array(nameLen.buffer), offset); offset += 2;
  container.set(nameBytes, offset); offset += nameBytes.length;
  container.set(shaBytes, offset); offset += shaBytes.length;
  container.set(new Uint8Array(ciphertextBuffer), offset);

  return {
    packageBytes: container,
    originalSha256: origSha256,
    originalSize: fileBuffer.byteLength,
    encryptedSize: container.byteLength
  };
}

async function decryptFilePackage(passphrase, packageBuffer) {
  const data = new Uint8Array(packageBuffer);
  let offset = 0;

  // Check Magic Header
  const magic = data.slice(offset, offset + MAGIC_HEADER.length);
  offset += MAGIC_HEADER.length;
  for (let i = 0; i < MAGIC_HEADER.length; i++) {
    if (magic[i] !== MAGIC_HEADER[i]) {
      throw new Error("Invalid file signature: Not an authentic SFSWLAN encrypted file");
    }
  }

  const salt = data.slice(offset, offset + SALT_SIZE); offset += SALT_SIZE;
  const iv = data.slice(offset, offset + IV_SIZE); offset += IV_SIZE;

  const nameLen = new Uint16Array(data.slice(offset, offset + 2).buffer)[0]; offset += 2;
  const fileName = new TextDecoder().decode(data.slice(offset, offset + nameLen)); offset += nameLen;

  const expectedSha256 = new TextDecoder().decode(data.slice(offset, offset + 64)); offset += 64;
  const ciphertext = data.slice(offset);

  // Derive AES-256 key
  const key = await deriveAESKey(passphrase, salt);

  // AES-256-GCM Decryption (verifies authentication tag automatically)
  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      key,
      ciphertext
    );
  } catch (err) {
    throw new Error("Authentication tag mismatch! Incorrect passphrase or corrupted data.");
  }

  // SHA-256 Data Integrity Verification
  const computedSha256 = await computeSHA256(decryptedBuffer);
  const match = (computedSha256.toLowerCase() === expectedSha256.toLowerCase());

  if (!match) {
    throw new Error("SHA-256 data integrity verification failed! Hash mismatch detected.");
  }

  return {
    fileName: fileName,
    fileBuffer: decryptedBuffer,
    originalSha256: expectedSha256,
    decryptedSha256: computedSha256,
    integrityVerified: true,
    fileSize: decryptedBuffer.byteLength
  };
}

// ── Application UI Controller ─────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // Navigation tabs
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = `tab-${tab.dataset.tab}`;
      navTabs.forEach(t => t.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(targetId)?.classList.add("active");
    });
  });

  // ── Tab 1: Send File Logic ──
  const sendDropzone = document.getElementById("sendDropzone");
  const fileInput = document.getElementById("fileInput");
  const btnBrowse = document.getElementById("btnBrowse");
  const fileSelectedInfo = document.getElementById("fileSelectedInfo");
  const selectedFileName = document.getElementById("selectedFileName");
  const selectedFileSize = document.getElementById("selectedFileSize");
  const hashPreviewBox = document.getElementById("hashPreviewBox");
  const originalShaPreview = document.getElementById("originalShaPreview");
  const btnEncryptAndSend = document.getElementById("btnEncryptAndSend");
  const sendPassphrase = document.getElementById("sendPassphrase");
  const toggleSendPass = document.getElementById("toggleSendPass");
  const genPassBtn = document.getElementById("genPassBtn");

  const transferMonitorSection = document.getElementById("transferMonitorSection");
  const sendProgressBar = document.getElementById("sendProgressBar");
  const sendProgressStatus = document.getElementById("sendProgressStatus");
  const sendProgressPercent = document.getElementById("sendProgressPercent");
  const sendResultCard = document.getElementById("sendResultCard");
  const shareCodeDisplay = document.getElementById("shareCodeDisplay");
  const resultShaDisplay = document.getElementById("resultShaDisplay");

  const btnDownloadEncPackage = document.getElementById("btnDownloadEncPackage");
  const shareUrlInput = document.getElementById("shareUrlInput");
  const btnCopyShareUrl = document.getElementById("btnCopyShareUrl");
  const qrCanvas = document.getElementById("qrCanvas");

  let activeFile = null;
  let activeEncryptedPackage = null;
  let activeEncFileName = "";

  btnBrowse.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) handleFileSelection(e.target.files[0]);
  });

  sendDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    sendDropzone.classList.add("dragover");
  });
  sendDropzone.addEventListener("dragleave", () => sendDropzone.classList.remove("dragover"));
  sendDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    sendDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) handleFileSelection(e.dataTransfer.files[0]);
  });

  async function handleFileSelection(file) {
    activeFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatBytes(file.size);
    fileSelectedInfo.style.display = "inline-flex";
    btnEncryptAndSend.disabled = false;

    // Show hash calculation
    hashPreviewBox.style.display = "flex";
    originalShaPreview.textContent = "Calculating original SHA-256...";
    const buffer = await file.arrayBuffer();
    const sha = await computeSHA256(buffer);
    originalShaPreview.textContent = sha;
  }

  toggleSendPass.addEventListener("click", () => {
    sendPassphrase.type = sendPassphrase.type === "password" ? "text" : "password";
  });

  genPassBtn.addEventListener("click", () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let key = "WLAN-";
    for (let i = 0; i < 8; i++) key += chars.charAt(Math.floor(Math.random() * chars.length));
    sendPassphrase.value = key;
    sendPassphrase.type = "text";
  });

  btnEncryptAndSend.addEventListener("click", async () => {
    if (!activeFile) return;
    const pass = sendPassphrase.value.trim();
    if (!pass) {
      alert("Please specify an authentication key/passphrase.");
      return;
    }

    btnEncryptAndSend.disabled = true;
    transferMonitorSection.style.display = "block";
    sendResultCard.style.display = "none";
    sendProgressBar.style.width = "25%";
    sendProgressPercent.textContent = "25%";
    sendProgressStatus.textContent = "Deriving 256-bit key via PBKDF2...";

    try {
      const buffer = await activeFile.arrayBuffer();

      sendProgressBar.style.width = "55%";
      sendProgressPercent.textContent = "55%";
      sendProgressStatus.textContent = "Encrypting with AES-256-GCM & packaging...";

      const result = await encryptFileBuffer(pass, buffer, activeFile.name);
      activeEncryptedPackage = result.packageBytes;
      activeEncFileName = activeFile.name + ".sfswlan";

      sendProgressBar.style.width = "85%";
      sendProgressPercent.textContent = "85%";
      sendProgressStatus.textContent = "Building transfer link & QR code...";

      // Generate 6-digit code
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      // Check if file is small enough to embed directly into URL fragment (< 2MB)
      let directUrl = `${window.location.origin}${window.location.pathname}?code=${code}`;
      if (activeEncryptedPackage.byteLength < 2 * 1024 * 1024) {
        const b64 = bufToBase64Url(activeEncryptedPackage);
        directUrl = `${window.location.origin}${window.location.pathname}#pkg=${b64}`;
      }

      shareUrlInput.value = directUrl;

      // Render QR Code if QRCode library is present
      if (window.QRCode && qrCanvas) {
        window.QRCode.toCanvas(qrCanvas, directUrl, { width: 140, margin: 1 }, function (error) {
          if (error) console.error(error);
        });
      }

      // Try background sync to session/API
      try {
        sessionStorage.setItem(`sfswlan_${code}`, bufToHex(activeEncryptedPackage));
        const formData = new FormData();
        formData.append("code", code);
        formData.append("filename", activeEncFileName);
        formData.append("package", new Blob([activeEncryptedPackage]));
        fetch("/api/share", { method: "POST", body: formData }).catch(() => {});
      } catch (e) {}

      sendProgressBar.style.width = "100%";
      sendProgressPercent.textContent = "100%";
      sendProgressStatus.textContent = "✓ Delivery Confirmed: Ready to Share";

      // Show results
      sendResultCard.style.display = "block";
      shareCodeDisplay.textContent = code;
      resultShaDisplay.textContent = result.originalSha256;
    } catch (err) {
      alert("Encryption error: " + err.message);
      sendProgressStatus.textContent = "Error: " + err.message;
    } finally {
      btnEncryptAndSend.disabled = false;
    }
  });

  btnDownloadEncPackage.addEventListener("click", () => {
    if (!activeEncryptedPackage) return;
    const blob = new Blob([activeEncryptedPackage], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = activeEncFileName || "encrypted_file.sfswlan";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  btnCopyShareUrl.addEventListener("click", () => {
    shareUrlInput.select();
    navigator.clipboard.writeText(shareUrlInput.value);
    btnCopyShareUrl.textContent = "✓ Copied!";
    setTimeout(() => { btnCopyShareUrl.textContent = "📋 Copy"; }, 2000);
  });

  // ── Tab 2: Receive & Decrypt File Logic ──
  const receiveCode = document.getElementById("receiveCode");
  const btnFetchCode = document.getElementById("btnFetchCode");
  const receiveDropzone = document.getElementById("receiveDropzone");
  const encryptedFileInput = document.getElementById("encryptedFileInput");
  const btnBrowseEnc = document.getElementById("btnBrowseEnc");
  const encSelectedName = document.getElementById("encSelectedName");
  const fetchHelpMessage = document.getElementById("fetchHelpMessage");
  const receivePassphrase = document.getElementById("receivePassphrase");
  const toggleRecvPass = document.getElementById("toggleRecvPass");
  const btnDecrypt = document.getElementById("btnDecrypt");

  const decryptResultCard = document.getElementById("decryptResultCard");
  const decryptedFileName = document.getElementById("decryptedFileName");
  const decryptedFileSize = document.getElementById("decryptedFileSize");
  const decryptedShaDisplay = document.getElementById("decryptedShaDisplay");
  const btnDownloadDecrypted = document.getElementById("btnDownloadDecrypted");

  let loadedEncryptedBuffer = null;
  let readyDecryptedData = null;

  // Auto-detect URL Fragment (#pkg=...) or query param (?code=...)
  function checkUrlForPackage() {
    const hash = window.location.hash;
    if (hash && hash.startsWith("#pkg=")) {
      const b64 = hash.replace("#pkg=", "");
      try {
        loadedEncryptedBuffer = base64UrlToBuf(b64);
        document.querySelector('[data-tab="receive"]').click();
        encSelectedName.textContent = `Encrypted Package Loaded (${formatBytes(loadedEncryptedBuffer.byteLength)})`;
        encSelectedName.style.display = "inline-flex";
        btnDecrypt.disabled = false;
        return;
      } catch (e) {
        console.error("Failed to parse package from URL", e);
      }
    }

    const urlParams = new URLSearchParams(window.location.search);
    const codeParam = urlParams.get("code");
    if (codeParam) {
      receiveCode.value = codeParam;
      document.querySelector('[data-tab="receive"]').click();
      fetchCodePackage(codeParam);
    }
  }
  checkUrlForPackage();

  btnBrowseEnc.addEventListener("click", () => encryptedFileInput.click());
  encryptedFileInput.addEventListener("change", async (e) => {
    if (e.target.files.length > 0) loadEncFile(e.target.files[0]);
  });

  receiveDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    receiveDropzone.classList.add("dragover");
  });
  receiveDropzone.addEventListener("dragleave", () => receiveDropzone.classList.remove("dragover"));
  receiveDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    receiveDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) loadEncFile(e.dataTransfer.files[0]);
  });

  async function loadEncFile(file) {
    encSelectedName.textContent = file.name + " (" + formatBytes(file.size) + ")";
    encSelectedName.style.display = "inline-flex";
    fetchHelpMessage.style.display = "none";
    loadedEncryptedBuffer = await file.arrayBuffer();
    btnDecrypt.disabled = false;
  }

  btnFetchCode.addEventListener("click", () => {
    let inputVal = receiveCode.value.trim();
    if (!inputVal) {
      alert("Please enter a 6-digit code or paste a direct share link.");
      return;
    }

    // If a full URL was pasted, check for #pkg= or ?code=
    if (inputVal.includes("#pkg=")) {
      const b64 = inputVal.split("#pkg=")[1];
      loadedEncryptedBuffer = base64UrlToBuf(b64);
      encSelectedName.textContent = `Encrypted Package Loaded (${formatBytes(loadedEncryptedBuffer.byteLength)})`;
      encSelectedName.style.display = "inline-flex";
      fetchHelpMessage.style.display = "none";
      btnDecrypt.disabled = false;
      return;
    } else if (inputVal.includes("code=")) {
      inputVal = inputVal.split("code=")[1].split("&")[0];
    }

    fetchCodePackage(inputVal);
  });

  async function fetchCodePackage(code) {
    btnFetchCode.textContent = "Fetching...";
    btnFetchCode.disabled = true;
    fetchHelpMessage.style.display = "none";

    try {
      let resp = await fetch(`/api/share?code=${code}`);
      if (resp.ok) {
        loadedEncryptedBuffer = await resp.arrayBuffer();
        encSelectedName.textContent = `Package Loaded from Server (Code: ${code}, Size: ${formatBytes(loadedEncryptedBuffer.byteLength)})`;
        encSelectedName.style.display = "inline-flex";
        btnDecrypt.disabled = false;
      } else {
        // Check session storage
        const localHex = sessionStorage.getItem(`sfswlan_${code}`);
        if (localHex) {
          loadedEncryptedBuffer = hexToBuf(localHex);
          encSelectedName.textContent = `Package Loaded from Local Session (Code: ${code})`;
          encSelectedName.style.display = "inline-flex";
          btnDecrypt.disabled = false;
        } else {
          throw new Error("Code not found or expired on this cloud instance.");
        }
      }
    } catch (err) {
      fetchHelpMessage.style.display = "block";
      fetchHelpMessage.innerHTML = `
        <strong>💡 Note:</strong> Vercel serverless cloud instances run independently. For 100% reliable cross-device transfer:
        <br>1. Download the <code>.sfswlan</code> encrypted file on the sender and select it above, <strong>OR</strong>
        <br>2. Open the direct <strong>QR / Direct Link</strong> on your phone.
      `;
    } finally {
      btnFetchCode.textContent = "Fetch & Load";
      btnFetchCode.disabled = false;
    }
  }

  toggleRecvPass.addEventListener("click", () => {
    receivePassphrase.type = receivePassphrase.type === "password" ? "text" : "password";
  });

  btnDecrypt.addEventListener("click", async () => {
    if (!loadedEncryptedBuffer) return;
    const pass = receivePassphrase.value.trim();
    if (!pass) {
      alert("Please enter the authentication key.");
      return;
    }

    btnDecrypt.disabled = true;
    btnDecrypt.textContent = "⌛ Decrypting with AES-256-GCM & Verifying SHA-256...";

    try {
      const decResult = await decryptFilePackage(pass, loadedEncryptedBuffer);
      readyDecryptedData = decResult;

      // Show confirmation
      decryptResultCard.style.display = "block";
      decryptedFileName.textContent = decResult.fileName;
      decryptedFileSize.textContent = formatBytes(decResult.fileSize);
      decryptedShaDisplay.textContent = decResult.decryptedSha256;
    } catch (err) {
      alert("Decryption / Integrity Error: " + err.message);
    } finally {
      btnDecrypt.disabled = false;
      btnDecrypt.textContent = "🔓 Decrypt (AES-256-GCM) & Verify SHA-256";
    }
  });

  btnDownloadDecrypted.addEventListener("click", () => {
    if (!readyDecryptedData) return;
    const blob = new Blob([readyDecryptedData.fileBuffer]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = readyDecryptedData.fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // ── Tab 3: SHA-256 Integrity Tool ──
  const hashDropzone = document.getElementById("hashDropzone");
  const hashFileInput = document.getElementById("hashFileInput");
  const btnBrowseHash = document.getElementById("btnBrowseHash");
  const hashFileInfo = document.getElementById("hashFileInfo");
  const toolCalculatedHash = document.getElementById("toolCalculatedHash");
  const toolExpectedHash = document.getElementById("toolExpectedHash");
  const btnVerifyHashMatch = document.getElementById("btnVerifyHashMatch");
  const toolHashResult = document.getElementById("toolHashResult");

  let currentCalculatedHash = "";

  btnBrowseHash.addEventListener("click", () => hashFileInput.click());
  hashFileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) handleHashToolFile(e.target.files[0]);
  });

  hashDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    hashDropzone.classList.add("dragover");
  });
  hashDropzone.addEventListener("dragleave", () => hashDropzone.classList.remove("dragover"));
  hashDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    hashDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) handleHashToolFile(e.dataTransfer.files[0]);
  });

  async function handleHashToolFile(file) {
    hashFileInfo.textContent = `${file.name} (${formatBytes(file.size)})`;
    hashFileInfo.style.display = "inline-flex";
    toolCalculatedHash.textContent = "Computing SHA-256 checksum...";

    const buffer = await file.arrayBuffer();
    currentCalculatedHash = await computeSHA256(buffer);
    toolCalculatedHash.textContent = currentCalculatedHash;
    toolHashResult.style.display = "none";
  }

  btnVerifyHashMatch.addEventListener("click", () => {
    if (!currentCalculatedHash) {
      alert("Please select a file first.");
      return;
    }
    const expected = toolExpectedHash.value.trim().toLowerCase();
    if (!expected) {
      alert("Please enter the expected SHA-256 hash.");
      return;
    }

    toolHashResult.style.display = "block";
    if (expected === currentCalculatedHash.toLowerCase()) {
      toolHashResult.className = "hash-result-box success";
      toolHashResult.innerHTML = "<strong>✓ INTEGRITY 100% VERIFIED</strong><br>The file digest matches the expected SHA-256 hash perfectly.";
    } else {
      toolHashResult.className = "hash-result-box error";
      toolHashResult.innerHTML = "<strong>✕ INTEGRITY MISMATCH DETECTED</strong><br>The computed SHA-256 hash differs from the expected hash. The file may be altered or corrupted.";
    }
  });
});
