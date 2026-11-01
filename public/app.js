/**
 * app.js
 * ──────
 * Client-Side Cryptography & File Transfer for Secure File Sharing over WLAN.
 * Author: ALAN JAISON
 *
 * Implements:
 *   - AES-256-GCM via W3C Web Cryptography API
 *   - PBKDF2-HMAC-SHA256 Key Derivation (100,000 iterations)
 *   - SHA-256 Data Integrity Verification (FIPS 180-4)
 *   - Zero-Knowledge: files encrypted in browser before sharing
 *   - URL Fragment transfer (#pkg=base64url) for files < 2.5 MB
 *   - .sfswlan package download for larger files
 */

// ── Constants & Helpers ───────────────────────────────────────────────────────
const MAGIC_HEADER = new TextEncoder().encode("SFSWLAN1");
const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;
const MAX_URL_BYTES = 2.5 * 1024 * 1024; // 2.5 MB limit for URL fragment

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
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
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ── Web Crypto API: AES-256-GCM & SHA-256 ─────────────────────────────────────

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
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptFileBuffer(passphrase, fileBuffer, fileName) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const key  = await deriveAESKey(passphrase, salt);

  const origSha256 = await computeSHA256(fileBuffer);

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    fileBuffer
  );

  const nameBytes = new TextEncoder().encode(fileName);
  const nameLen   = new Uint16Array([nameBytes.length]);
  const shaBytes  = new TextEncoder().encode(origSha256); // 64 bytes

  const totalLength =
    MAGIC_HEADER.length + salt.length + iv.length +
    2 + nameBytes.length + shaBytes.length + ciphertextBuffer.byteLength;

  const container = new Uint8Array(totalLength);
  let offset = 0;
  container.set(MAGIC_HEADER, offset); offset += MAGIC_HEADER.length;
  container.set(salt, offset);         offset += salt.length;
  container.set(iv, offset);           offset += iv.length;
  container.set(new Uint8Array(nameLen.buffer), offset); offset += 2;
  container.set(nameBytes, offset);    offset += nameBytes.length;
  container.set(shaBytes, offset);     offset += shaBytes.length;
  container.set(new Uint8Array(ciphertextBuffer), offset);

  return { packageBytes: container, originalSha256: origSha256, originalSize: fileBuffer.byteLength };
}

async function decryptFilePackage(passphrase, packageBuffer) {
  const data = new Uint8Array(packageBuffer);
  let offset = 0;

  // Verify magic header
  const magic = data.slice(offset, offset + MAGIC_HEADER.length);
  offset += MAGIC_HEADER.length;
  for (let i = 0; i < MAGIC_HEADER.length; i++) {
    if (magic[i] !== MAGIC_HEADER[i]) {
      throw new Error("Invalid file: Not an authentic SFSWLAN encrypted package.");
    }
  }

  const salt = data.slice(offset, offset + SALT_SIZE); offset += SALT_SIZE;
  const iv   = data.slice(offset, offset + IV_SIZE);   offset += IV_SIZE;

  const nameLen  = new Uint16Array(data.slice(offset, offset + 2).buffer)[0]; offset += 2;
  const fileName = new TextDecoder().decode(data.slice(offset, offset + nameLen)); offset += nameLen;

  const expectedSha256 = new TextDecoder().decode(data.slice(offset, offset + 64)); offset += 64;
  const ciphertext = data.slice(offset);

  const key = await deriveAESKey(passphrase, salt);

  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  } catch {
    throw new Error("Decryption failed — wrong passphrase or corrupted file.");
  }

  const computedSha256 = await computeSHA256(decryptedBuffer);
  if (computedSha256.toLowerCase() !== expectedSha256.toLowerCase()) {
    throw new Error("SHA-256 integrity check failed — file may be corrupted or tampered.");
  }

  return { fileName, fileBuffer: decryptedBuffer, originalSha256: expectedSha256,
           decryptedSha256: computedSha256, integrityVerified: true, fileSize: decryptedBuffer.byteLength };
}

// ── Application UI Controller ─────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {

  // ── Main Tab Navigation ──
  document.querySelectorAll(".nav-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = `tab-${tab.dataset.tab}`;
      document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(targetId)?.classList.add("active");
    });
  });

  // ── Receive Method Sub-Tabs ──
  document.querySelectorAll(".recv-method-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".recv-method-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".recv-method-pane").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.rm)?.classList.add("active");
    });
  });

  // ────────────────────────────────────────────────────────────────
  //  TAB 1: SEND FILE
  // ────────────────────────────────────────────────────────────────
  const sendDropzone       = document.getElementById("sendDropzone");
  const fileInput          = document.getElementById("fileInput");
  const btnBrowse          = document.getElementById("btnBrowse");
  const fileSelectedInfo   = document.getElementById("fileSelectedInfo");
  const selectedFileName   = document.getElementById("selectedFileName");
  const selectedFileSize   = document.getElementById("selectedFileSize");
  const hashPreviewBox     = document.getElementById("hashPreviewBox");
  const originalShaPreview = document.getElementById("originalShaPreview");
  const btnEncryptAndSend  = document.getElementById("btnEncryptAndSend");
  const sendPassphrase     = document.getElementById("sendPassphrase");
  const toggleSendPass     = document.getElementById("toggleSendPass");
  const genPassBtn         = document.getElementById("genPassBtn");
  const sizeWarning        = document.getElementById("sizeWarning");

  const transferMonitorSection = document.getElementById("transferMonitorSection");
  const sendProgressBar        = document.getElementById("sendProgressBar");
  const sendProgressStatus     = document.getElementById("sendProgressStatus");
  const sendProgressPercent    = document.getElementById("sendProgressPercent");
  const sendResultCard         = document.getElementById("sendResultCard");
  const resultShaDisplay       = document.getElementById("resultShaDisplay");
  const btnDownloadEncPackage  = document.getElementById("btnDownloadEncPackage");
  const shareUrlInput          = document.getElementById("shareUrlInput");
  const btnCopyShareUrl        = document.getElementById("btnCopyShareUrl");
  const qrCanvas               = document.getElementById("qrCanvas");
  const qrTooLarge             = document.getElementById("qrTooLarge");
  const qrcodeContainer        = document.getElementById("qrcodeContainer");

  let activeFile = null;
  let activeEncryptedPackage = null;
  let activeEncFileName = "";

  btnBrowse.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", e => {
    if (e.target.files.length > 0) handleFileSelection(e.target.files[0]);
  });

  sendDropzone.addEventListener("dragover", e => { e.preventDefault(); sendDropzone.classList.add("dragover"); });
  sendDropzone.addEventListener("dragleave", () => sendDropzone.classList.remove("dragover"));
  sendDropzone.addEventListener("drop", e => {
    e.preventDefault(); sendDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) handleFileSelection(e.dataTransfer.files[0]);
  });

  async function handleFileSelection(file) {
    activeFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatBytes(file.size);
    fileSelectedInfo.style.display = "inline-flex";
    btnEncryptAndSend.disabled = false;

    // Show size warning for large files
    sizeWarning.style.display = file.size > MAX_URL_BYTES ? "block" : "none";

    hashPreviewBox.style.display = "flex";
    originalShaPreview.textContent = "Computing SHA-256...";
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
    if (!pass) { alert("Please enter a passphrase."); return; }

    btnEncryptAndSend.disabled = true;
    transferMonitorSection.style.display = "block";
    sendResultCard.style.display = "none";

    function setProgress(pct, msg) {
      sendProgressBar.style.width = pct + "%";
      sendProgressPercent.textContent = pct + "%";
      sendProgressStatus.textContent = msg;
    }

    try {
      setProgress(20, "Deriving AES-256 key via PBKDF2-HMAC-SHA256...");
      const buffer = await activeFile.arrayBuffer();

      setProgress(50, "Encrypting with AES-256-GCM...");
      const result = await encryptFileBuffer(pass, buffer, activeFile.name);
      activeEncryptedPackage = result.packageBytes;
      activeEncFileName = activeFile.name + ".sfswlan";

      setProgress(80, "Building share link & QR code...");

      resultShaDisplay.textContent = result.originalSha256;

      // Build share URL — URL fragment for small files, none for large
      const canUseUrl = activeEncryptedPackage.byteLength < MAX_URL_BYTES;
      if (canUseUrl) {
        const b64 = bufToBase64Url(activeEncryptedPackage);
        const shareUrl = `${window.location.origin}${window.location.pathname}#pkg=${b64}`;
        shareUrlInput.value = shareUrl;

        // Generate QR code
        if (window.QRCode && qrCanvas) {
          qrCanvas.width = 140; qrCanvas.height = 140;
          window.QRCode.toCanvas(qrCanvas, shareUrl, { width: 140, margin: 1 }, err => {
            if (err) console.error("QR error:", err);
          });
          qrcodeContainer.style.display = "flex";
        }
        qrTooLarge.style.display = "none";
      } else {
        shareUrlInput.value = "(File too large for link — use Option A to download)";
        qrcodeContainer.style.display = "none";
        qrTooLarge.style.display = "block";
      }

      setProgress(100, "✓ Encrypted & Ready — choose a sharing method below");
      sendResultCard.style.display = "block";
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
    a.href = url; a.download = activeEncFileName || "encrypted_file.sfswlan";
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  });

  btnCopyShareUrl.addEventListener("click", () => {
    const val = shareUrlInput.value;
    if (!val || val.startsWith("(File too large")) return;
    navigator.clipboard.writeText(val).then(() => {
      btnCopyShareUrl.textContent = "✓ Copied!";
      setTimeout(() => { btnCopyShareUrl.textContent = "📋 Copy"; }, 2000);
    }).catch(() => {
      shareUrlInput.select();
      document.execCommand("copy");
      btnCopyShareUrl.textContent = "✓ Copied!";
      setTimeout(() => { btnCopyShareUrl.textContent = "📋 Copy"; }, 2000);
    });
  });

  // ────────────────────────────────────────────────────────────────
  //  TAB 2: RECEIVE FILE
  // ────────────────────────────────────────────────────────────────
  const receiveCode       = document.getElementById("receiveCode");
  const btnFetchCode      = document.getElementById("btnFetchCode");
  const receiveDropzone   = document.getElementById("receiveDropzone");
  const encryptedFileInput = document.getElementById("encryptedFileInput");
  const btnBrowseEnc      = document.getElementById("btnBrowseEnc");
  const encSelectedName   = document.getElementById("encSelectedName");
  const fetchHelpMessage  = document.getElementById("fetchHelpMessage");
  const receivePassphrase = document.getElementById("receivePassphrase");
  const toggleRecvPass    = document.getElementById("toggleRecvPass");
  const btnDecrypt        = document.getElementById("btnDecrypt");
  const autoLoadedBanner  = document.getElementById("autoLoadedBanner");
  const autoLoadedInfo    = document.getElementById("autoLoadedInfo");

  const decryptResultCard   = document.getElementById("decryptResultCard");
  const decryptedFileName   = document.getElementById("decryptedFileName");
  const decryptedFileSize   = document.getElementById("decryptedFileSize");
  const decryptedShaDisplay = document.getElementById("decryptedShaDisplay");
  const btnDownloadDecrypted = document.getElementById("btnDownloadDecrypted");

  let loadedEncryptedBuffer = null;
  let readyDecryptedData = null;

  // ── Auto-detect URL fragment on page load ──
  function checkUrlForPackage() {
    const hash = window.location.hash;
    if (hash && hash.startsWith("#pkg=")) {
      const b64 = hash.slice(5); // remove "#pkg="
      try {
        loadedEncryptedBuffer = base64UrlToBuf(b64);

        // Switch to receive tab and method 1
        document.querySelector('[data-tab="receive"]').click();
        document.getElementById("rmTab1").click();

        autoLoadedBanner.style.display = "block";
        autoLoadedInfo.textContent = `Package size: ${formatBytes(loadedEncryptedBuffer.byteLength)}`;
        btnDecrypt.disabled = false;

        // Clean URL (remove hash so refresh doesn't reload the huge URL)
        history.replaceState(null, "", window.location.pathname);
      } catch (e) {
        console.error("Failed to load package from URL:", e);
      }
    }
  }
  checkUrlForPackage();

  // ── Paste link and fetch ──
  btnFetchCode.addEventListener("click", () => {
    let input = receiveCode.value.trim();
    if (!input) { alert("Please paste a share link."); return; }

    // Extract #pkg= from pasted link
    if (input.includes("#pkg=")) {
      const b64 = input.split("#pkg=")[1];
      try {
        loadedEncryptedBuffer = base64UrlToBuf(b64);
        autoLoadedBanner.style.display = "block";
        autoLoadedInfo.textContent = `Package loaded from link — size: ${formatBytes(loadedEncryptedBuffer.byteLength)}`;
        fetchHelpMessage.style.display = "none";
        btnDecrypt.disabled = false;
      } catch (e) {
        showFetchError("Could not parse the encrypted package from this link. Make sure you copied the full link.");
      }
      return;
    }

    // Not a recognized link format
    showFetchError(
      "This doesn't look like a valid share link. A valid link contains <code>#pkg=</code>.<br>" +
      "Ask the sender to copy the full link from the <strong>Option B</strong> box and send it to you."
    );
  });

  function showFetchError(html) {
    fetchHelpMessage.style.display = "block";
    fetchHelpMessage.innerHTML = `⚠️ ${html}`;
    fetchHelpMessage.className = "info-note warning-note";
  }

  // ── File Drop / Browse ──
  btnBrowseEnc.addEventListener("click", () => encryptedFileInput.click());
  encryptedFileInput.addEventListener("change", async e => {
    if (e.target.files.length > 0) loadEncFile(e.target.files[0]);
  });

  receiveDropzone.addEventListener("dragover", e => { e.preventDefault(); receiveDropzone.classList.add("dragover"); });
  receiveDropzone.addEventListener("dragleave", () => receiveDropzone.classList.remove("dragover"));
  receiveDropzone.addEventListener("drop", e => {
    e.preventDefault(); receiveDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) loadEncFile(e.dataTransfer.files[0]);
  });

  async function loadEncFile(file) {
    encSelectedName.textContent = `${file.name}  (${formatBytes(file.size)})`;
    encSelectedName.style.display = "inline-flex";
    loadedEncryptedBuffer = await file.arrayBuffer();
    btnDecrypt.disabled = false;
    autoLoadedBanner.style.display = "none";
  }

  toggleRecvPass.addEventListener("click", () => {
    receivePassphrase.type = receivePassphrase.type === "password" ? "text" : "password";
  });

  btnDecrypt.addEventListener("click", async () => {
    if (!loadedEncryptedBuffer) { alert("Please load an encrypted file or link first."); return; }
    const pass = receivePassphrase.value.trim();
    if (!pass) { alert("Please enter the passphrase."); return; }

    btnDecrypt.disabled = true;
    btnDecrypt.textContent = "⌛ Decrypting & Verifying...";

    try {
      const decResult = await decryptFilePackage(pass, loadedEncryptedBuffer);
      readyDecryptedData = decResult;

      decryptResultCard.style.display = "block";
      decryptedFileName.textContent = decResult.fileName;
      decryptedFileSize.textContent = formatBytes(decResult.fileSize);
      decryptedShaDisplay.textContent = decResult.decryptedSha256;

      // Scroll to result
      decryptResultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (err) {
      alert("Decryption Error: " + err.message);
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
    a.href = url; a.download = readyDecryptedData.fileName;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  });

  // ────────────────────────────────────────────────────────────────
  //  TAB 3: SHA-256 INTEGRITY TOOL
  // ────────────────────────────────────────────────────────────────
  const hashDropzone        = document.getElementById("hashDropzone");
  const hashFileInput       = document.getElementById("hashFileInput");
  const btnBrowseHash       = document.getElementById("btnBrowseHash");
  const hashFileInfo        = document.getElementById("hashFileInfo");
  const toolCalculatedHash  = document.getElementById("toolCalculatedHash");
  const toolExpectedHash    = document.getElementById("toolExpectedHash");
  const btnVerifyHashMatch  = document.getElementById("btnVerifyHashMatch");
  const toolHashResult      = document.getElementById("toolHashResult");

  let currentCalculatedHash = "";

  btnBrowseHash.addEventListener("click", () => hashFileInput.click());
  hashFileInput.addEventListener("change", e => {
    if (e.target.files.length > 0) handleHashToolFile(e.target.files[0]);
  });

  hashDropzone.addEventListener("dragover", e => { e.preventDefault(); hashDropzone.classList.add("dragover"); });
  hashDropzone.addEventListener("dragleave", () => hashDropzone.classList.remove("dragover"));
  hashDropzone.addEventListener("drop", e => {
    e.preventDefault(); hashDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) handleHashToolFile(e.dataTransfer.files[0]);
  });

  async function handleHashToolFile(file) {
    hashFileInfo.textContent = `${file.name}  (${formatBytes(file.size)})`;
    hashFileInfo.style.display = "inline-flex";
    toolCalculatedHash.textContent = "Computing SHA-256...";
    const buffer = await file.arrayBuffer();
    currentCalculatedHash = await computeSHA256(buffer);
    toolCalculatedHash.textContent = currentCalculatedHash;
    toolHashResult.style.display = "none";
  }

  btnVerifyHashMatch.addEventListener("click", () => {
    if (!currentCalculatedHash) { alert("Please select a file first."); return; }
    const expected = toolExpectedHash.value.trim().toLowerCase();
    if (!expected) { alert("Please paste the expected SHA-256 hash."); return; }

    toolHashResult.style.display = "block";
    if (expected === currentCalculatedHash.toLowerCase()) {
      toolHashResult.className = "hash-result-box success";
      toolHashResult.innerHTML = "<strong>✓ INTEGRITY 100% VERIFIED</strong><br>The computed SHA-256 digest matches the expected hash perfectly. File is authentic.";
    } else {
      toolHashResult.className = "hash-result-box error";
      toolHashResult.innerHTML = "<strong>✕ INTEGRITY MISMATCH DETECTED</strong><br>The computed SHA-256 digest does NOT match the expected hash. File may be altered or corrupted.";
    }
  });
});
