/**
 * api/share.js
 * ────────────
 * Vercel Serverless Function for Encrypted Package Relay.
 * Zero-knowledge: the server only relays already-encrypted AES-256-GCM packages.
 */

// In-memory package cache (for Vercel serverless runtime)
const packageStore = new Map();

export const config = {
  api: {
    bodyParser: false, // Handle binary upload stream
  },
};

export default async function handler(req, res) {
  // Set CORS headers for WLAN & cross-device compatibility
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // GET /api/share?code=123456
  if (req.method === "GET") {
    const { code } = req.query;
    if (!code || !packageStore.has(code)) {
      return res.status(404).json({ error: "Transfer package not found or expired" });
    }

    const item = packageStore.get(code);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${item.filename || 'package.sfswlan'}"`);
    return res.status(200).send(item.data);
  }

  // POST /api/share
  if (req.method === "POST") {
    try {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const rawBody = Buffer.concat(chunks);

      // Parse simple boundary or query code
      const code = req.query.code || Math.floor(100000 + Math.random() * 900000).toString();
      
      packageStore.set(code, {
        data: rawBody,
        filename: req.headers["x-filename"] || "transfer.sfswlan",
        createdAt: Date.now()
      });

      // Cleanup entries older than 30 minutes
      const now = Date.now();
      for (const [k, v] of packageStore.entries()) {
        if (now - v.createdAt > 30 * 60 * 1000) {
          packageStore.delete(k);
        }
      }

      return res.status(200).json({ success: true, code: code });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}

