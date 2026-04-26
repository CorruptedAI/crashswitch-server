const express = require("express");
const jwt     = require("jsonwebtoken");
const pool    = require("../db");
const router  = express.Router();

// Private key comes from env var — never stored in code
const PRIVATE_KEY  = (process.env.PRIVATE_KEY || "").replace(/\\n/g, "\n");
const JWT_ISSUER   = "crashswitch-server";
const JWT_AUDIENCE = "crashswitch-client";
const TOKEN_TTL    = "30m";  // short-lived — client re-validates every 25 min

/**
 * POST /auth/verify
 * Body: { key: string, hwid: string }
 *
 * Returns: { token: string } on success
 *          { error: string } on failure
 *
 * Error messages are deliberately vague to avoid leaking info.
 */
router.post("/verify", async (req, res) => {
  const ip   = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const { key, hwid } = req.body ?? {};

  // Basic input validation
  if (typeof key  !== "string" || key.length  < 8 || key.length  > 64) {
    return res.status(400).json({ error: "Invalid request" });
  }
  if (typeof hwid !== "string" || hwid.length < 8 || hwid.length > 128) {
    return res.status(400).json({ error: "Invalid request" });
  }

  const client = await pool.connect();
  try {
    // Fetch the key record
    const result = await client.query(
      `SELECT id, key_value, hwid, expires_at, revoked
       FROM license_keys
       WHERE key_value = $1
       LIMIT 1`,
      [key]
    );

    const record = result.rows[0];

    // --- Check 1: key exists ---
    if (!record) {
      await logAttempt(client, key, hwid, ip, false, "key_not_found");
      return res.status(401).json({ error: "Invalid license key" });
    }

    // --- Check 2: not revoked ---
    if (record.revoked) {
      await logAttempt(client, key, hwid, ip, false, "revoked");
      return res.status(401).json({ error: "License key has been revoked" });
    }

    // --- Check 3: not expired ---
    if (new Date(record.expires_at) < new Date()) {
      await logAttempt(client, key, hwid, ip, false, "expired");
      return res.status(401).json({ error: "License key has expired" });
    }

    // --- Check 4: HWID binding ---
    if (record.hwid === null || record.hwid === "") {
      // First activation — bind this HWID to the key
      await client.query(
        `UPDATE license_keys SET hwid = $1 WHERE id = $2`,
        [hwid, record.id]
      );
    } else if (record.hwid !== hwid) {
      // HWID mismatch — different machine
      await logAttempt(client, key, hwid, ip, false, "hwid_mismatch");
      return res.status(401).json({ error: "License key is bound to a different machine" });
    }

    // --- All checks passed — issue JWT ---
    if (!PRIVATE_KEY) {
      console.error("PRIVATE_KEY env var not set!");
      return res.status(500).json({ error: "Server configuration error" });
    }

    const payload = {
      sub:  key,
      hwid: hwid,
      iss:  JWT_ISSUER,
      aud:  JWT_AUDIENCE,
    };

    const token = jwt.sign(payload, PRIVATE_KEY, {
      algorithm : "RS256",
      expiresIn : TOKEN_TTL,
    });

    await logAttempt(client, key, hwid, ip, true, "ok");
    return res.json({ token, expiresIn: 30 * 60 });

  } catch (err) {
    console.error("Auth error:", err);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    client.release();
  }
});

async function logAttempt(client, key, hwid, ip, success, reason) {
  try {
    await client.query(
      `INSERT INTO auth_log (key_value, hwid, ip_address, success, reason)
       VALUES ($1, $2, $3, $4, $5)`,
      [key, hwid, ip, success, reason]
    );
  } catch { /* don't let logging break auth */ }
}

module.exports = router;
