const express = require("express");
const bcrypt  = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const pool    = require("../db");
const router  = express.Router();

// ── Admin auth middleware ─────────────────────────────────────────────────────
// Admin password hash is stored as env var ADMIN_PASSWORD_HASH
// Generate it once with:  node -e "require('bcrypt').hash('yourpass',12).then(console.log)"
function requireAdmin(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const password   = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : "";

  if (!password) return res.status(401).json({ error: "Unauthorized" });

  const hash = process.env.ADMIN_PASSWORD_HASH || "";
  if (!hash) return res.status(500).json({ error: "Admin not configured" });

  bcrypt.compare(password, hash, (err, match) => {
    if (err || !match) return res.status(401).json({ error: "Unauthorized" });
    next();
  });
}

// ── POST /admin/keys — Create a new key ───────────────────────────────────────
router.post("/keys", requireAdmin, async (req, res) => {
  const { note, days } = req.body ?? {};
  const expiryDays = parseInt(days) || 365;

  const keyValue = generateKey();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiryDays);

  try {
    const result = await pool.query(
      `INSERT INTO license_keys (key_value, expires_at, note)
       VALUES ($1, $2, $3)
       RETURNING id, key_value, expires_at, note`,
      [keyValue, expiresAt.toISOString(), note || ""]
    );
    res.json({ success: true, key: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/keys — List all keys ──────────────────────────────────────────
router.get("/keys", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, key_value, hwid,
              created_at, expires_at, revoked, note,
              (expires_at < NOW()) AS expired
       FROM license_keys
       ORDER BY created_at DESC`
    );
    res.json({ keys: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/keys/:key — Revoke a key ────────────────────────────────────
router.delete("/keys/:key", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE license_keys SET revoked = TRUE WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, revoked: req.params.key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/keys/:key/unrevoke — Restore a revoked key ───────────────────
router.post("/keys/:key/unrevoke", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE license_keys SET revoked = FALSE WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, message: `Key ${req.params.key} is now active again` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/keys/:key/permanent — Permanently delete a key ──────────────
router.delete("/keys/:key/permanent", requireAdmin, async (req, res) => {
  try {
    // Also delete associated auth logs
    await pool.query(`DELETE FROM auth_log WHERE key_value = $1`, [req.params.key]);
    const result = await pool.query(
      `DELETE FROM license_keys WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, deleted: req.params.key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/keys/:key/reset-hwid — Unbind HWID ───────────────────────────
// Useful if a user gets a new PC
router.post("/keys/:key/reset-hwid", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE license_keys SET hwid = NULL WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, message: "HWID reset — key can activate on a new machine" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/logs — View recent auth attempts ───────────────────────────────
router.get("/logs", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT key_value, hwid, ip_address, success, reason, created_at
       FROM auth_log
       ORDER BY created_at DESC
       LIMIT 100`
    );
    res.json({ logs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Key generator ─────────────────────────────────────────────────────────────
function generateKey() {
  // Format: CRASH-XXXX-XXXX-XXXX-XXXX
  const hex = uuidv4().replace(/-/g, "").toUpperCase();
  return `CRASH-${hex.slice(0,4)}-${hex.slice(4,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}`;
}

module.exports = router;
