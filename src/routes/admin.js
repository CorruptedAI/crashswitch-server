const express = require("express");
const bcrypt  = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const pool    = require("../db");
const router  = express.Router();

// ── Admin auth middleware ─────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const password   = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!password) return res.status(401).json({ error: "Unauthorized" });
  const hash = process.env.ADMIN_PASSWORD_HASH || "";
  if (!hash) return res.status(500).json({ error: "Admin not configured" });
  bcrypt.compare(password, hash, (err, match) => {
    if (err || !match) return res.status(401).json({ error: "Unauthorized" });
    next();
  });
}

// ── POST /admin/keys — Create a new key ──────────────────────────────────────
router.post("/keys", requireAdmin, async (req, res) => {
  const { note, days } = req.body ?? {};
  const expiryDays = parseInt(days) || 365;
  const keyValue   = generateKey();
  const expiresAt  = new Date();
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
    if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, revoked: req.params.key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/keys/:key/unrevoke ────────────────────────────────────────────
router.post("/keys/:key/unrevoke", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE license_keys SET revoked = FALSE WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, message: `Key ${req.params.key} is now active again` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/keys/:key/permanent ────────────────────────────────────────
router.delete("/keys/:key/permanent", requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM auth_log WHERE key_value = $1`, [req.params.key]);
    const result = await pool.query(
      `DELETE FROM license_keys WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, deleted: req.params.key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/keys/:key/reset-hwid ─────────────────────────────────────────
router.post("/keys/:key/reset-hwid", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE license_keys SET hwid = NULL WHERE key_value = $1 RETURNING id`,
      [req.params.key]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, message: "HWID reset" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/keys/:key/adjust-time — Add or remove days ───────────────────
// Body: { days: number }  — positive to add, negative to remove
router.post("/keys/:key/adjust-time", requireAdmin, async (req, res) => {
  const days = parseInt(req.body?.days);
  if (isNaN(days) || days === 0)
    return res.status(400).json({ error: "Provide a non-zero 'days' value (positive to add, negative to remove)" });
  try {
    const result = await pool.query(
      `UPDATE license_keys
       SET expires_at = expires_at + ($1 || ' days')::INTERVAL
       WHERE key_value = $2
       RETURNING key_value, expires_at`,
      [days, req.params.key]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
    const row = result.rows[0];
    res.json({
      success:    true,
      key:        row.key_value,
      expires_at: row.expires_at,
      adjusted:   `${days > 0 ? "+" : ""}${days} days`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/hwid/ban — Ban a HWID ────────────────────────────────────────
router.post("/hwid/ban", requireAdmin, async (req, res) => {
  const { hwid, reason } = req.body ?? {};
  if (!hwid) return res.status(400).json({ error: "hwid is required" });
  try {
    await pool.query(
      `INSERT INTO hwid_bans (hwid, reason)
       VALUES ($1, $2)
       ON CONFLICT (hwid) DO UPDATE SET reason = $2, banned_at = NOW()`,
      [hwid, reason || ""]
    );
    res.json({ success: true, banned: hwid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/hwid/ban/:hwid — Unban a HWID ──────────────────────────────
router.delete("/hwid/ban/:hwid", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM hwid_bans WHERE hwid = $1 RETURNING hwid`,
      [req.params.hwid]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "HWID not in ban list" });
    res.json({ success: true, unbanned: req.params.hwid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/hwid/bans — List all banned HWIDs ─────────────────────────────
router.get("/hwid/bans", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT hwid, reason, banned_at FROM hwid_bans ORDER BY banned_at DESC`
    );
    res.json({ bans: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/logs ───────────────────────────────────────────────────────────
router.get("/logs", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT key_value, hwid, ip_address, success, reason, created_at
       FROM auth_log ORDER BY created_at DESC LIMIT 100`
    );
    res.json({ logs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function generateKey() {
  const hex = uuidv4().replace(/-/g, "").toUpperCase();
  return `CRASH-${hex.slice(0,4)}-${hex.slice(4,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}`;
}

module.exports = router;
