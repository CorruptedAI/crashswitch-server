require("dotenv").config();
const express      = require("express");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const authRoutes   = require("./routes/auth");
const adminRoutes  = require("./routes/admin");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json());

// Rate limit auth endpoint aggressively — 10 requests per minute per IP
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit admin endpoint
const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests" },
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/auth",  authLimiter,  authRoutes);
app.use("/admin", adminLimiter, adminRoutes);

// Health check
app.get("/health", (_, res) => res.json({ status: "ok", ts: Date.now() }));

// 404
app.use((_, res) => res.status(404).json({ error: "Not found" }));

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`CrashSwitch license server running on port ${PORT}`);
});
