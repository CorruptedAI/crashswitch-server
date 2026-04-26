#!/usr/bin/env node
/**
 * Run ONCE before deploying:  node scripts/generateKeys.js
 *
 * Outputs:
 *   private.pem  — stays on the server ONLY, never committed, never in the exe
 *   public.pem   — embed this in CrashSwitch.exe (safe to distribute)
 */
const { generateKeyPairSync } = require("crypto");
const fs = require("fs");
const path = require("path");

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const outDir = path.join(__dirname, "..");
fs.writeFileSync(path.join(outDir, "private.pem"), privateKey,  { mode: 0o600 });
fs.writeFileSync(path.join(outDir, "public.pem"),  publicKey);

console.log("✓ private.pem — ADD TO RAILWAY as env var PRIVATE_KEY (contents)");
console.log("✓ public.pem  — embed in CrashSwitch.exe as embedded resource");
console.log();
console.log("IMPORTANT: Never commit private.pem to git.");
console.log("Add to .gitignore:  private.pem");
