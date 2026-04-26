#!/usr/bin/env node
/**
 * Run once after Railway provisions your Postgres DB:
 *   node scripts/setupDb.js
 */
require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function setup() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS license_keys (
        id           SERIAL PRIMARY KEY,
        key_value    VARCHAR(64)  UNIQUE NOT NULL,
        hwid         VARCHAR(128) DEFAULT NULL,
        created_at   TIMESTAMPTZ  DEFAULT NOW(),
        expires_at   TIMESTAMPTZ  NOT NULL,
        revoked      BOOLEAN      DEFAULT FALSE,
        note         TEXT         DEFAULT ''
      );

      CREATE TABLE IF NOT EXISTS auth_log (
        id           SERIAL PRIMARY KEY,
        key_value    VARCHAR(64)  NOT NULL,
        hwid         VARCHAR(128),
        ip_address   VARCHAR(64),
        success      BOOLEAN,
        reason       TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log("✓ Database tables created.");
  } finally {
    client.release();
    await pool.end();
  }
}

setup().catch(console.error);
