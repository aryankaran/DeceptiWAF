/**
 * DeceptiWAF - config.js
 * ------------------------------------------------------------------
 * Central configuration. Separating config from code is standard
 * practice — you can change passwords, thresholds, and ports without
 * touching server.js. In production, sensitive values (passwords)
 * would come from environment variables.
 * ------------------------------------------------------------------
 */

// In production, these would be read from environment variables:
//   process.env.STUDENT_PASSWORD || 'kuce2024'
// For the demo, hardcoded fallbacks are fine.
module.exports = {
  // --- Server ---
  PORT: process.env.PORT || 3000,
  HOST: '0.0.0.0',

  // --- Credentials ---
  // NOTE: In a real app, passwords would be hashed (bcrypt/argon2) and
  // stored in a database. For this demo they're plaintext in config.
  STUDENT_PASSWORD: process.env.STUDENT_PASSWORD || 'kuce2024',
  ADMIN_PASSWORD:   process.env.ADMIN_PASSWORD   || 'socadmin123',

  // --- Session ---
  SESSION_MAX_AGE_MS: 2 * 60 * 60 * 1000,    // 2 hours for legit sessions
  HONEYPOT_SESSION_MAX_AGE_MS: 30 * 60 * 1000, // 30 min trapped in honeypot

  // --- CredShield (Phase 3) ---
  HONEYPOT_THRESHOLD: 3,        // number of failed logins before honeypot arms
  HONEYPOT_TTL_MS: 30 * 60 * 1000, // auto-disarm after 30 min of inactivity

  // --- WAF (Phase 2) ---
  WAF_BLOCK_THRESHOLD: 4,       // block when score > 4

  // --- Event store (Phase 4) ---
  EVENT_HISTORY_MAX: 500,       // keep last 500 events in memory

  // --- Geo (Phase 4) ---
  GEO_CACHE_TTL_MS: 60 * 60 * 1000, // 1 hour
  GEO_API_BASE: 'http://ip-api.com/json',

  // --- Data files ---
  USERS_DATA_FILE: 'data/users.json',
};
