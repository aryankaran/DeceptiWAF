/**
 * DeceptiWAF — config.js
 * Central configuration. In production, sensitive values would come
 * from environment variables.
 */

module.exports = {
  PORT: process.env.PORT || 3000,
  HOST: '0.0.0.0',

  // Credentials (demo only — production would use env vars + hashed passwords)
  STUDENT_PASSWORD: process.env.STUDENT_PASSWORD || 'kuce2024',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'socadmin123',

  // Session
  SESSION_MAX_AGE_MS: 2 * 60 * 60 * 1000,      // 2 hours
  HONEYPOT_SESSION_MAX_AGE_MS: 30 * 60 * 1000,  // 30 min

  // CredShield
  HONEYPOT_THRESHOLD: 3,
  HONEYPOT_TTL_MS: 30 * 60 * 1000,

  // WAF
  WAF_BLOCK_THRESHOLD: 4,

  // Event store
  EVENT_HISTORY_MAX: 500,

  // Geo
  GEO_CACHE_TTL_MS: 60 * 60 * 1000,
  GEO_API_BASE: 'http://ip-api.com/json',

  // Data
  USERS_DATA_FILE: 'data/users.json',
};
