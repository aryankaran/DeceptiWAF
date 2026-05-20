/**
 * DeceptiWAF - lib/credshield.js
 * ------------------------------------------------------------------
 * Phase 3: CredShield — Brute-Force Honeypot
 *
 *   Tracks failed login attempts per IP. After 3 failures from the
 *   same IP, that IP enters "honeypot-active" state. On the 4th
 *   attempt (regardless of credentials), the system lies "Login
 *   Successful" and redirects to /trap — a fake dashboard that
 *   looks real, so the attacker wastes time exploring decoy data.
 *
 *   Events emitted via Socket.io:
 *     - 'honeypot_event' { type: 'failed',     ip, attempt, username }
 *     - 'honeypot_event' { type: 'activated',  ip, attempt }
 *     - 'honeypot_event' { type: 'trapped',    ip, attempt, username }
 *
 *   Threshold: HONEYPOT_THRESHOLD = 3 (trap on the (THRESHOLD+1)th attempt)
 *
 *   TTL: Honeypot auto-disarms after HONEYPOT_TTL_MS of inactivity,
 *   so a legit user on a shared IP isn't locked out forever.
 * ------------------------------------------------------------------
 */

const HONEYPOT_THRESHOLD = 3;

// Auto-disarm after 30 minutes of no login attempts from the trapped IP.
// This prevents permanent lockout of legit users on shared IPs.
const HONEYPOT_TTL_MS = 30 * 60 * 1000;

// ip -> { count, lastAttempt, honeypotActive, trappedUser, armedAt, trapCount }
const failedLogins = new Map();

function record(ip) {
  if (!failedLogins.has(ip)) {
    failedLogins.set(ip, {
      count: 0,
      lastAttempt: 0,
      honeypotActive: false,
      trappedUser: null,
      armedAt: null,
      trapCount: 0,
    });
  }
  return failedLogins.get(ip);
}

function getStatus(ip) {
  const s = failedLogins.get(ip);
  if (!s) return null;
  // Lazy TTL check: if honeypot is active but hasn't been touched in TTL_MS,
  // auto-disarm so the IP can try again.
  if (s.honeypotActive && s.lastAttempt && (Date.now() - s.lastAttempt > HONEYPOT_TTL_MS)) {
    s.honeypotActive = false;
    s.count = 0;
    s.trappedUser = null;
    s.armedAt = null;
    // Keep trapCount for historical reporting
  }
  return s;
}

function isHoneypotActive(ip) {
  const s = getStatus(ip);
  return !!(s && s.honeypotActive);
}

function getTrappedUser(ip) {
  const s = getStatus(ip);
  return s ? s.trappedUser : null;
}

/**
 * Process a failed login attempt (called on the NORMAL failure path,
 * i.e. when the IP is NOT yet honeypot-active).
 *
 * Returns an object describing what CredShield decided to do.
 *
 *   { action: 'reject' }                                  -> normal reject
 *   { action: 'activate' }                                -> just turned honeypot ON
 */
function noteFailedLogin(ip, username) {
  const s = record(ip);
  s.count += 1;
  s.lastAttempt = Date.now();

  // Just crossed the threshold? Activate honeypot, but still reject THIS
  // attempt (the spec says "on the 4th attempt, redirect to /trap").
  if (s.count >= HONEYPOT_THRESHOLD && !s.honeypotActive) {
    s.honeypotActive = true;
    s.armedAt = Date.now();
    return { action: 'activate', attempt: s.count };
  }

  // Under threshold — normal reject.
  return { action: 'reject', attempt: s.count };
}

/**
 * Record a trapped attempt (called on the TRAP path, when the IP is
 * already honeypot-active). Bumps the counter so the SOC dashboard
 * reports the correct attempt number (4, 5, 6, ...) instead of
 * staying stuck at the threshold.
 *
 * Returns the new attempt count and trap count.
 */
function noteTrappedAttempt(ip, username) {
  const s = record(ip);
  s.count += 1;
  s.trapCount += 1;
  s.lastAttempt = Date.now();
  s.trappedUser = username || 'unknown';
  return { attempt: s.count, trapCount: s.trapCount };
}

/**
 * Reset an IP's history (call on successful legitimate login, or via
 * admin reset endpoint).
 */
function clear(ip) {
  failedLogins.delete(ip);
}

/**
 * Admin: disarm all trapped IPs (nuclear option).
 */
function clearAll() {
  failedLogins.clear();
}

/**
 * Pretty-print the tracker state for debugging / SOC display / admin API.
 */
function snapshot() {
  const out = [];
  for (const [ip, s] of failedLogins.entries()) {
    // Trigger lazy TTL check
    getStatus(ip);
    out.push({
      ip,
      count: s.count,
      honeypotActive: s.honeypotActive,
      trappedUser: s.trappedUser,
      armedAt: s.armedAt ? new Date(s.armedAt).toISOString() : null,
      lastAttempt: s.lastAttempt ? new Date(s.lastAttempt).toISOString() : null,
      trapCount: s.trapCount,
    });
  }
  return out;
}

module.exports = {
  HONEYPOT_THRESHOLD,
  HONEYPOT_TTL_MS,
  noteFailedLogin,
  noteTrappedAttempt,
  isHoneypotActive,
  getTrappedUser,
  getStatus,
  clear,
  clearAll,
  snapshot,
};
