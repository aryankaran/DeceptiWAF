// Honeypot failure counter and trap state tracker

const HONEYPOT_THRESHOLD = 3;
const HONEYPOT_TTL_MS = 30 * 60 * 1000; // 30 min

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

// Process a failed login. Returns { action: 'reject' } or { action: 'activate' }
function noteFailedLogin(ip, username) {
  const s = record(ip);
  s.count += 1;
  s.lastAttempt = Date.now();
  if (s.count >= HONEYPOT_THRESHOLD && !s.honeypotActive) {
    s.honeypotActive = true;
    s.armedAt = Date.now();
    return { action: 'activate', attempt: s.count };
  }
  return { action: 'reject', attempt: s.count };
}

// Record a trapped attempt (IP already honeypot-active). Bumps counters.
function noteTrappedAttempt(ip, username) {
  const s = record(ip);
  s.count += 1;
  s.trapCount += 1;
  s.lastAttempt = Date.now();
  s.trappedUser = username || 'unknown';
  return { attempt: s.count, trapCount: s.trapCount };
}

function clear(ip) { failedLogins.delete(ip); }
function clearAll() { failedLogins.clear(); }

// Snapshot for admin API / SOC display
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
