// SQLite database initialization and data access methods

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'deceptiwaf.db');
const db = new Database(dbPath);

// Enable WAL mode for high performance
db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    fake_profile_json TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    type TEXT NOT NULL,
    attack_type TEXT,
    score INTEGER DEFAULT 0,
    threshold INTEGER DEFAULT 4,
    ip TEXT NOT NULL,
    method TEXT,
    path TEXT,
    hits_json TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL,
    server_time INTEGER NOT NULL,
    geo_json TEXT,
    fingerprint_json TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
  CREATE INDEX IF NOT EXISTS idx_events_server_time ON events(server_time DESC);

  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL,
    blocked_until INTEGER DEFAULT 0
  );
`);

// Prepared Statements
const stmtInsertSession = db.prepare(`
  INSERT OR REPLACE INTO sessions (token, username, fake_profile_json, created_at)
  VALUES (?, ?, ?, ?)
`);

const stmtGetSession = db.prepare(`
  SELECT token, username, fake_profile_json, created_at FROM sessions WHERE token = ?
`);

const stmtDeleteSession = db.prepare(`
  DELETE FROM sessions WHERE token = ?
`);

const stmtInsertEvent = db.prepare(`
  INSERT INTO events (seq, kind, type, attack_type, score, threshold, ip, method, path, hits_json, user_agent, timestamp, server_time, geo_json, fingerprint_json)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const stmtGetRecentEvents = db.prepare(`
  SELECT * FROM events ORDER BY seq DESC LIMIT ?
`);

const stmtGetTopAttackers = db.prepare(`
  SELECT 
    ip,
    COUNT(*) as total_events,
    SUM(CASE WHEN kind = 'waf' AND type = 'block' THEN 1 ELSE 0 END) as blocked_count,
    SUM(CASE WHEN kind = 'waf' AND type = 'flag' THEN 1 ELSE 0 END) as flagged_count,
    SUM(CASE WHEN kind = 'honeypot' AND type = 'trapped' THEN 1 ELSE 0 END) as trapped_count,
    SUM(CASE WHEN kind = 'honeypot' AND type = 'failed' THEN 1 ELSE 0 END) as failed_count,
    SUM(CASE WHEN kind = 'ratelimit' AND type = 'block' THEN 1 ELSE 0 END) as ratelimit_count,
    MAX(server_time) as last_seen,
    geo_json
  FROM events
  WHERE ip IS NOT NULL AND ip != ''
  GROUP BY ip
  ORDER BY total_events DESC
  LIMIT ?
`);

const stmtGetStats = db.prepare(`
  SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN kind = 'waf' AND type = 'block' THEN 1 ELSE 0 END) as blocked,
    SUM(CASE WHEN kind = 'waf' AND type = 'flag' THEN 1 ELSE 0 END) as flagged,
    SUM(CASE WHEN kind = 'honeypot' AND type = 'trapped' THEN 1 ELSE 0 END) as trapped,
    SUM(CASE WHEN kind = 'honeypot' AND type = 'failed' THEN 1 ELSE 0 END) as failed,
    SUM(CASE WHEN kind = 'ratelimit' THEN 1 ELSE 0 END) as ratelimited,
    COUNT(DISTINCT ip) as uniqueAttackers
  FROM events
`);

const stmtClearEvents = db.prepare(`DELETE FROM events`);

// Helper Functions
function saveSession(token, username, fakeUserProfile = null) {
  stmtInsertSession.run(token, username, fakeUserProfile ? JSON.stringify(fakeUserProfile) : null, Date.now());
}

function getSession(token) {
  const row = stmtGetSession.get(token);
  if (!row) return null;
  return {
    username: row.username,
    issuedAt: row.created_at,
    fakeUserProfile: row.fake_profile_json ? JSON.parse(row.fake_profile_json) : null,
  };
}

function deleteSession(token) {
  stmtDeleteSession.run(token);
}

function saveEvent(evt) {
  stmtInsertEvent.run(
    evt.seq || 0,
    evt.kind || 'unknown',
    evt.type || 'info',
    evt.attackType || null,
    evt.score || 0,
    evt.threshold || 4,
    evt.ip || '0.0.0.0',
    evt.method || 'GET',
    evt.path || '/',
    evt.hits ? JSON.stringify(evt.hits) : null,
    evt.userAgent || '',
    evt.timestamp || new Date().toISOString(),
    evt.serverTime || Date.now(),
    evt.geo ? JSON.stringify(evt.geo) : null,
    evt.fingerprint ? JSON.stringify(evt.fingerprint) : null
  );
}

function getRecentEvents(limit = 50) {
  const rows = stmtGetRecentEvents.all(limit);
  return rows.map((r) => ({
    id: r.id,
    seq: r.seq,
    kind: r.kind,
    type: r.type,
    attackType: r.attack_type,
    score: r.score,
    threshold: r.threshold,
    ip: r.ip,
    method: r.method,
    path: r.path,
    hits: r.hits_json ? JSON.parse(r.hits_json) : [],
    userAgent: r.user_agent,
    timestamp: r.timestamp,
    serverTime: r.server_time,
    geo: r.geo_json ? JSON.parse(r.geo_json) : null,
    fingerprint: r.fingerprint_json ? JSON.parse(r.fingerprint_json) : null,
  }));
}

function getTopAttackers(limit = 20) {
  const rows = stmtGetTopAttackers.all(limit);
  return rows.map((r) => ({
    ip: r.ip,
    geo: r.geo_json ? JSON.parse(r.geo_json) : null,
    totalEvents: r.total_events || 0,
    blockedCount: r.blocked_count || 0,
    flaggedCount: r.flagged_count || 0,
    trappedCount: r.trapped_count || 0,
    failedCount: r.failed_count || 0,
    ratelimitCount: r.ratelimit_count || 0,
    lastSeen: r.last_seen ? new Date(r.last_seen).toISOString() : new Date().toISOString(),
  }));
}

function getEventStats() {
  const s = stmtGetStats.get();
  return {
    total: s.total || 0,
    blocked: s.blocked || 0,
    flagged: s.flagged || 0,
    trapped: s.trapped || 0,
    failed: s.failed || 0,
    ratelimited: s.ratelimited || 0,
    uniqueAttackers: s.uniqueAttackers || 0,
  };
}

function clearEvents() {
  stmtClearEvents.run();
}

module.exports = {
  db,
  saveSession,
  getSession,
  deleteSession,
  saveEvent,
  getRecentEvents,
  getTopAttackers,
  getEventStats,
  clearEvents,
};
