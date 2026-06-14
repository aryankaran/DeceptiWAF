/**
 * DeceptiWAF — lib/eventStore.js
 * SOC Event Store interfacing with SQLite database (`lib/db.js`).
 * Maintains compatibility with existing code while offering persistent logging.
 */

const db = require('./db');

const MAX_EVENTS = 500;
let currentSeq = 0;

// Initialize seq from database if events exist
try {
  const recent = db.getRecentEvents(1);
  if (recent.length > 0) {
    currentSeq = recent[0].seq || 0;
  }
} catch (e) {
  console.error('[EVENTSTORE] Failed to read last seq:', e.message);
}

function push(evt) {
  currentSeq += 1;
  evt.seq = currentSeq;
  evt.serverTime = Date.now();
  if (!evt.timestamp) {
    evt.timestamp = new Date().toISOString();
  }

  // Persist to SQLite
  try {
    db.saveEvent(evt);
  } catch (e) {
    console.error('[EVENTSTORE] Error persisting event:', e.message);
  }
}

function recent(limit = 50) {
  return db.getRecentEvents(limit);
}

function topAttackers(limit = 20) {
  return db.getTopAttackers(limit);
}

function stats() {
  const s = db.getEventStats();
  return {
    ...s,
    bufferMax: MAX_EVENTS,
  };
}

function clear() {
  db.clearEvents();
  currentSeq = 0;
}

module.exports = {
  push,
  recent,
  topAttackers,
  stats,
  clear,
  MAX_EVENTS,
};
