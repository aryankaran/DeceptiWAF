/**
 * DeceptiWAF — lib/eventStore.js
 * In-memory ring buffer (last 500 events) for SOC event history.
 * Indexed by IP for the attacker catalog.
 */

const MAX_EVENTS = 500;

// Newest first. We unshift on push and pop from the end.
const events = [];

// ip -> { ip, geo, firstSeen, lastSeen, totalEvents, blockedCount, trappedCount, recentEvents: [] }
const attackers = new Map();

function push(evt) {
  // Augment with a server-side sequence number
  evt.seq = (events[0]?.seq || 0) + 1;
  evt.serverTime = Date.now();

  events.unshift(evt);
  if (events.length > MAX_EVENTS) events.pop();

  // Index by IP
  if (evt.ip) {
    let a = attackers.get(evt.ip);
    if (!a) {
      a = {
        ip: evt.ip,
        geo: evt.geo || null,
        firstSeen: evt.serverTime,
        lastSeen: evt.serverTime,
        totalEvents: 0,
        blockedCount: 0,
        flaggedCount: 0,
        trappedCount: 0,
        failedCount: 0,
        lastEvent: null,
      };
      attackers.set(evt.ip, a);
    }
    a.lastSeen = evt.serverTime;
    a.totalEvents += 1;
    if (evt.geo) a.geo = evt.geo; // keep latest geo
    a.lastEvent = evt;

    if (evt.kind === 'waf' && evt.type === 'block') a.blockedCount++;
    else if (evt.kind === 'waf' && evt.type === 'flag') a.flaggedCount++;
    else if (evt.kind === 'honeypot' && evt.type === 'trapped') a.trappedCount++;
    else if (evt.kind === 'honeypot' && evt.type === 'failed') a.failedCount++;
  }
}

function recent(limit = 50) {
  return events.slice(0, limit);
}

function topAttackers(limit = 20) {
  return Array.from(attackers.values())
    .sort((a, b) => b.totalEvents - a.totalEvents)
    .slice(0, limit);
}

function stats() {
  let blocked = 0, flagged = 0, trapped = 0, failed = 0;
  for (const e of events) {
    if (e.kind === 'waf' && e.type === 'block') blocked++;
    else if (e.kind === 'waf' && e.type === 'flag') flagged++;
    else if (e.kind === 'honeypot' && e.type === 'trapped') trapped++;
    else if (e.kind === 'honeypot' && e.type === 'failed') failed++;
  }
  return {
    total: events.length,
    blocked,
    flagged,
    trapped,
    failed,
    uniqueAttackers: attackers.size,
    bufferMax: MAX_EVENTS,
  };
}

function clear() {
  events.length = 0;
  attackers.clear();
}

module.exports = {
  push,
  recent,
  topAttackers,
  stats,
  clear,
  MAX_EVENTS,
};
