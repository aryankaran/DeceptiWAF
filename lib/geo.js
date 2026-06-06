/**
 * DeceptiWAF — lib/geo.js
 * IP geolocation via ip-api.com (free, HTTP-only, ~45 req/min).
 * Results cached for 1 hour. Private IPs return "Local Network".
 */

const http = require('http');

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const cache = new Map(); // ip -> { data, fetchedAt }

// Private IP ranges — these can't be geolocated
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  // Strip IPv6-mapped IPv4 prefix
  const v4 = ip.replace(/^::ffff:/, '');
  if (v4 === '::1' || v4 === '127.0.0.1') return true;
  if (v4.startsWith('10.')) return true;
  if (v4.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v4)) return true;
  if (v4.startsWith('169.254.')) return true;  // link-local
  if (v4.startsWith('fc') || v4.startsWith('fd')) return true; // IPv6 ULA
  if (v4.startsWith('fe80')) return true; // IPv6 link-local
  return false;
}

const LOCAL_RECORD = {
  country: 'Local Network',
  countryCode: 'LO',
  city: 'Internal',
  region: '—',
  lat: 0,
  lon: 0,
  isp: '—',
  org: 'Local Lab',
  source: 'local',
};

const UNKNOWN_RECORD = {
  country: 'Unknown',
  countryCode: '??',
  city: '—',
  region: '—',
  lat: 0,
  lon: 0,
  isp: '—',
  org: '—',
  source: 'fallback',
};

/**
 * Look up geo info for an IP. Returns a Promise resolving to the record.
 * Never throws — on any failure, returns UNKNOWN_RECORD.
 */
function lookup(ip) {
  return new Promise((resolve) => {
    if (!ip) return resolve({ ...UNKNOWN_RECORD, ip });

    // Private IP shortcut
    if (isPrivateIp(ip)) return resolve({ ...LOCAL_RECORD, ip });

    // Cache hit?
    const cached = cache.get(ip);
    if (cached && (Date.now() - cached.fetchedAt < CACHE_TTL_MS)) {
      return resolve({ ...cached.data, ip, source: 'cache' });
    }

    // ip-api.com free endpoint — JSON over HTTP (free tier is HTTP-only).
    // Fields: status,country,countryCode,region,regionName,city,lat,lon,isp,org,query
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,query`;

    const req = http.get(url, { timeout: 4000 }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          const j = JSON.parse(body);
          if (j.status !== 'success') {
            return resolve({ ...UNKNOWN_RECORD, ip });
          }
          const data = {
            country: j.country || 'Unknown',
            countryCode: j.countryCode || '??',
            city: j.city || '—',
            region: j.regionName || '—',
            lat: j.lat || 0,
            lon: j.lon || 0,
            isp: j.isp || '—',
            org: j.org || '—',
            source: 'ip-api.com',
          };
          cache.set(ip, { data, fetchedAt: Date.now() });
          resolve({ ...data, ip });
        } catch (e) {
          resolve({ ...UNKNOWN_RECORD, ip });
        }
      });
    });

    req.on('error', () => resolve({ ...UNKNOWN_RECORD, ip }));
    req.on('timeout', () => { req.destroy(); resolve({ ...UNKNOWN_RECORD, ip }); });
  });
}

/**
 * Synchronous best-effort lookup — returns cached data immediately, or
 * a placeholder if not cached. Useful for inline rendering where you
 * can't await. Triggers a background refresh if stale.
 */
function lookupSync(ip) {
  if (!ip || isPrivateIp(ip)) return { ...LOCAL_RECORD, ip };
  const cached = cache.get(ip);
  // Check TTL — if stale, return 'pending' and trigger background refresh
  if (cached && (Date.now() - cached.fetchedAt < CACHE_TTL_MS)) {
    return { ...cached.data, ip, source: 'cache' };
  }
  // Stale or not cached — trigger background lookup if not already in progress
  if (cached) {
    // Stale cache — trigger background refresh (fire-and-forget)
    // but still return the stale data so the UI has something to show
    lookup(ip).catch(() => {});
    return { ...cached.data, ip, source: 'cache' };
  }
  return { ...UNKNOWN_RECORD, ip, source: 'pending' };
}

function cacheSize() { return cache.size; }
function clearCache() { cache.clear(); }

module.exports = {
  lookup,
  lookupSync,
  isPrivateIp,
  cacheSize,
  clearCache,
};
