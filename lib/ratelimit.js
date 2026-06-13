// Sliding-window rate limiter per IP address

const eventStore = require('./eventStore');
const geo = require('./geo');

const WINDOW_MS = 60 * 1000;      // 1 minute sliding window
const MAX_REQUESTS = 60;          // Max 60 req/min for standard endpoints
const LOGIN_MAX_REQUESTS = 15;    // Max 15 req/min for /login
const BURST_WINDOW_MS = 5 * 1000; // 5 second burst window
const BURST_MAX_REQUESTS = 20;    // Max 20 req per 5s burst

// ip -> { requests: [timestamps], loginRequests: [timestamps] }
const ipTracker = new Map();

function cleanStaleTimestamps(timestamps, windowMs, now) {
  const cutoff = now - windowMs;
  return timestamps.filter((t) => t > cutoff);
}

function checkRateLimit(ip, isLogin = false) {
  const now = Date.now();
  let record = ipTracker.get(ip);
  if (!record) {
    record = { requests: [], loginRequests: [] };
    ipTracker.set(ip, record);
  }

  // Clean stale requests
  record.requests = cleanStaleTimestamps(record.requests, WINDOW_MS, now);
  record.loginRequests = cleanStaleTimestamps(record.loginRequests, WINDOW_MS, now);

  // Burst check (last 5 seconds)
  const recentBurst = record.requests.filter((t) => t > now - BURST_WINDOW_MS).length;
  if (recentBurst >= BURST_MAX_REQUESTS) {
    return {
      limited: true,
      reason: 'burst_exceeded',
      count: recentBurst,
      limit: BURST_MAX_REQUESTS,
      resetMs: 5000,
    };
  }

  // Login specific limit
  if (isLogin) {
    record.loginRequests.push(now);
    if (record.loginRequests.length > LOGIN_MAX_REQUESTS) {
      return {
        limited: true,
        reason: 'login_flood',
        count: record.loginRequests.length,
        limit: LOGIN_MAX_REQUESTS,
        resetMs: WINDOW_MS,
      };
    }
  }

  // General request limit
  record.requests.push(now);
  if (record.requests.length > MAX_REQUESTS) {
    return {
      limited: true,
      reason: 'rate_exceeded',
      count: record.requests.length,
      limit: MAX_REQUESTS,
      resetMs: WINDOW_MS,
    };
  }

  return {
    limited: false,
    count: record.requests.length,
    remaining: MAX_REQUESTS - record.requests.length,
    resetMs: WINDOW_MS,
  };
}

function rateLimitMiddleware(req, res, next) {
  // Allow disabling rate limiting via config.js (ENABLE_RATE_LIMIT: false) or ?noratelimit=1
  const config = require('../config');
  if (!config.ENABLE_RATE_LIMIT || req.query.noratelimit === '1') {
    return next();
  }

  // Skip static assets
  if (req.path.match(/\.(ico|png|jpg|jpeg|gif|css|js|map)$/i)) {
    return next();
  }

  const ip = req.ip || '127.0.0.1';
  const isLogin = req.path === '/login' && req.method === 'POST';
  const result = checkRateLimit(ip, isLogin);

  if (result.limited) {
    const io = req.app.get('io');
    const payload = {
      kind: 'ratelimit',
      type: 'block',
      attackType: result.reason === 'login_flood' ? 'Login Brute/Flood' : 'Rate Limit Exceeded',
      score: 5,
      threshold: 4,
      ip,
      method: req.method,
      path: req.path,
      reason: result.reason,
      count: result.count,
      limit: result.limit,
      timestamp: new Date().toISOString(),
      geo: geo.lookupSync(ip),
    };

    eventStore.push(payload);
    geo.lookup(ip).then((g) => { payload.geo = g; }).catch(() => {});
    if (io) io.emit('waf_event', payload);

    console.log(`\x1b[31m[RATE LIMIT BLOCK]\x1b[0m ip=${ip} reason=${result.reason} count=${result.count}/${result.limit} path=${req.path}`);

    res.set('Retry-After', Math.ceil(result.resetMs / 1000));
    res.set('X-RateLimit-Limit', result.limit);
    res.set('X-RateLimit-Remaining', 0);

    return res.status(429).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>429 Too Many Requests - DeceptiWAF</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Inter', system-ui, sans-serif; background: #020617; }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 text-slate-100">
  <div class="w-full max-w-md bg-slate-900/80 border border-amber-900/50 rounded-2xl shadow-2xl p-6 text-center space-y-4">
    <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-950/80 text-amber-400 border border-amber-500/30 mono font-bold text-lg">
      429
    </div>
    <h1 class="mono text-lg font-bold text-amber-400">TOO MANY REQUESTS</h1>
    <p class="text-xs text-slate-400 leading-relaxed">
      Rate limit triggered for IP <span class="mono text-amber-300">${ip}</span>. Reason: <span class="mono text-fuchsia-400">${result.reason}</span> (${result.count}/${result.limit} requests).
    </p>
    <div class="bg-slate-950/80 border border-slate-800 rounded-lg p-3 mono text-xs text-slate-400">
      Please wait <span class="text-amber-400 font-bold">${Math.ceil(result.resetMs / 1000)} seconds</span> before retrying.
    </div>
    <a href="/" class="block bg-slate-800 hover:bg-slate-700 text-slate-200 mono text-xs py-2.5 rounded-lg transition">RETURN TO PORTAL</a>
  </div>
</body>
</html>`);
  }

  return next();
}

function snapshot() {
  const out = [];
  for (const [ip, rec] of ipTracker.entries()) {
    out.push({
      ip,
      reqCount: rec.requests.length,
      loginCount: rec.loginRequests.length,
    });
  }
  return out;
}

module.exports = {
  checkRateLimit,
  rateLimitMiddleware,
  snapshot,
};
