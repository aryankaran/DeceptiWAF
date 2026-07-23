// Express & Socket.io Application Server

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const { wafMiddleware } = require('./lib/waf');
const { rateLimitMiddleware } = require('./lib/ratelimit');
const credShield = require('./lib/credshield');
const geo = require('./lib/geo');
const eventStore = require('./lib/eventStore');
const fakeProfile = require('./lib/fakeProfile');
const db = require('./lib/db');
const config = require('./config');

// Crash resistance — log errors but keep running
process.on('unhandledRejection', (r) => console.error('[FATAL] Unhandled rejection:', r));
process.on('uncaughtException', (e) => console.error('[FATAL] Uncaught exception:', e));
process.on('SIGTERM', () => { console.log('[SHUTDOWN] SIGTERM'); process.exit(0); });

// App setup
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set('trust proxy', true); // trust X-Forwarded-For for accurate req.ip behind proxies
app.set('io', io);

// Body parsers must run before WAF & RateLimit so they can inspect req.body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimitMiddleware);
app.use(wafMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

// Load user database from JSON (passwords are SHA-256 hashed per-user)
function sha256(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }

let USERS = {};
try {
  const raw = fs.readFileSync(path.join(__dirname, config.USERS_DATA_FILE), 'utf8');
  USERS = JSON.parse(raw);
  delete USERS._comment;
  delete USERS._passwords;
  console.log(`[DATA] Loaded ${Object.keys(USERS).length} users from ${config.USERS_DATA_FILE}`);
} catch (e) {
  console.error(`[FATAL] Cannot load ${config.USERS_DATA_FILE}: ${e.message}`);
  process.exit(1);
}

// In-memory session cache backed by SQLite
const SESSIONS = {};

function issueSession(username, fakeUserProfile) {
  const token = crypto.randomBytes(24).toString('hex');
  const sess = { username, issuedAt: Date.now(), fakeUserProfile: fakeUserProfile || null };
  SESSIONS[token] = sess;
  try { db.saveSession(token, username, fakeUserProfile || null); } catch (e) {}
  return token;
}

function getTokenFromRequest(req) {
  return (req.cookies && req.cookies.deceptiwaf_session) ||
         (req.query && req.query.token) || null;
}

function getUserFromSession(req) {
  const token = getTokenFromRequest(req);
  if (!token) return null;
  let session = SESSIONS[token];
  if (!session) {
    session = db.getSession(token);
    if (session) SESSIONS[token] = session;
  }
  if (!session) return null;
  if (session.fakeUserProfile) return session.fakeUserProfile; // honeypot trap
  return USERS[session.username] || null;
}

function destroySession(req) {
  const token = getTokenFromRequest(req);
  if (token) {
    delete SESSIONS[token];
    try { db.deleteSession(token); } catch (e) {}
  }
}

function isHttps(req) {
  return req.secure || req.protocol === 'https' ||
    (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Helper: capture browser fingerprint from request headers
function captureFingerprint(req) {
  return {
    userAgent: req.get('user-agent') || '',
    acceptLanguage: req.get('accept-language') || '',
    secChUa: req.get('sec-ch-ua') || '',
    secChUaPlatform: req.get('sec-ch-ua-platform') || '',
    secChUaMobile: req.get('sec-ch-ua-mobile') || '',
    referer: req.get('referer') || '',
  };
}

// ============================================================
// Routes
// ============================================================

app.get('/', (req, res) => {
  const user = getUserFromSession(req);
  if (user) {
    const token = getTokenFromRequest(req);
    const target = user.role === 'admin' ? '/soc' : '/dashboard';
    return res.redirect(`${target}?token=${token}`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login: CredShield checks trap state before real credential check
app.post('/login', (req, res) => {
  const { studentId, password } = req.body || {};
  if (!studentId || !password) return res.redirect('/?error=missing');

  const username = String(studentId).trim().toLowerCase();
  if (username.startsWith('__')) return res.redirect('/?error=invalid'); // reserved sentinels
  const ip = req.ip;
  const io = req.app.get('io');

  // Already-trapped IP: always "succeed" with a deterministic fake profile
  if (credShield.isHoneypotActive(ip)) {
    const trapInfo = credShield.noteTrappedAttempt(ip, username);
    const profile = fakeProfile.getOrCreate(username); // same username = same fake data
    const fakeToken = issueSession('__honeypot__', profile);

    const payload = {
      kind: 'honeypot', type: 'trapped', ip, username,
      attempt: trapInfo.attempt, trapCount: trapInfo.trapCount,
      timestamp: new Date().toISOString(),
      geo: geo.lookupSync(ip),
      fakeIdentity: { name: profile.name, username: profile.username, branch: profile.branch },
      fingerprint: captureFingerprint(req),
    };
    eventStore.push(payload);
    geo.lookup(ip).then((g) => { payload.geo = g; }).catch(() => {});
    if (io) io.emit('honeypot_event', payload);

    console.log(`\x1b[35m[HONEYPOT TRAP]\x1b[0m ip=${ip} attempt=${trapInfo.attempt} claimed=${username} fake=${profile.name}`);
    const secure = isHttps(req);
    res.cookie('deceptiwaf_session', fakeToken, {
      httpOnly: true, maxAge: config.HONEYPOT_SESSION_MAX_AGE_MS,
      sameSite: secure ? 'none' : 'lax', secure, path: '/',
    });
    return res.redirect(`/dashboard?token=${fakeToken}`); // /dashboard, not /trap — deception
  }

  const user = USERS[username];

  // Record a failed login, emit events, maybe arm the honeypot
  const recordFailure = (reason) => {
    const decision = credShield.noteFailedLogin(ip, username);
    console.log(`\x1b[33m[AUTH FAIL]\x1b[0m user=${username} reason=${reason} ip=${ip} fails=${decision.attempt}/${credShield.HONEYPOT_THRESHOLD}`);

    const payload = {
      kind: 'honeypot',
      type: decision.action === 'activate' ? 'activated' : 'failed',
      ip, username,
      attempt: decision.attempt,
      threshold: credShield.HONEYPOT_THRESHOLD,
      timestamp: new Date().toISOString(),
      geo: geo.lookupSync(ip),
      fingerprint: captureFingerprint(req),
    };
    eventStore.push(payload);
    geo.lookup(ip).then((g) => { payload.geo = g; }).catch(() => {});
    if (io) io.emit('honeypot_event', payload);

    if (decision.action === 'activate') {
      console.log(`\x1b[35m[HONEYPOT ARMED]\x1b[0m ip=${ip} next login will be trapped`);
    }
  };

  if (!user) { recordFailure('no_such_user'); return res.redirect('/?error=invalid'); }

  const inputHash = sha256(password);
  const passwordOk = user.passwordHash
    ? (inputHash === user.passwordHash)
    : (password === (user.role === 'admin' ? config.ADMIN_PASSWORD : config.STUDENT_PASSWORD));
  if (!passwordOk) { recordFailure('bad_password'); return res.redirect('/?error=invalid'); }

  // Real success — clear failure history
  credShield.clear(ip);
  const token = issueSession(username);
  const secure = isHttps(req);
  res.cookie('deceptiwaf_session', token, {
    httpOnly: true, maxAge: config.SESSION_MAX_AGE_MS,
    sameSite: secure ? 'none' : 'lax', secure, path: '/',
  });
  const target = user.role === 'admin' ? '/soc' : '/dashboard';
  console.log(`[AUTH] login OK user=${username} role=${user.role} ip=${ip}`);
  return res.redirect(`${target}?token=${token}`);
});

app.post('/logout', (req, res) => {
  destroySession(req);
  res.clearCookie('deceptiwaf_session', { path: '/' });
  res.redirect('/');
});

// Current user profile (consumed by dashboard/soc/honeypot pages)
app.get('/api/me', (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user });
});

// Admin-only: CredShield management
app.get('/api/honeypot/status', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  res.json({ threshold: credShield.HONEYPOT_THRESHOLD, ttlMs: credShield.HONEYPOT_TTL_MS, tracked: credShield.snapshot() });
});

app.post('/api/honeypot/reset', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  const targetIp = req.query.ip || req.body?.ip;
  if (targetIp) {
    credShield.clear(targetIp);
    console.log(`\x1b[32m[ADMIN ACTION]\x1b[0m Honeypot trap disarmed for IP: ${targetIp}`);
    return res.json({ ok: true, reset: targetIp });
  }
  credShield.clearAll();
  console.log(`\x1b[32m[ADMIN ACTION]\x1b[0m Honeypot state disarmed & all traps cleared by admin.`);
  res.json({ ok: true, reset: 'all' });
});

// Admin-only: SOC event history + attacker catalog
app.get('/api/events/recent', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 50, 500));
  res.json({ events: eventStore.recent(limit) });
});

app.get('/api/attackers/top', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 20, 100));
  res.json({ attackers: eventStore.topAttackers(limit) });
});

app.get('/api/stats', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  res.json({
    ...eventStore.stats(),
    credshield: {
      threshold: credShield.HONEYPOT_THRESHOLD,
      ttlMs: credShield.HONEYPOT_TTL_MS,
      tracked: credShield.snapshot().length,
      active: credShield.snapshot().filter(s => s.honeypotActive).length,
    },
    geo: { cacheSize: geo.cacheSize() },
  });
});

app.post('/api/events/clear', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  eventStore.clear();
  console.log(`\x1b[32m[ADMIN ACTION]\x1b[0m SQLite database event history cleared by admin.`);
  res.json({ ok: true });
});

// Dashboard: serves real dashboard for students, fake one for trapped attackers
app.get('/dashboard', (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.redirect('/?error=auth');
  if (user.role === 'admin') {
    const token = getTokenFromRequest(req);
    return res.redirect('/soc' + (token ? '?token=' + token : ''));
  }
  if (user.role === 'honeypot') {
    console.log(`\x1b[35m[HONEYPOT]\x1b[0m serving fake dashboard  ip=${req.ip} user=${user.username}`);
    return res.sendFile(path.join(__dirname, 'public', 'honeypot.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// /trap redirects to /dashboard (keeps URL bar clean for trapped attackers)
app.get('/trap', (req, res) => {
  const user = getUserFromSession(req);
  const authorized = credShield.isHoneypotActive(req.ip) || (user && user.role === 'honeypot');
  if (!authorized) return res.redirect('/?error=auth');
  const token = getTokenFromRequest(req);
  res.redirect(`/dashboard${token ? '?token=' + token : ''}`);
});

app.get('/soc', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.redirect('/?error=auth');
  res.sendFile(path.join(__dirname, 'public', 'soc.html'));
});

app.get('/test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'test.html')));

app.get('/slides', (req, res) => res.sendFile(path.join(__dirname, 'public', 'slides.html')));

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Catch-all 404
app.use((req, res) => {
  res.status(404).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>404 - DeceptiWAF</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
<div class="text-center max-w-md">
<div class="mono text-6xl font-bold text-red-500 mb-4">404</div>
<p class="mono text-sm text-slate-400 mb-6">Route not found: ${escHtml(req.method)} ${escHtml(req.path)}</p>
<div class="space-y-2">
<a href="/" class="block bg-blue-900 hover:bg-blue-800 text-white mono text-xs py-2 rounded">Login Page</a>
<a href="/test" class="block bg-red-900 hover:bg-red-800 text-red-100 mono text-xs py-2 rounded">Attack Simulator</a>
<a href="/soc" class="block bg-green-900 hover:bg-green-800 text-green-100 mono text-xs py-2 rounded">SOC Dashboard (admin)</a>
</div></div></body></html>`);
});

// Socket.io: require admin auth before allowing event subscriptions
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  const session = SESSIONS[token];
  if (!session) return next(new Error('unauthorized: invalid token'));
  const user = session.fakeUserProfile || USERS[session.username];
  if (!user || user.role !== 'admin') return next(new Error('unauthorized: admin only'));
  socket.adminUser = user;
  next();
});

io.on('connection', (socket) => {
  console.log(`[SOC] Admin connected: ${socket.id} user=${socket.adminUser?.username}`);
  socket.on('disconnect', () => console.log(`[SOC] Admin disconnected: ${socket.id}`));
});

// Start
const PORT = config.PORT;
server.listen(PORT, config.HOST, () => {
  console.log('==================================================');
  console.log('  DeceptiWAF — Target App + SOC Dashboard');
  console.log('==================================================');
  console.log(`  Login page  : http://localhost:${PORT}/`);
  console.log(`  Dashboard   : http://localhost:${PORT}/dashboard`);
  console.log(`  SOC (admin) : http://localhost:${PORT}/soc`);
  console.log(`  Attack sim  : http://localhost:${PORT}/test`);
  console.log(`  Health      : http://localhost:${PORT}/health`);
  console.log('--------------------------------------------------');
  console.log('  Students: <username>@2024  (see data/users.json)');
  console.log('  Admin   : socadmin123');
  console.log('==================================================');
});
