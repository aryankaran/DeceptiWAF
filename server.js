/**
 * DeceptiWAF - server.js
 * ------------------------------------------------------------------
 * Phase 1: Target App Setup (CURRENT)
 *   - Express + Socket.io bootstrap
 *   - Static file serving for /public
 *   - Routes:  GET  /           -> login page
 *              POST /login      -> credential check + session cookie
 *              GET  /dashboard  -> real student dashboard (auth-guarded)
 *              GET  /api/me     -> JSON profile of current session user
 *              POST /logout     -> destroy session, redirect to /
 *              GET  /trap       -> honeypot dashboard
 *              GET  /soc        -> SOC dashboard (Phase 4 stub, admin-only)
 *   - Demo users: aryan, sucheta, isha, sweet, shaly, demo1, demo2
 *   - Admin user: admin -> redirects to /soc
 * ------------------------------------------------------------------
 */

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const { wafMiddleware } = require('./lib/waf');
const credShield = require('./lib/credshield');
const geo = require('./lib/geo');
const eventStore = require('./lib/eventStore');

// ------------------------------------------------------------------
// Crash resistance — never let the server die silently.
// The platform's preview watcher restarts `npm start` on file changes,
// but if the process exits due to an unhandled error, the preview goes
// 404 until the next file change. These handlers log + keep running.
// ------------------------------------------------------------------
process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception:', err);
  // Keep running — the platform will restart us on next file change
  // if we're in a truly broken state.
});
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] SIGTERM received, exiting gracefully');
  process.exit(0);
});

// ------------------------------------------------------------------
// App bootstrap
// ------------------------------------------------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set('trust proxy', true);
app.set('io', io); // so the WAF middleware can emit events

// Body parsers MUST run before the WAF middleware so it can inspect req.body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ------------------------------------------------------------------
// [Phase 2] WAF Middleware — global, runs before every route
// ------------------------------------------------------------------
app.use(wafMiddleware);

// Static assets (served AFTER the WAF so even static paths go through
// inspection — but the WAF skips file extensions like .ico/.css/.js)
app.use(express.static(path.join(__dirname, 'public')));

// ------------------------------------------------------------------
// Demo users — username-style IDs (Phase 1 polish)
// All student passwords: "kuce2024"   |   Admin password: "socadmin123"
// ------------------------------------------------------------------
const STUDENT_PASSWORD = 'kuce2024';
const ADMIN_PASSWORD = 'socadmin123';

const USERS = {
  aryan: {
    role: 'student',
    name: 'Aryan Verma',
    username: 'aryan',
    branch: 'B.Tech Computer Science',
    semester: 5,
    section: 'A',
    email: 'aryan.v@kuce.edu.in',
    cgpa: 8.74,
    attendance: 92,
    credits: 124,
    dues: 2500,
    courses: [
      ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4, 'A'],
      ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal',  4, 'A+'],
      ['CSE310', 'Computer Networks',            'Dr. S. Raina',    3, 'B+'],
      ['CSE312', 'Operating Systems',            'Dr. P. Bhat',     4, 'A'],
      ['HUM201', 'Technical Communication',      'Ms. F. Ansari',   2, 'A'],
    ],
  },
  sucheta: {
    role: 'student',
    name: 'Sucheta Nair',
    username: 'sucheta',
    branch: 'B.Tech Computer Science',
    semester: 5,
    section: 'A',
    email: 'sucheta.n@kuce.edu.in',
    cgpa: 9.12,
    attendance: 96,
    credits: 132,
    dues: 0,
    courses: [
      ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4, 'A+'],
      ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal',  4, 'A'],
      ['CSE310', 'Computer Networks',            'Dr. S. Raina',    3, 'A'],
      ['CSE312', 'Operating Systems',            'Dr. P. Bhat',     4, 'A+'],
      ['HUM201', 'Technical Communication',      'Ms. F. Ansari',   2, 'A'],
    ],
  },
  isha: {
    role: 'student',
    name: 'Isha Gupta',
    username: 'isha',
    branch: 'B.Tech Information Technology',
    semester: 5,
    section: 'B',
    email: 'isha.g@kuce.edu.in',
    cgpa: 8.45,
    attendance: 88,
    credits: 120,
    dues: 1500,
    courses: [
      ['IT301',  'Web Technologies',      'Dr. R. Bose',    4, 'A'],
      ['IT305',  'Cloud Computing',       'Prof. S. Das',   4, 'A'],
      ['IT310',  'Information Security',  'Dr. M. Khanna',  3, 'A+'],
      ['IT312',  'Software Engineering',  'Dr. P. Bhat',    4, 'B+'],
      ['HUM201', 'Technical Communication','Ms. F. Ansari', 2, 'A'],
    ],
  },
  sweet: {
    role: 'student',
    name: 'Sweet Patel',
    username: 'sweet',
    branch: 'B.Tech Electronics & Communication',
    semester: 5,
    section: 'B',
    email: 'sweet.p@kuce.edu.in',
    cgpa: 7.92,
    attendance: 84,
    credits: 116,
    dues: 3200,
    courses: [
      ['ECE301', 'Signals & Systems',         'Dr. R. Verma',   4, 'B+'],
      ['ECE305', 'Analog Circuits',           'Prof. K. Joshi', 4, 'B'],
      ['ECE310', 'Digital Communication',     'Dr. N. Kaul',    3, 'B+'],
      ['ECE312', 'Microprocessors',           'Dr. V. Shah',    4, 'A'],
      ['HUM201', 'Technical Communication',   'Ms. F. Ansari',  2, 'A'],
    ],
  },
  shaly: {
    role: 'student',
    name: 'Shaly Sinha',
    username: 'shaly',
    branch: 'B.Tech Computer Science',
    semester: 5,
    section: 'A',
    email: 'shaly.s@kuce.edu.in',
    cgpa: 8.88,
    attendance: 90,
    credits: 128,
    dues: 800,
    courses: [
      ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4, 'A'],
      ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal', 4, 'A'],
      ['CSE310', 'Computer Networks',            'Dr. S. Raina',   3, 'A'],
      ['CSE312', 'Operating Systems',            'Dr. P. Bhat',    4, 'A'],
      ['HUM201', 'Technical Communication',      'Ms. F. Ansari',  2, 'A+'],
    ],
  },
  demo1: {
    role: 'student',
    name: 'Demo User One',
    username: 'demo1',
    branch: 'B.Tech Computer Science',
    semester: 5,
    section: 'A',
    email: 'demo1@kuce.edu.in',
    cgpa: 8.00,
    attendance: 85,
    credits: 120,
    dues: 0,
    courses: [
      ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4, 'A'],
      ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal', 4, 'B+'],
      ['CSE310', 'Computer Networks',            'Dr. S. Raina',   3, 'A'],
      ['CSE312', 'Operating Systems',            'Dr. P. Bhat',    4, 'B'],
      ['HUM201', 'Technical Communication',      'Ms. F. Ansari',  2, 'A'],
    ],
  },
  demo2: {
    role: 'student',
    name: 'Demo User Two',
    username: 'demo2',
    branch: 'B.Tech Electronics & Communication',
    semester: 5,
    section: 'B',
    email: 'demo2@kuce.edu.in',
    cgpa: 8.20,
    attendance: 89,
    credits: 124,
    dues: 500,
    courses: [
      ['ECE301', 'Signals & Systems',         'Dr. R. Verma',   4, 'A'],
      ['ECE305', 'Analog Circuits',           'Prof. K. Joshi', 4, 'A'],
      ['ECE310', 'Digital Communication',     'Dr. N. Kaul',    3, 'B+'],
      ['ECE312', 'Microprocessors',           'Dr. V. Shah',    4, 'A'],
      ['HUM201', 'Technical Communication',   'Ms. F. Ansari',  2, 'A'],
    ],
  },
  admin: {
    role: 'admin',
    name: 'SOC Administrator',
    username: 'admin',
    email: 'soc@kuce.edu.in',
  },

  // Phase 3: sentinel "user" for honeypot-trapped attackers. Their session
  // token resolves to this object, which gets them into /trap but nowhere else.
  __honeypot__: {
    role: 'honeypot',
    name: 'Aarav Mehta',          // fake name shown if /api/me is ever called
    username: 'shaly',            // looks like a real compromised account
    branch: 'B.Tech Electronics & Communication',
    semester: 5,
    section: 'B',
    email: 'aarav.m2042@kuce.edu.in',
    cgpa: 9.12,
    attendance: 96,
    credits: 132,
    dues: 0,
    courses: [
      ['ECE301', 'Signals & Systems',         'Dr. R. Verma',   4, 'A+'],
      ['ECE305', 'Analog Circuits',           'Prof. K. Joshi', 4, 'A'],
      ['ECE310', 'Digital Communication',     'Dr. N. Kaul',    3, 'A'],
      ['ECE312', 'Microprocessors',           'Dr. V. Shah',    4, 'A'],
      ['HUM201', 'Technical Communication',   'Ms. F. Ansari',  2, 'A'],
    ],
  },
};

// ------------------------------------------------------------------
// Session store (in-memory for Phase 1)
//   sessionToken -> { username, issuedAt }
// Phase 3+ may swap this for something more robust.
// ------------------------------------------------------------------
const SESSIONS = {};

function issueSession(username) {
  const token = crypto.randomBytes(24).toString('hex');
  SESSIONS[token] = { username, issuedAt: Date.now() };
  return token;
}

function getUserFromSession(req) {
  // Session can come from either:
  //   (a) the deceptiwaf_session cookie (preferred, when cookies work), OR
  //   (b) a ?token=<...> query parameter (fallback for sandboxed iframes
  //       where cookies are blocked entirely — e.g. some preview hosts).
  let token = null;
  if (req.cookies && req.cookies.deceptiwaf_session) token = req.cookies.deceptiwaf_session;
  if (!token && req.query && req.query.token) token = req.query.token;

  if (!token || !SESSIONS[token]) return null;
  const username = SESSIONS[token].username;
  return USERS[username] || null;
}

function getTokenFromRequest(req) {
  if (req.cookies && req.cookies.deceptiwaf_session) return req.cookies.deceptiwaf_session;
  if (req.query && req.query.token) return req.query.token;
  return null;
}

function destroySession(req) {
  const token = getTokenFromRequest(req);
  if (token) delete SESSIONS[token];
}

// Detect whether the request is HTTPS (direct or behind a proxy).
// Browsers refuse to store cookies without Secure:true when the page
// is served over HTTPS — this is what caused the "session expired"
// bounce on the preview URL.
function isHttps(req) {
  return (
    req.secure === true ||
    req.protocol === 'https' ||
    (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'
  );
}

// [Phase 3] Brute-force tracker will live here:
//   const failedLogins = {};  // { ip: { count, lastAttempt, honeypotActive } }

// ------------------------------------------------------------------
// [Phase 2] WAF Middleware placeholder
// ------------------------------------------------------------------
// app.use(wafMiddleware);  // <-- will be inserted here in Phase 2

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------

// Landing page = login
app.get('/', (req, res) => {
  // If already logged in, send to the right place
  const user = getUserFromSession(req);
  if (user) {
    const token = getTokenFromRequest(req);
    const target = user.role === 'admin' ? '/soc' : '/dashboard';
    return res.redirect(`${target}?token=${token}`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login handler — Phase 3 wraps credential check with CredShield.
//
// Flow:
//   1. If this IP is already honeypot-active, ALWAYS succeed (even with
//      wrong creds) and redirect to /trap. Emit 'honeypot_event' {trapped}.
//   2. Otherwise, do the real credential check.
//   3. On real failure, call CredShield.noteFailedLogin(ip). If that
//      crosses the threshold (3 fails), activate honeypot for this IP
//      and emit 'honeypot_event' {activated}. The 4th attempt will trap.
//   4. On real success, clear the IP's failure history.
app.post('/login', (req, res) => {
  const { studentId, password } = req.body || {};
  if (!studentId || !password) return res.redirect('/?error=missing');

  const username = studentId.trim().toLowerCase();
  const ip = req.ip;
  const io = req.app.get('io');

  // ------------------------------------------------------------------
  // CredShield Phase A — already-trapped IP gets the fake "success"
  // ------------------------------------------------------------------
  if (credShield.isHoneypotActive(ip)) {
    const trapInfo = credShield.noteTrappedAttempt(ip, username);
    const fakeToken = issueSession('__honeypot__'); // sentinel session user

    // Phase 4: store + emit with geo
    const trapPayload = {
      kind: 'honeypot',
      type: 'trapped',
      ip,
      username,
      attempt: trapInfo.attempt,
      trapCount: trapInfo.trapCount,
      timestamp: new Date().toISOString(),
      geo: geo.lookupSync(ip),
    };
    eventStore.push(trapPayload);
    // Async geo refresh (in case sync returned 'pending')
    geo.lookup(ip).then((g) => { trapPayload.geo = g; }).catch(() => {});

    if (io) io.emit('honeypot_event', trapPayload);

    const magenta = '\x1b[35m', yellow = '\x1b[33m', reset = '\x1b[0m';
    console.log(
      `${magenta}[HONEYPOT TRAP]${reset} ip=${ip}  ` +
      `attempt=${trapInfo.attempt}  trapCount=${trapInfo.trapCount}  ` +
      `claimed_user=${username}  ${yellow}redirect -> /trap${reset}`
    );

    const secure = isHttps(req);
    res.cookie('deceptiwaf_session', fakeToken, {
      httpOnly: true, maxAge: 30 * 60 * 1000,
      sameSite: secure ? 'none' : 'lax', secure, path: '/',
    });

    return res.redirect(`/trap?token=${fakeToken}`);
  }

  // ------------------------------------------------------------------
  // Normal credential check
  // ------------------------------------------------------------------
  const user = USERS[username];

  // Real failure paths — count toward honeypot activation
  const recordFailure = (reason) => {
    const decision = credShield.noteFailedLogin(ip, username);
    const yellow = '\x1b[33m', magenta = '\x1b[35m', dim = '\x1b[2m', reset = '\x1b[0m';
    console.log(
      `${yellow}[AUTH FAIL]${reset} user=${username}  reason=${reason}  ` +
      `ip=${ip}  fails=${decision.attempt}/${credShield.HONEYPOT_THRESHOLD}  ${dim}(${reason})${reset}`
    );

    if (decision.action === 'activate') {
      // Just crossed the threshold — honeypot is now armed.
      console.log(`${magenta}[HONEYPOT ARMED]${reset} ip=${ip}  next attempt will be trapped`);
      const activatePayload = {
        kind: 'honeypot',
        type: 'activated',
        ip,
        attempt: decision.attempt,
        threshold: credShield.HONEYPOT_THRESHOLD,
        timestamp: new Date().toISOString(),
        geo: geo.lookupSync(ip),
      };
      eventStore.push(activatePayload);
      geo.lookup(ip).then((g) => { activatePayload.geo = g; }).catch(() => {});
      if (io) io.emit('honeypot_event', activatePayload);
    } else {
      const failedPayload = {
        kind: 'honeypot',
        type: 'failed',
        ip,
        username,
        attempt: decision.attempt,
        threshold: credShield.HONEYPOT_THRESHOLD,
        timestamp: new Date().toISOString(),
        geo: geo.lookupSync(ip),
      };
      eventStore.push(failedPayload);
      geo.lookup(ip).then((g) => { failedPayload.geo = g; }).catch(() => {});
      if (io) io.emit('honeypot_event', failedPayload);
    }
  };

  if (!user) {
    recordFailure('no_such_user');
    return res.redirect('/?error=invalid');
  }

  const expectedPassword = user.role === 'admin' ? ADMIN_PASSWORD : STUDENT_PASSWORD;
  if (password !== expectedPassword) {
    recordFailure('bad_password');
    return res.redirect('/?error=invalid');
  }

  // ------------------------------------------------------------------
  // Real success — clear failure history, issue real session
  // ------------------------------------------------------------------
  credShield.clear(ip);
  const token = issueSession(username);

  const secure = isHttps(req);
  res.cookie('deceptiwaf_session', token, {
    httpOnly: true,
    maxAge: 2 * 60 * 60 * 1000,
    sameSite: secure ? 'none' : 'lax',
    secure,
    path: '/',
  });

  const target = user.role === 'admin' ? '/soc' : '/dashboard';
  console.log(
    `[AUTH] login OK    user=${username}  role=${user.role}  ip=${req.ip}  ` +
    `proto=${req.protocol}  secure=${secure}  redirect=${target}?token=<...>`
  );

  return res.redirect(`${target}?token=${token}`);
});

// Logout
app.post('/logout', (req, res) => {
  destroySession(req);
  res.clearCookie('deceptiwaf_session', { path: '/' });
  res.redirect('/');
});

// Current session profile (consumed by dashboard.html / soc.html)
app.get('/api/me', (req, res) => {
  const user = getUserFromSession(req);
  if (!user) {
    const hasCookie = !!(req.cookies && req.cookies.deceptiwaf_session);
    const hasQueryToken = !!(req.query && req.query.token);
    console.log(
      `[AUTH] /api/me 401  ip=${req.ip}  proto=${req.protocol}  ` +
      `cookie_present=${hasCookie}  query_token_present=${hasQueryToken}`
    );
    return res.status(401).json({ error: 'unauthorized' });
  }
  return res.json({ user });
});

// ------------------------------------------------------------------
// Phase 3 admin endpoints — CredShield management (admin-only)
// ------------------------------------------------------------------

// GET /api/honeypot/status — list all tracked IPs and their state
app.get('/api/honeypot/status', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  res.json({
    threshold: credShield.HONEYPOT_THRESHOLD,
    ttlMs: credShield.HONEYPOT_TTL_MS,
    tracked: credShield.snapshot(),
  });
});

// POST /api/honeypot/reset — disarm one IP (?ip=1.2.3.4) or all IPs (no ?ip)
app.post('/api/honeypot/reset', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });

  const targetIp = req.query.ip || req.body?.ip;
  if (targetIp) {
    credShield.clear(targetIp);
    console.log(`[CREDSHIELD] admin ${user.username} reset IP ${targetIp}`);
    return res.json({ ok: true, reset: targetIp });
  } else {
    credShield.clearAll();
    console.log(`[CREDSHIELD] admin ${user.username} reset ALL IPs`);
    return res.json({ ok: true, reset: 'all' });
  }
});

// ------------------------------------------------------------------
// Phase 4 SOC endpoints — event history + attacker catalog (admin-only)
// ------------------------------------------------------------------

// GET /api/events/recent?limit=50 — recent events (WAF + honeypot) with geo
app.get('/api/events/recent', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
  res.json({ events: eventStore.recent(limit) });
});

// GET /api/attackers/top?limit=20 — top attackers by event count, with geo
app.get('/api/attackers/top', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  res.json({ attackers: eventStore.topAttackers(limit) });
});

// GET /api/stats — aggregate SOC stats
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

// POST /api/events/clear — wipe event history (admin-only)
app.post('/api/events/clear', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
  eventStore.clear();
  console.log(`[EVENTSTORE] admin ${user.username} cleared event history`);
  res.json({ ok: true });
});

// Real student dashboard — auth-guarded, students only
app.get('/dashboard', (req, res) => {
  const user = getUserFromSession(req);
  if (!user)                      return res.redirect('/?error=auth');
  if (user.role === 'admin')      return res.redirect('/soc');
  // Phase 3: honeypot-trapped attackers get redirected back to /trap
  if (user.role === 'honeypot')   return res.redirect('/trap');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Honeypot trap — Phase 3 lockdown:
//   Allow if (a) the requester's IP is honeypot-active, OR
//             (b) they hold a __honeypot__ session token.
//   Otherwise redirect to login (so attackers can't just navigate here).
app.get('/trap', (req, res) => {
  const user = getUserFromSession(req);
  const ipActive = credShield.isHoneypotActive(req.ip);
  const hasTrapSession = user && user.role === 'honeypot';

  if (!ipActive && !hasTrapSession) {
    return res.redirect('/?error=auth');
  }
  res.sendFile(path.join(__dirname, 'public', 'honeypot.html'));
});

// SOC dashboard — admin-only
app.get('/soc', (req, res) => {
  const user = getUserFromSession(req);
  if (!user || user.role !== 'admin') return res.redirect('/?error=auth');
  res.sendFile(path.join(__dirname, 'public', 'soc.html'));
});

// Attack simulator / cyber range — open access for demo purposes.
// Lets you click buttons to fire real attacks at the WAF and watch the
// SOC dashboard light up in real time.
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// ------------------------------------------------------------------
// Health check (for the preview platform to know we're alive)
// ------------------------------------------------------------------
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now(), phase: '1-3' });
});

// ------------------------------------------------------------------
// Catch-all 404 — friendly page instead of Express's default "Cannot GET /"
// ------------------------------------------------------------------
app.use((req, res) => {
  // Don't override the WAF's 403s
  if (res.statusCode === 403) return;
  res.status(404).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>404 - DeceptiWAF</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
<div class="text-center max-w-md">
<div class="mono text-6xl font-bold text-red-500 mb-4">404</div>
<p class="mono text-sm text-slate-400 mb-6">Route not found: ${req.method} ${req.path}</p>
<div class="space-y-2">
<a href="/" class="block bg-blue-900 hover:bg-blue-800 text-white mono text-xs py-2 rounded">Login Page</a>
<a href="/test" class="block bg-red-900 hover:bg-red-800 text-red-100 mono text-xs py-2 rounded">Attack Simulator</a>
<a href="/soc" class="block bg-green-900 hover:bg-green-800 text-green-100 mono text-xs py-2 rounded">SOC Dashboard (admin)</a>
</div>
</div></body></html>`);
});

// ------------------------------------------------------------------
// Socket.io wiring (Phase 4 will emit events from WAF + CredShield)
// ------------------------------------------------------------------
io.on('connection', (socket) => {
  console.log(`[SOC] Dashboard client connected: ${socket.id}`);
  socket.on('disconnect', () => {
    console.log(`[SOC] Dashboard client disconnected: ${socket.id}`);
  });
});

// ------------------------------------------------------------------
// Start server
// ------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('==================================================');
  console.log('  DeceptiWAF - Target App (Phase 1 + demo users)');
  console.log('==================================================');
  console.log(`  Login page    : http://localhost:${PORT}/`);
  console.log(`  Dashboard     : http://localhost:${PORT}/dashboard`);
  console.log(`  Honeypot trap : http://localhost:${PORT}/trap`);
  console.log(`  SOC (admin)   : http://localhost:${PORT}/soc`);
  console.log('--------------------------------------------------');
  console.log('  Demo students (password: kuce2024):');
  console.log('    aryan, sucheta, isha, sweet, shaly, demo1, demo2');
  console.log('  Admin (password: socadmin123): admin');
  console.log('==================================================');
});
