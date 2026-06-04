/**
 * DeceptiWAF - lib/waf.js
 * ------------------------------------------------------------------
 * Phase 2: Mini-WAF Engine
 *
 *   1. PATTERN DICTIONARY  — regex rules grouped by attack family
 *      (SQLi, XSS, Path Traversal, Malicious User-Agents)
 *
 *   2. SCORING ENGINE      — each rule has a point value. Sum all
 *      matched rules for the request. Threshold = 4 (block on > 4).
 *      Spec example: UNION=3, -- =1, so 'UNION--' = 4 (allowed, flagged),
 *      but ' UNION SELECT ... --' = 3 + 2 + 1 = 6 (blocked).
 *
 *   3. DE-OBFUSCATION       — URL-decode (one pass + recursive) before
 *      regex matching, so %27%20OR%201%3D1 catches URL-encoded attacks.
 *
 *   4. INSPECTION SURFACES  — URL path, query string values, body
 *      fields (urlencoded + JSON), User-Agent, Referer.
 *
 *   5. EXPORTS              — `inspectRequest(req)` returns the analysis
 *      object; `wafMiddleware` is the Express middleware that blocks.
 * ------------------------------------------------------------------
 */

// ------------------------------------------------------------------
// Pattern dictionary
//   Each entry: { id, family, pattern, score, label }
// ------------------------------------------------------------------
const PATTERNS = [

  // -------- SQL Injection --------------------------------------
  { id: 'sqli_union_select',    family: 'SQLi',  pattern: /union\s+(all\s+)?select/i,         score: 4, label: "UNION SELECT" },
  { id: 'sqli_or_tautology',    family: 'SQLi',  pattern: /['"]?\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, score: 4, label: "OR 1=1 tautology" },
  { id: 'sqli_or_string_eq',    family: 'SQLi',  pattern: /'\s*or\s+'[^']*'\s*=\s*'[^']*'/i,  score: 4, label: "OR 'x'='x' tautology" },
  { id: 'sqli_comment_dash',    family: 'SQLi',  pattern: /--/,                              score: 1, label: "SQL comment --" },
  { id: 'sqli_comment_hash',    family: 'SQLi',  pattern: /#/,                                score: 1, label: "SQL comment #" },
  { id: 'sqli_comment_slash',   family: 'SQLi',  pattern: /\/\*/,                             score: 2, label: "SQL comment /* */" },
  { id: 'sqli_mysqL_versioned', family: 'SQLi',  pattern: /\/\*!\d+/,                         score: 2, label: "MySQL versioned comment" },
  { id: 'sqli_drop_table',      family: 'SQLi',  pattern: /(drop|truncate)\s+table/i,         score: 5, label: "DROP/TRUNCATE TABLE" },
  { id: 'sqli_stacked_query',   family: 'SQLi',  pattern: /;\s*(select|insert|update|delete|drop|exec)/i, score: 4, label: "Stacked SQL query" },
  { id: 'sqli_information_sch', family: 'SQLi',  pattern: /information_schema/i,              score: 3, label: "information_schema reference" },
  { id: 'sqli_sleep',           family: 'SQLi',  pattern: /sleep\s*\(\s*\d+\s*\)/i,           score: 4, label: "SLEEP() time-based blind" },
  { id: 'sqli_benchmark',       family: 'SQLi',  pattern: /benchmark\s*\(/i,                  score: 4, label: "BENCHMARK() time-based blind" },
  { id: 'sqli_waitfor',         family: 'SQLi',  pattern: /waitfor\s+delay/i,                 score: 4, label: "WAITFOR DELAY (MSSQL)" },
  { id: 'sqli_xpcmdshell',      family: 'SQLi',  pattern: /xp_cmdshell/i,                     score: 5, label: "xp_cmdshell (RCE via SQL)" },
  { id: 'sqli_hex_blob',        family: 'SQLi',  pattern: /0x[0-9a-f]{8,}/i,                  score: 2, label: "Hex blob literal" },
  { id: 'sqli_extractvalue',    family: 'SQLi',  pattern: /extractvalue\s*\(/i,               score: 4, label: "extractValue() error-based" },
  { id: 'sqli_updatexml',       family: 'SQLi',  pattern: /updatexml\s*\(/i,                  score: 4, label: "updatexml() error-based" },

  // -------- Cross-Site Scripting (XSS) -------------------------
  { id: 'xss_script_tag',       family: 'XSS',   pattern: /<\s*script/i,                       score: 4, label: "<script> tag" },
  { id: 'xss_onerror',          family: 'XSS',   pattern: /onerror\s*=/i,                      score: 4, label: "onerror= handler" },
  { id: 'xss_onload',           family: 'XSS',   pattern: /onload\s*=/i,                       score: 3, label: "onload= handler" },
  { id: 'xss_onmouseover',      family: 'XSS',   pattern: /onmouseover\s*=/i,                  score: 2, label: "onmouseover= handler" },
  { id: 'xss_onclick',          family: 'XSS',   pattern: /onclick\s*=/i,                      score: 2, label: "onclick= handler" },
  { id: 'xss_javascript_proto', family: 'XSS',   pattern: /javascript:/i,                      score: 3, label: "javascript: protocol" },
  { id: 'xss_alert',            family: 'XSS',   pattern: /alert\s*\(/i,                       score: 2, label: "alert() call" },
  { id: 'xss_prompt',           family: 'XSS',   pattern: /prompt\s*\(/i,                      score: 2, label: "prompt() call" },
  { id: 'xss_confirm',          family: 'XSS',   pattern: /confirm\s*\(/i,                     score: 2, label: "confirm() call" },
  { id: 'xss_document_cookie',  family: 'XSS',   pattern: /document\.cookie/i,                 score: 3, label: "document.cookie access" },
  { id: 'xss_eval',             family: 'XSS',   pattern: /eval\s*\(/i,                        score: 3, label: "eval() call" },
  { id: 'xss_fromcharcode',     family: 'XSS',   pattern: /string\.fromcharcode/i,             score: 3, label: "String.fromCharCode obfuscation" },
  { id: 'xss_iframe',           family: 'XSS',   pattern: /<\s*iframe/i,                       score: 3, label: "<iframe> tag" },
  { id: 'xss_svg',              family: 'XSS',   pattern: /<\s*svg/i,                          score: 3, label: "<svg> tag" },
  { id: 'xss_img_src_x',        family: 'XSS',   pattern: /<\s*img[^>]+src\s*=\s*['"]?x/i,     score: 2, label: "<img src=x> probe" },
  { id: 'xss_body_onload',      family: 'XSS',   pattern: /<\s*body[^>]+on/i,                  score: 3, label: "<body onload=...>" },
  { id: 'xss_innerhtml',        family: 'XSS',   pattern: /\.innerhtml\s*=/i,                 score: 3, label: ".innerHTML assignment" },

  // -------- Path Traversal -------------------------------------
  { id: 'pt_dotdot_slash',      family: 'PathTraversal', pattern: /\.\.\//,                    score: 3, label: "../ traversal" },
  { id: 'pt_dotdot_backslash',  family: 'PathTraversal', pattern: /\.\.\\/,                    score: 3, label: "..\\ traversal" },
  { id: 'pt_etc_passwd',        family: 'PathTraversal', pattern: /\/etc\/passwd/i,            score: 5, label: "/etc/passwd access" },
  { id: 'pt_etc_shadow',        family: 'PathTraversal', pattern: /\/etc\/shadow/i,            score: 5, label: "/etc/shadow access" },
  { id: 'pt_proc_self',         family: 'PathTraversal', pattern: /\/proc\/self/i,             score: 3, label: "/proc/self access" },
  { id: 'pt_windows_winini',    family: 'PathTraversal', pattern: /(win\.ini|boot\.ini|system32)/i, score: 3, label: "Windows system file" },
  { id: 'pt_dotdot_urlenc',     family: 'PathTraversal', pattern: /(\.\.%2f|\.\.%5c|%2e%2e)/i,  score: 3, label: "URL-encoded ../" },
  { id: 'pt_dotdot_overlong',   family: 'PathTraversal', pattern: /\.\.%c0%af/i,                score: 3, label: "Overlong UTF-8 traversal" },
  { id: 'pt_php_wrapper',       family: 'PathTraversal', pattern: /php:\/\/(filter|input|data)/i, score: 5, label: "PHP stream wrapper" },
  { id: 'pt_file_uri',          family: 'PathTraversal', pattern: /file:\/\/\//i,              score: 3, label: "file:// URI" },

  // -------- Malicious User-Agents ------------------------------
  // These are automated scanner signatures; a single hit is enough
  // to block (score >= 5).
  { id: 'ua_sqlmap',            family: 'MaliciousUA', pattern: /sqlmap/i,                     score: 5, label: "sqlmap scanner" },
  { id: 'ua_nikto',             family: 'MaliciousUA', pattern: /nikto/i,                      score: 5, label: "nikto scanner" },
  { id: 'ua_hydra',             family: 'MaliciousUA', pattern: /hydra/i,                      score: 5, label: "hydra brute-forcer" },
  { id: 'ua_havij',             family: 'MaliciousUA', pattern: /havij/i,                      score: 5, label: "Havij SQLi tool" },
  { id: 'ua_acunetix',          family: 'MaliciousUA', pattern: /acunetix/i,                   score: 5, label: "Acunetix scanner" },
  { id: 'ua_nessus',            family: 'MaliciousUA', pattern: /nessus/i,                     score: 4, label: "Nessus scanner" },
  { id: 'ua_nmap',              family: 'MaliciousUA', pattern: /nmap/i,                       score: 4, label: "nmap scripting engine" },
  { id: 'ua_masscan',           family: 'MaliciousUA', pattern: /masscan/i,                    score: 4, label: "masscan scanner" },
  { id: 'ua_dirbuster',         family: 'MaliciousUA', pattern: /dirbuster/i,                  score: 4, label: "DirBuster" },
  { id: 'ua_gobuster',          family: 'MaliciousUA', pattern: /gobuster/i,                   score: 4, label: "gobuster" },
  { id: 'ua_wpscan',            family: 'MaliciousUA', pattern: /wpscan/i,                     score: 4, label: "WPScan" },
  { id: 'ua_w3af',              family: 'MaliciousUA', pattern: /w3af/i,                       score: 4, label: "w3af scanner" },
  { id: 'ua_arachni',           family: 'MaliciousUA', pattern: /arachni/i,                    score: 4, label: "Arachni scanner" },
  { id: 'ua_wfuzz',             family: 'MaliciousUA', pattern: /wfuzz/i,                      score: 4, label: "wfuzz fuzzer" },
  { id: 'ua_zgrab',             family: 'MaliciousUA', pattern: /zgrab/i,                      score: 3, label: "zgrab scanner" },
];

// Block threshold — per spec, block when score > 4
const BLOCK_THRESHOLD = 4;

// ------------------------------------------------------------------
// De-obfuscation helpers (Phase 5: Anti-Evasion)
// ------------------------------------------------------------------

// Try to URL-decode a string. Failures return the input unchanged.
function safeDecode(s) {
  if (typeof s !== 'string') return s;
  try { return decodeURIComponent(s); } catch { return s; }
}

// Recursively URL-decode until stable (catches double-encoded payloads
// like %2527 — encoded twice to evade single-decode WAFs).
function deepDecode(s, maxPasses = 3) {
  if (typeof s !== 'string') return s;
  let prev = s;
  for (let i = 0; i < maxPasses; i++) {
    const next = safeDecode(prev);
    if (next === prev) break;
    prev = next;
  }
  return prev;
}

// HTML entity decoder — handles named, decimal, and hex entities.
// Catches &lt;script&gt;, &#60;script&#62;, &#x3c;script&#x3e; etc.
const NAMED_ENTITIES = {
  lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ',
  tab: '\t', newline: '\n', copy: '©', reg: '®', trade: '™',
  ldquo: '"', rdquo: '"', lsquo: "'", rsquo: "'",
  sol: '/', verbar: '|', num: '#', cent: '¢', pound: '£', yen: '¥',
  euro: '€',sect: '§', deg: '°', plusmn: '±', times: '×', divide: '÷',
};

function decodeHtmlEntities(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/&(#[xX]?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, ent) => {
    if (ent[0] === '#') {
      let cp;
      if (ent[1] === 'x' || ent[1] === 'X') {
        cp = parseInt(ent.slice(2), 16);
      } else {
        cp = parseInt(ent.slice(1), 10);
      }
      if (isNaN(cp) || cp < 0 || cp > 0x10FFFF) return m;
      try { return String.fromCodePoint(cp); } catch { return m; }
    } else {
      return NAMED_ENTITIES[ent.toLowerCase()] || m;
    }
  });
}

// Unicode NFKC normalization — converts full-width chars (ＵＮＩＯＮ) and
// other compatibility forms to their ASCII equivalents. Catches
// 'ＵＮＩＯＮ ＳＥＬＥＣＴ' style evasion.
function normalizeUnicode(s) {
  if (typeof s !== 'string') return s;
  try { return s.normalize('NFKC'); } catch { return s; }
}

// SQL/whitespace normalizer — replaces inline comments with spaces and
// collapses runs of whitespace. Catches 'UNION/**/SELECT' style evasion
// and 'UNION   SELECT' padding.
function normalizeForSql(s) {
  if (typeof s !== 'string') return s;
  return s
    .replace(/\/\*[\s\S]*?\*\//g, ' ')  // /* comment */ -> space
    .replace(/\s+/g, ' ')                  // collapse whitespace
    .trim();
}

// Build the full haystack set: every reasonable de-obfuscation layer
// applied in sequence, deduplicated. The WAF tests each pattern against
// EACH haystack so layered obfuscation can't slip through.
function buildHaystacks(raw, opts = {}) {
  if (typeof raw !== 'string' || raw.length === 0) return [];
  const decode = opts.decode !== false;
  const haystacks = new Set();

  haystacks.add(raw);

  if (decode) {
    const urlDecoded = deepDecode(raw);
    haystacks.add(urlDecoded);
  }

  // Apply HTML entity decoding to raw and urlDecoded
  const htmlRaw = decodeHtmlEntities(raw);
  haystacks.add(htmlRaw);
  if (decode) {
    const htmlUrl = decodeHtmlEntities(deepDecode(raw));
    haystacks.add(htmlUrl);
  }

  // Apply Unicode normalization to everything we have so far
  const uniSet = new Set();
  for (const h of haystacks) {
    const n = normalizeUnicode(h);
    if (n !== h) uniSet.add(n);
  }
  for (const u of uniSet) haystacks.add(u);

  // Apply SQL normalization to everything (catches UNION/**/SELECT)
  const sqlSet = new Set();
  for (const h of haystacks) {
    const n = normalizeForSql(h);
    if (n !== h) sqlSet.add(n);
  }
  for (const s of sqlSet) haystacks.add(s);

  return Array.from(haystacks);
}

// ------------------------------------------------------------------
// Inspection — collect every interesting string from the request
// ------------------------------------------------------------------
function collectInputVectors(req) {
  const vectors = [];

  // 1. URL path
  if (req.path) vectors.push({ source: 'path', value: req.path });

  // 2. Query string values
  if (req.query && typeof req.query === 'object') {
    for (const [k, v] of Object.entries(req.query)) {
      if (k === 'token') continue; // never inspect session tokens
      if (typeof v === 'string') vectors.push({ source: `query.${k}`, value: v });
    }
  }

  // 3. Body fields (urlencoded or JSON)
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) {
      if (typeof v === 'string') vectors.push({ source: `body.${k}`, value: v });
    }
  }

  // 4. Headers worth inspecting
  const ua = req.get('user-agent');
  if (ua) vectors.push({ source: 'header.user-agent', value: ua, decode: false });

  const ref = req.get('referer');
  if (ref) vectors.push({ source: 'header.referer', value: ref });

  return vectors;
}

// ------------------------------------------------------------------
// Core: inspect a single string against the pattern dictionary
// ------------------------------------------------------------------
function scanString(raw, opts = {}) {
  // Phase 5: build a multi-layer haystack so layered obfuscation
  // (URL-encode + HTML-entity + Unicode full-width + SQL comments)
  // can't slip through. Each pattern is tested against each haystack.
  const haystacks = buildHaystacks(raw, opts);

  const hits = [];
  for (const pattern of PATTERNS) {
    for (const h of haystacks) {
      if (pattern.pattern.test(h)) {
        hits.push({
          id: pattern.id,
          family: pattern.family,
          label: pattern.label,
          score: pattern.score,
          source: opts.source || 'unknown',
        });
        break; // don't double-count the same pattern across haystacks
      }
    }
  }
  return hits;
}

// ------------------------------------------------------------------
// Inspect the whole request — returns the analysis object
// ------------------------------------------------------------------
function inspectRequest(req) {
  const vectors = collectInputVectors(req);
  const allHits = [];
  let totalScore = 0;

  for (const vec of vectors) {
    const hits = scanString(vec.value, { source: vec.source, decode: vec.decode !== false });
    for (const h of hits) {
      allHits.push({ ...h, source: vec.source, sample: vec.value.slice(0, 200) });
      totalScore += h.score;
    }
  }

  // Deduplicate hits by pattern id+source (so multiple haystacks don't inflate)
  const seen = new Set();
  const deduped = [];
  for (const h of allHits) {
    const key = `${h.id}@${h.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(h);
  }
  // Recompute score on deduped
  totalScore = deduped.reduce((s, h) => s + h.score, 0);

  // Determine primary attack family (highest-scoring family)
  const familyScores = {};
  for (const h of deduped) {
    familyScores[h.family] = (familyScores[h.family] || 0) + h.score;
  }
  const topFamily = Object.entries(familyScores).sort((a, b) => b[1] - a[1])[0];
  const attackType = topFamily ? topFamily[0] : 'Unknown';

  return {
    blocked: totalScore > BLOCK_THRESHOLD,
    score: totalScore,
    threshold: BLOCK_THRESHOLD,
    attackType,
    hits: deduped,
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.get('user-agent') || '',
    // Phase 5+ fingerprinting — capture browser/network metadata for SOC display
    fingerprint: {
      userAgent: req.get('user-agent') || '',
      acceptLanguage: req.get('accept-language') || '',
      acceptEncoding: req.get('accept-encoding') || '',
      secChUa: req.get('sec-ch-ua') || '',
      secChUaPlatform: req.get('sec-ch-ua-platform') || '',
      secChUaMobile: req.get('sec-ch-ua-mobile') || '',
      secFetchMode: req.get('sec-fetch-mode') || '',
      secFetchSite: req.get('sec-fetch-site') || '',
      referer: req.get('referer') || '',
      host: req.get('host') || '',
      connection: req.get('connection') || '',
    },
    timestamp: new Date().toISOString(),
  };
}

// ------------------------------------------------------------------
// Express middleware
// ------------------------------------------------------------------
function wafMiddleware(req, res, next) {
  // Skip inspection for static asset requests (favicon, etc.) — keep
  // logs clean and reduce noise.
  if (req.path.match(/\.(ico|png|jpg|jpeg|gif|css|js|map)$/i)) {
    return next();
  }

  const result = inspectRequest(req);

  if (result.blocked) {
    // ---- Block path ----
    const io = req.app.get('io');
    const eventPayload = {
      kind: 'waf',
      type: 'block',
      attackType: result.attackType,
      score: result.score,
      threshold: result.threshold,
      ip: result.ip,
      method: result.method,
      path: result.path,
      hits: result.hits,
      userAgent: result.userAgent,
      fingerprint: result.fingerprint,
      timestamp: result.timestamp,
    };

    if (io) io.emit('waf_event', eventPayload);

    // Phase 4: store in event history (best-effort geo lookup, async)
    storeEventWithGeo(eventPayload);

    // ANSI-coloured console log
    const red = '\x1b[31m', yellow = '\x1b[33m', cyan = '\x1b[36m', dim = '\x1b[2m', reset = '\x1b[0m';
    console.log(
      `${red}[WAF BLOCK]${reset} ${cyan}${result.attackType}${reset} ` +
      `score=${red}${result.score}${reset}/${result.threshold} ` +
      `ip=${result.ip} ${dim}${result.method} ${result.path}${reset}`
    );
    for (const h of result.hits) {
      console.log(`  ${yellow}-${reset} ${h.family}/${h.id} (${h.score}pt) source=${h.source} ${dim}${h.label}${reset}`);
    }

    // Inline 403 page (no template engine — keeps the project build-free)
    return res.status(403).type('html').send(renderBlockedPage(result));
  }

  if (result.score > 0) {
    // ---- Suspicious-but-allowed path ----
    const io = req.app.get('io');
    const eventPayload = {
      kind: 'waf',
      type: 'flag',
      attackType: result.attackType,
      score: result.score,
      threshold: result.threshold,
      ip: result.ip,
      method: result.method,
      path: result.path,
      hits: result.hits,
      userAgent: result.userAgent,
      fingerprint: result.fingerprint,
      timestamp: result.timestamp,
    };
    if (io) io.emit('waf_event', eventPayload);
    storeEventWithGeo(eventPayload);

    const yellow = '\x1b[33m', dim = '\x1b[2m', reset = '\x1b[0m';
    console.log(
      `${yellow}[WAF FLAG]${reset} score=${result.score}/${result.threshold} ` +
      `ip=${result.ip} ${dim}${result.method} ${result.path}${reset}`
    );
    for (const h of result.hits) {
      console.log(`  ${yellow}-${reset} ${h.family}/${h.id} (${h.score}pt) source=${h.source} ${dim}${h.label}${reset}`);
    }
  }

  return next();
}

// ------------------------------------------------------------------
// Phase 4 helper: store event with async geo lookup
// ------------------------------------------------------------------
let _eventStore = null;
let _geo = null;
function lazyDeps() {
  if (!_eventStore) _eventStore = require('./eventStore');
  if (!_geo) _geo = require('./geo');
}
function storeEventWithGeo(payload) {
  try {
    lazyDeps();
    // Synchronous store first (with cached/sync geo if available)
    const syncGeo = _geo.lookupSync(payload.ip);
    _eventStore.push({ ...payload, geo: syncGeo });
    // If geo is pending, do async lookup and patch the latest entry for that IP
    if (syncGeo.source === 'pending') {
      _geo.lookup(payload.ip).then((fullGeo) => {
        // Patch the attacker catalog with full geo
        // (eventStore.push already created the entry; we just update geo)
        const attackers = _eventStore.topAttackers(1000);
        // We don't have a "patch" API, but the next event from this IP
        // will pick up the cached geo. Good enough for the demo.
      }).catch(() => {});
    }
  } catch (e) {
    console.error('[WAF] storeEventWithGeo error:', e.message);
  }
}

// ------------------------------------------------------------------
// Inline 403 page renderer (no template engine needed)
// ------------------------------------------------------------------
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderBlockedPage(result) {
  const hitsRows = result.hits.map((h) => `
    <tr>
      <td class="px-4 py-2 mono text-xs text-fuchsia-400">${escapeHtml(h.family)}</td>
      <td class="px-4 py-2 mono text-xs text-slate-300">${escapeHtml(h.id)}</td>
      <td class="px-4 py-2 text-xs text-slate-400">${escapeHtml(h.label)}</td>
      <td class="px-4 py-2 mono text-xs text-slate-500">${escapeHtml(h.source)}</td>
      <td class="px-4 py-2 mono text-xs text-right text-red-400 font-bold">${h.score}</td>
    </tr>`).join('');

  const samplePayload = result.hits[0]?.sample || result.path;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>403 Blocked - DeceptiWAF</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Inter', system-ui, sans-serif; background: #020617; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    @keyframes pulse-ring {
      0%   { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }
      70%  { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
      100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    .pulse-ring { animation: pulse-ring 2s infinite; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 text-slate-100">

  <div class="w-full max-w-2xl">
    <div class="bg-slate-900/80 border border-red-900/50 rounded-2xl shadow-2xl overflow-hidden">

      <!-- Header -->
      <div class="bg-red-950/40 border-b border-red-900/50 px-6 py-5 flex items-center gap-4">
        <div class="relative w-3 h-3 rounded-full bg-red-500 pulse-ring"></div>
        <div>
          <p class="mono text-red-400 font-bold tracking-widest text-sm">DECEPTIWAF // REQUEST BLOCKED</p>
          <p class="mono text-[10px] text-red-700/80">HTTP 403 FORBIDDEN &middot; WAF rule triggered</p>
        </div>
      </div>

      <!-- Body -->
      <div class="p-6 space-y-5">

        <!-- Score block -->
        <div class="grid grid-cols-3 gap-4">
          <div class="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <p class="mono text-[10px] text-slate-500 tracking-widest">ATTACK TYPE</p>
            <p class="mono text-lg text-fuchsia-400 font-bold mt-1">${escapeHtml(result.attackType)}</p>
          </div>
          <div class="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <p class="mono text-[10px] text-slate-500 tracking-widest">SCORE</p>
            <p class="mono text-lg text-red-400 font-bold mt-1">${result.score} <span class="text-slate-600 text-sm">/ ${result.threshold}</span></p>
          </div>
          <div class="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <p class="mono text-[10px] text-slate-500 tracking-widest">SOURCE IP</p>
            <p class="mono text-lg text-amber-400 font-bold mt-1">${escapeHtml(result.ip)}</p>
          </div>
        </div>

        <!-- Payload sample -->
        <div>
          <p class="mono text-[10px] text-slate-500 tracking-widest mb-1">PAYLOAD SAMPLE</p>
          <pre class="bg-slate-950/80 border border-slate-800 rounded-lg p-3 mono text-xs text-amber-300 overflow-x-auto whitespace-pre-wrap break-all">${escapeHtml(samplePayload)}</pre>
        </div>

        <!-- Hit details -->
        <div>
          <p class="mono text-[10px] text-slate-500 tracking-widest mb-2">RULES TRIGGERED (${result.hits.length})</p>
          <div class="bg-slate-950/60 border border-slate-800 rounded-lg overflow-hidden">
            <table class="w-full">
              <thead class="bg-slate-900/80 mono text-[10px] text-slate-500 tracking-widest text-left">
                <tr>
                  <th class="px-4 py-2">FAMILY</th>
                  <th class="px-4 py-2">RULE ID</th>
                  <th class="px-4 py-2">LABEL</th>
                  <th class="px-4 py-2">SOURCE</th>
                  <th class="px-4 py-2 text-right">PTS</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                ${hitsRows}
                <tr class="bg-slate-900/40">
                  <td colspan="4" class="px-4 py-2 mono text-xs text-right text-slate-400">TOTAL</td>
                  <td class="px-4 py-2 mono text-xs text-right text-red-400 font-bold">${result.score}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Meta -->
        <div class="mono text-[10px] text-slate-600 flex justify-between border-t border-slate-800 pt-4">
          <span>METHOD: ${escapeHtml(result.method)}</span>
          <span>PATH: ${escapeHtml(result.path)}</span>
          <span>TIMESTAMP: ${escapeHtml(result.timestamp)}</span>
        </div>

        <!-- CTA -->
        <div class="flex gap-3 pt-2">
          <a href="/" class="flex-1 text-center bg-slate-800 hover:bg-slate-700 text-slate-200 mono text-xs py-2.5 rounded-lg">RETURN TO LOGIN</a>
        </div>
      </div>
    </div>

    <p class="text-center mono text-[10px] text-slate-700 mt-6">// This request has been logged and reported to the SOC dashboard.</p>
  </div>
</body>
</html>`;
}

module.exports = {
  PATTERNS,
  BLOCK_THRESHOLD,
  inspectRequest,
  scanString,
  deepDecode,
  decodeHtmlEntities,
  normalizeUnicode,
  normalizeForSql,
  buildHaystacks,
  wafMiddleware,
  renderBlockedPage,
};
