#!/usr/bin/env bash
# ===================================================================
# DeceptiWAF - Phase 2 Attack Test Script
# Run this to fire every attack type at the WAF and verify it blocks.
#
# Usage:
#   ./scripts/test-waf.sh                 # tests against localhost:3000
#   ./scripts/test-waf.sh https://my-host # tests against a custom URL
#
# Tip: open the SOC dashboard in another tab (login as admin) to watch
# events stream in live as this script runs.
# ===================================================================

set -u
BASE="${1:-http://localhost:3000}"

# Hard timeout on every curl to prevent hangs
CURL_OPTS=(--max-time 5 --connect-timeout 3 -s)

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_cyn=$'\033[36m'
c_dim=$'\033[2m'; c_rst=$'\033[0m'

PASS=0; FAIL=0

# Run a single attack, expect a 403
expect_block() {
  local label="$1"; shift
  local code
  code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "$@")
  if [ "$code" = "403" ]; then
    PASS=$((PASS+1))
    printf "  ${c_grn}BLOCK${c_rst}  %s  ${c_dim}(403)%s\n" "$label" "${c_rst}"
  else
    FAIL=$((FAIL+1))
    printf "  ${c_red}FAIL ${c_rst}  %s  ${c_dim}(got %s, expected 403)%s\n" "$label" "$code" "${c_rst}"
  fi
}

# Run a request, expect a non-403 (200/302/etc)
expect_pass() {
  local label="$1"; shift
  local code
  code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "$@")
  if [ "$code" = "403" ]; then
    FAIL=$((FAIL+1))
    printf "  ${c_red}FAIL ${c_rst}  %s  ${c_dim}(blocked, expected pass)%s\n" "$label" "${c_rst}"
  else
    PASS=$((PASS+1))
    printf "  ${c_grn}PASS ${c_rst}  %s  ${c_dim}(%s)%s\n" "$label" "$code" "${c_rst}"
  fi
}

echo "=================================================="
echo "  DeceptiWAF - Phase 2 Attack Test Suite"
echo "  Target: $BASE"
echo "=================================================="
echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[1] SQL Injection${c_rst}"
# ------------------------------------------------------------------

# Classic OR 1=1 — comment-only tail, expect flagged but allowed (score 4 = 3+1)
# Actually OR=4 + -- = 1, total 5 → blocked
expect_block "Classic ' OR 1=1 --" \
  -X POST -d "studentId=admin' OR 1=1 --&password=x" "$BASE/login"

# String-equality tautology
expect_block "String tautology ' OR 'a'='a" \
  -X POST -d "studentId=admin' OR 'a'='a&password=x" "$BASE/login"

# UNION SELECT (spec example: UNION=3 + SELECT=... + more) -> blocked
expect_block "UNION SELECT injection" \
  -X POST -d "studentId=x' UNION SELECT username,password FROM users --&password=x" "$BASE/login"

# Stacked DROP TABLE
expect_block "Stacked DROP TABLE" \
  -X POST -d "studentId=x'; DROP TABLE users; --&password=x" "$BASE/login"

# Time-based blind SLEEP
expect_block "Time-based SLEEP()" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND SLEEP(5) --"

# information_schema recon
expect_block "information_schema recon" \
  -G "$BASE/dashboard" --data-urlencode "q=x UNION SELECT table_name FROM information_schema.tables"

# Error-based extractvalue
expect_block "extractValue() error-based" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND extractvalue(1, concat(0x7e,(SELECT version()))) --"

# xp_cmdshell RCE via SQL
expect_block "xp_cmdshell RCE" \
  -G "$BASE/dashboard" --data-urlencode "q=x'; EXEC xp_cmdshell('whoami'); --"

# URL-encoded classic (anti-evasion)
expect_block "URL-encoded OR 1=1" \
  -X POST -d "studentId=admin%27%20OR%201%3D1%20--&password=x" "$BASE/login"

# Double-encoded (Phase 5 anti-evasion — should still catch with deepDecode)
expect_block "Double-encoded OR 1=1" \
  -X POST -d "studentId=admin%2527%2520OR%25201%253D1%2520--&password=x" "$BASE/login"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[2] Cross-Site Scripting (XSS)${c_rst}"
# ------------------------------------------------------------------

expect_block "Classic <script>alert(1)</script>" \
  -G "$BASE/dashboard" --data-urlencode "q=<script>alert(1)</script>"

expect_block "onerror payload" \
  -G "$BASE/dashboard" --data-urlencode "q=<img src=x onerror=alert(document.cookie)>"

expect_block "javascript: protocol" \
  -G "$BASE/dashboard" --data-urlencode "q=<a href=javascript:alert(1)>click</a>"

expect_block "<iframe> injection" \
  -G "$BASE/dashboard" --data-urlencode "q=<iframe src=javascript:alert(1)></iframe>"

expect_block "<svg onload>" \
  -G "$BASE/dashboard" --data-urlencode "q=<svg onload=alert(1)>"

expect_block "String.fromCharCode obfuscation" \
  -G "$BASE/dashboard" --data-urlencode "q=<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"

expect_block "URL-encoded <script>" \
  -G "$BASE/dashboard" --data-urlencode "q=%3Cscript%3Ealert(1)%3C/script%3E"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[3] Path Traversal${c_rst}"
# ------------------------------------------------------------------

expect_block "../../etc/passwd" \
  -G "$BASE/dashboard" --data-urlencode "q=../../etc/passwd"

expect_block "URL-encoded ../../../etc/passwd" \
  -G "$BASE/dashboard" --data-urlencode "q=..%2F..%2F..%2Fetc%2Fpasswd"

expect_block "/etc/shadow access" \
  -G "$BASE/dashboard" --data-urlencode "q=/etc/shadow"

expect_block "Windows win.ini" \
  -G "$BASE/dashboard" --data-urlencode "q=..\\..\\windows\\win.ini"

expect_block "PHP stream wrapper" \
  -G "$BASE/dashboard" --data-urlencode "q=php://filter/convert.base64-encode/resource=index.php"

expect_block "/proc/self/environ" \
  -G "$BASE/dashboard" --data-urlencode "q=/proc/self/environ"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[4] Malicious User-Agents${c_rst}"
# ------------------------------------------------------------------

expect_block "sqlmap UA"  -H "User-Agent: sqlmap/1.6" "$BASE/"
expect_block "nikto UA"   -H "User-Agent: Nikto/2.1.6" "$BASE/"
expect_block "hydra UA"   -H "User-Agent: hydra/9.5" "$BASE/"
expect_block "havij UA"   -H "User-Agent: Havij/1.17" "$BASE/"
expect_block "acunetix UA" -H "User-Agent: Acunetix-Scanner/14.0" "$BASE/"
expect_block "nessus UA"  -H "User-Agent: Nessus/10.5" "$BASE/"
expect_block "dirbuster UA" -H "User-Agent: DirBuster/1.0" "$BASE/"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[5] Anti-Evasion (Phase 5)${c_rst}"
# ------------------------------------------------------------------

# HTML entity encoded XSS (named)
expect_block "HTML named: &lt;script&gt;" \
  -G "$BASE/dashboard" --data-urlencode "q=&lt;script&gt;alert(1)&lt;/script&gt;"

# HTML decimal encoded XSS
expect_block "HTML decimal: &#60;script&#62;" \
  -G "$BASE/dashboard" --data-urlencode "q=&#60;script&#62;alert(1)&#60;/script&#62;"

# HTML hex encoded XSS
expect_block "HTML hex: &#x3c;script&#x3e;" \
  -G "$BASE/dashboard" --data-urlencode "q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"

# Unicode full-width UNION SELECT (NFKC normalization)
expect_block "Full-width UNION SELECT" \
  -X POST --data-urlencode "studentId=' ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3 --" --data "password=x" "$BASE/login"

# SQL comment evasion
expect_block "UNION/**/SELECT (SQL comment)" \
  -X POST -d "studentId=x' UNION/**/SELECT 1,2,3 --&password=x" "$BASE/login"

# SQL comment with text inside
expect_block "UNION/*foo*/SELECT" \
  -X POST -d "studentId=x' UNION/*foo*/SELECT 1,2,3 --&password=x" "$BASE/login"

# Whitespace padding
expect_block "UNION     SELECT (padded)" \
  -X POST -d "studentId=x' UNION     SELECT 1,2,3 --&password=x" "$BASE/login"

# Layered: URL-encoded + HTML entity
expect_block "URL+HTML layered %26lt%3Bscript" \
  -G "$BASE/dashboard" --data-urlencode "q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B"

# Double URL-encoded
expect_block "Double URL-encoded %2527 OR 1=1" \
  -X POST -d "studentId=admin%2527%2520OR%25201%253D1%2520--&password=x" "$BASE/login"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[6] Benign traffic (should NOT be blocked)${c_rst}"
# ------------------------------------------------------------------

expect_pass "Normal login page GET" "$BASE/"
expect_pass "Valid login POST" \
  -X POST -d "studentId=aryan&password=aryan@2024" "$BASE/login"
expect_pass "Normal search query" \
  -G "$BASE/dashboard" --data-urlencode "q=Data Structures"
expect_pass "Course code search" \
  -G "$BASE/dashboard" --data-urlencode "q=CSE301"
expect_pass "Instructor name search" \
  -G "$BASE/dashboard" --data-urlencode "q=Dr. Khan"

# Edge case: just a SQL comment (score 1 — should pass but be flagged)
expect_pass "SQL comment only (score 1)" \
  -G "$BASE/dashboard" --data-urlencode "q=--"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[7] Edge cases (low-score flagged but allowed)${c_rst}"
# ------------------------------------------------------------------

# Just an alert() call alone — score 2 (allowed, flagged)
expect_pass "alert() alone (score 2)" \
  -G "$BASE/dashboard" --data-urlencode "q=alert(hello)"

# Just <img src=x> alone — score 2 (allowed, flagged)
expect_pass "<img src=x> alone (score 2)" \
  -G "$BASE/dashboard" --data-urlencode "q=<img src=x>"

echo ""

# ------------------------------------------------------------------
echo "=================================================="
echo "  RESULTS: ${c_grn}${PASS} passed${c_rst}, ${c_red}${FAIL} failed${c_rst}"
echo "=================================================="
echo ""
echo "  Next steps:"
echo "    1. Login as admin at ${BASE}/?user=admin  (password: socadmin123)"
echo "    2. Re-run this script — events should stream into the SOC feed."
echo "    3. Watch the server console for [WAF BLOCK] lines."
echo ""

exit $FAIL
