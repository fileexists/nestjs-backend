#!/usr/bin/env bash
# =============================================================================
# test-api.sh — Manual integration test suite using cURL
#
# Usage:
#   chmod +x scripts/test-api.sh
#   ./scripts/test-api.sh [BASE_URL]
#
# Defaults to http://localhost:5000 when no argument is provided.
# Requires: curl, jq
# =============================================================================

set -euo pipefail

BASE_URL="${1:-http://localhost:5000}"
COOKIE_JAR="$(mktemp /tmp/nestjs-cookies.XXXXXX)"
PASS=0
FAIL=0

# ── colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

assert_status() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$label (HTTP $actual)";
  else fail "$label — expected HTTP $expected, got $actual"; fi
}

assert_field() {
  local label="$1" field="$2" expected="$3" json="$4"
  local actual; actual=$(echo "$json" | jq -r "$field" 2>/dev/null || echo "PARSE_ERROR")
  if [[ "$actual" == "$expected" ]]; then ok "$label (.${field} = \"$actual\")";
  else fail "$label — expected .${field}=\"$expected\", got \"$actual\""; fi
}

# ── helpers ───────────────────────────────────────────────────────────────────
GET()  { curl -s -o /tmp/_body -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$BASE_URL$1"; }
POST() { curl -s -o /tmp/_body -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
              -X POST -H 'Content-Type: application/json' -d "$2" "$BASE_URL$1"; }
PUT()  { curl -s -o /tmp/_body -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
              -X PUT  -H 'Content-Type: application/json' -d "$2" "$BASE_URL$1"; }
DEL()  { curl -s -o /tmp/_body -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
              -X DELETE "$BASE_URL$1"; }
BODY() { cat /tmp/_body; }

# =============================================================================
echo ""
info "Target: $BASE_URL"
echo "============================================================"

# ── 1. HEALTH ─────────────────────────────────────────────────────────────────
echo ""
info "--- Health Check ---"
STATUS=$(GET "/health")
assert_status "GET /health" "200" "$STATUS"
assert_field  "GET /health → status" ".status" "ok" "$(BODY)"

# ── 2. AUTH — register ────────────────────────────────────────────────────────
echo ""
info "--- Auth: Register ---"

TEST_EMAIL="testuser_$$@example.com"
TEST_PASS="SecurePass123!"

STATUS=$(POST "/api/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "POST /api/auth/register (new user)" "201" "$STATUS"
assert_field  "Register → message" ".message" "User registered successfully" "$(BODY)"

STATUS=$(POST "/api/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "POST /api/auth/register (duplicate) → 400" "400" "$STATUS"

STATUS=$(POST "/api/auth/register" "{\"email\":\"not-an-email\",\"password\":\"pass\"}")
assert_status "POST /api/auth/register (invalid email) → 400" "400" "$STATUS"

# ── 3. AUTH — login ───────────────────────────────────────────────────────────
echo ""
info "--- Auth: Login ---"

STATUS=$(POST "/api/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
assert_status "POST /api/auth/login (valid)" "200" "$STATUS"
assert_field  "Login → message" ".message" "Login successful." "$(BODY)"

STATUS=$(POST "/api/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"WrongPassword!\"}")
assert_status "POST /api/auth/login (wrong password) → 401" "401" "$STATUS"

STATUS=$(POST "/api/auth/login" "{\"email\":\"nobody@example.com\",\"password\":\"irrelevant\"}")
assert_status "POST /api/auth/login (unknown email) → 401" "401" "$STATUS"

# ── 4. AUTH — validate ────────────────────────────────────────────────────────
echo ""
info "--- Auth: Validate ---"
# Cookie jar already has access_token from the successful login above
STATUS=$(GET "/api/auth/validate")
assert_status "GET /api/auth/validate (with cookie)" "200" "$STATUS"
assert_field  "Validate → success" ".success" "true" "$(BODY)"

# ── 5. USER — /me ─────────────────────────────────────────────────────────────
echo ""
info "--- User: /me ---"
STATUS=$(GET "/api/user/me")
assert_status "GET /api/user/me (authenticated)" "200" "$STATUS"
assert_field  "GET /api/user/me → email" ".email" "$TEST_EMAIL" "$(BODY)"

# ── 6. AUTH — logout ─────────────────────────────────────────────────────────
echo ""
info "--- Auth: Logout ---"
STATUS=$(POST "/api/auth/logout" "{}")
assert_status "POST /api/auth/logout" "200" "$STATUS"

STATUS=$(GET "/api/user/me")
assert_status "GET /api/user/me (after logout) → 401" "401" "$STATUS"

# ── 7. ADMIN ROUTES — seed an admin first ─────────────────────────────────────
echo ""
info "--- Permission endpoints (requires ADMIN account) ---"
info "Skipping permission CRUD — seed an ADMIN user first:"
info "  yarn seed --email admin@example.com --password AdminPass123! --permission ADMIN"
info "Then re-run this script with the admin cookie or use Swagger at $BASE_URL/docs"

# ── 8. Unauthenticated access ─────────────────────────────────────────────────
echo ""
info "--- Unauthenticated access ---"
STATUS=$(GET "/api/permission")
assert_status "GET /api/permission (no token) → 401" "401" "$STATUS"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================================"

rm -f "$COOKIE_JAR" /tmp/_body
[[ $FAIL -eq 0 ]]
