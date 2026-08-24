#!/usr/bin/env bash
# 13_test_e2b_api_security.sh — E2B REST API Security, KeyAuth, and Input Validation Edge Cases.
# Covers: Missing/invalid Bearer tokens (401), custom API_SECRET, public WebUI static route,
# container start parameter boundaries (CPU, memory, ID regex), and log/delete invalid IDs.
# CI-safe (no kernel required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18093
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
CUSTOM_SECRET="custom_super_secret_key"
export API_SECRET="$CUSTOM_SECRET"
AUTH="Authorization: Bearer $CUSTOM_SECRET"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

echo "==> starting server on :$PORT with custom API_SECRET"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!

for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

echo "--- 1. API Authentication: missing or invalid bearer token rejected (400/401)"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$API/containers")
[ "$HTTP" = "400" ] || [ "$HTTP" = "401" ] || fail "expected 400 or 401 for missing auth, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$API/containers" -H "Authorization: Bearer wrong_secret")
[ "$HTTP" = "401" ] || fail "expected 401 for wrong secret, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$API/containers" -H "Authorization: Bearer secret")
[ "$HTTP" = "401" ] || fail "expected 401 for default secret when custom API_SECRET is set, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$API/containers" -H "$AUTH")
[ "$HTTP" = "200" ] || fail "expected 200 for valid custom secret, got: $HTTP"
echo "   auth checks (401 & 200) ✓"

echo "--- 2. Public Static WebUI routes bypass KeyAuth"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$PVM_API/")
[ "$HTTP" = "200" ] || fail "expected 200 for public WebUI root, got: $HTTP"
echo "   public WebUI bypasses auth ✓"

echo "--- 3. POST /api/containers/start input validation"
# Negative CPU
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/start" -H "$AUTH" -H "Content-Type: application/json" -d '{"name":"c1","cpu":-1}')
[ "$HTTP" = "400" ] || fail "expected 400 for negative CPU, got: $HTTP"
# Excessive CPU (>1024)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/start" -H "$AUTH" -H "Content-Type: application/json" -d '{"name":"c1","cpu":2048}')
[ "$HTTP" = "400" ] || fail "expected 400 for CPU > 1024, got: $HTTP"
# Invalid memory
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/start" -H "$AUTH" -H "Content-Type: application/json" -d '{"name":"c1","mem":"512X"}')
[ "$HTTP" = "400" ] || fail "expected 400 for invalid memory format, got: $HTTP"
# Invalid ID
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/start" -H "$AUTH" -H "Content-Type: application/json" -d '{"name":"../evil"}')
[ "$HTTP" = "400" ] || fail "expected 400 for traversal container name, got: $HTTP"
echo "   container start parameter validations ✓"

echo "--- 4. Log, delete, snapshot, and restore with invalid ID formats"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$API/containers/..%2fevil/logs" -H "$AUTH")
[ "$HTTP" = "400" ] || fail "expected 400 for invalid logs ID, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API/containers/..%2fevil" -H "$AUTH")
[ "$HTTP" = "400" ] || fail "expected 400 for invalid delete ID, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/..%2fevil/snapshot" -H "$AUTH")
[ "$HTTP" = "400" ] || fail "expected 400 for invalid snapshot ID, got: $HTTP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/containers/..%2fevil/restore" -H "$AUTH")
[ "$HTTP" = "400" ] || fail "expected 400 for invalid restore ID, got: $HTTP"
echo "   regex ID validations across endpoints ✓"

echo ""
echo "✅ 13_test_e2b_api_security: ALL PASS"
