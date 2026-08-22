#!/usr/bin/env bash
# 16_test_pool_quota.sh — E2E test for Warm Pool Management & Tenant Quota Configuration.
# Covers: GET /api/pool/stats, POST /api/pool/warm boundaries (1..100), POST /api/pool/quota,
# and quota input validation.
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

PORT=18096
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET.
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET=$(openssl rand -hex 16 2>/dev/null || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

fail() { echo "❌ $1"; exit 1; }

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!

for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

req() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}
req_status() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}

echo "--- 1. Initial pool stats (empty pool)"
STATS=$(req GET /pool/stats)
[ "$(echo "$STATS" | jq -r .ready)" = "0" ] || fail "expected ready=0, got: $STATS"
echo "   initial stats ready=0 ✓"

echo "--- 2. POST /api/pool/warm warms sandboxes"
RESP=$(req POST /pool/warm '{"template":{"name":"alpine","memory":"256M","cpu":1},"n":3}')
CREATED=$(echo "$RESP" | jq -r .created)
[ "$CREATED" = "3" ] || fail "expected created=3, got: $RESP"
STATS=$(req GET /pool/stats)
[ "$(echo "$STATS" | jq -r .ready)" = "3" ] || fail "expected ready=3 after warm, got: $STATS"
echo "   warmed 3 sandboxes (stats ready=3) ✓"

echo "--- 3. POST /api/pool/warm boundary checks (n <= 0 and n > 100 rejected)"
STATUS=$(req_status POST /pool/warm '{"template":{"name":"alpine"},"n":0}')
[ "$STATUS" = "400" ] || fail "expected 400 for n=0, got: $STATUS"
STATUS=$(req_status POST /pool/warm '{"template":{"name":"alpine"},"n":101}')
[ "$STATUS" = "400" ] || fail "expected 400 for n=101, got: $STATUS"
echo "   pool warm boundaries validated ✓"

echo "--- 4. POST /api/pool/quota sets tenant quota"
RESP=$(req POST /pool/quota '{"tenant":"qa-team","quota":{"MaxConcurrent":5,"MaxCPU":8,"MaxMemoryMB":4096,"MaxTasksPerHour":20}}')
[ "$(echo "$RESP" | jq -r .status)" = "ok" ] || fail "expected status=ok, got: $RESP"
echo "   tenant quota configured ✓"

echo "--- 5. POST /api/pool/quota input validation error cases (400)"
STATUS=$(req_status POST /pool/quota '{"tenant":"../invalid","quota":{"MaxConcurrent":5}}')
[ "$STATUS" = "400" ] || fail "expected 400 for path traversal tenant, got: $STATUS"
STATUS=$(req_status POST /pool/quota '{"tenant":"","quota":{"MaxConcurrent":5}}')
[ "$STATUS" = "400" ] || fail "expected 400 for empty tenant, got: $STATUS"
STATUS=$(req_status POST /pool/quota '{"tenant":"qa-team","quota":{"MaxConcurrent":-1}}')
[ "$STATUS" = "400" ] || fail "expected 400 for negative quota, got: $STATUS"
STATUS=$(req_status POST /pool/quota '{"tenant":"qa-team","quota":{"MaxConcurrent":"bad_type"}}')
[ "$STATUS" = "400" ] || fail "expected 400 for bad quota type, got: $STATUS"
echo "   invalid quota requests rejected 400 ✓"

echo ""
echo "✅ 16_test_pool_quota: ALL PASS"
