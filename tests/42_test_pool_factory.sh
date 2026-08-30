#!/usr/bin/env bash
# 42_test_pool_factory.sh — warm pool with the real (state-recorded) factory:
# warmed sandboxes materialize under the state root, pool + quota persist
# across restart.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18043
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

start_server() {
    "$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
    SRV=$!
    for _ in $(seq 1 40); do
        curl -sf -H "$AUTH" "$API/pool/stats" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    fail "server failed to start: $(cat "$TMP/server.log")"
}
start_server

echo "--- 1. warm creates REAL state records (no phantom ids)"
curl -sf -X POST "$API/pool/warm" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"template":{"name":"tpl-a"},"n":2}' | jq -e '.created == 2' >/dev/null || fail "warm 2"
STATS=$(curl -sf -H "$AUTH" "$API/pool/stats")
echo "$STATS" | jq -e '.ready >= 2' >/dev/null || fail "stats must show ready>=2: $STATS"
WARM_IDS=$(ls "$PVM_STATE_ROOT" | grep '^warm-' || true)
[ -n "$WARM_IDS" ] || fail "warm sandboxes must materialize state dirs"
for id in $WARM_IDS; do
    jq -e '.status == "ready"' "$PVM_STATE_ROOT/$id/state.json" >/dev/null || fail "$id must be status=ready"
done

echo "--- 2. quota install + persistence across restart"
curl -sf -X POST "$API/pool/quota" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"tenant":"tenant-x","quota":{"max_concurrent":3,"max_cpu":4,"max_memory_mb":512,"max_tasks_per_hour":10}}' >/dev/null || fail "set quota"
[ -f "$PVM_STATE_ROOT/pool.json" ] || fail "pool.json must persist"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""
start_server

STATS2=$(curl -sf -H "$AUTH" "$API/pool/stats")
echo "$STATS2" | jq -e '.ready >= 2' >/dev/null || fail "pool must survive restart: $STATS2"
jq -e '.quotas["tenant-x"].max_concurrent == 3' "$PVM_STATE_ROOT/pool.json" >/dev/null || fail "quota must survive restart"

echo "✅ 42 pool factory suite passed"
