#!/usr/bin/env bash
# 43_test_task_shortid_metrics.sh — /api/tasks short-id prefix resolution and
# the per-task metrics view.
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

PORT=18044
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/tasks" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/tasks" >/dev/null || fail "server failed to start"

echo "--- 1. seed two tasks with a shared prefix and one distinct"
for id in alpha-1 alpha-2 omega; do
    mkdir -p "$PVM_STATE_ROOT/$id"
    cat > "$PVM_STATE_ROOT/$id/state.json" <<EOF
{"id":"$id","name":"$id","status":"running","pid":99999}
EOF
done

echo "--- 2. full id and unique prefix resolve"
curl -sf -H "$AUTH" "$API/tasks/omega" | jq -e '.id == "omega"' >/dev/null || fail "full id"
curl -sf -H "$AUTH" "$API/tasks/ome" | jq -e '.id == "omega"' >/dev/null || fail "unique prefix must resolve"

echo "--- 3. ambiguous prefix falls back to exact-match-or-404"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "$API/tasks/alpha")
# 'alpha' is not an exact task and the prefix is ambiguous: must NOT resolve
# to a random one of alpha-1/alpha-2 (404 shape).
[ "$CODE" = "404" ] || fail "ambiguous prefix must 404, got $CODE"
curl -sf -H "$AUTH" "$API/tasks/alpha-1" | jq -e '.id == "alpha-1"' >/dev/null || fail "exact id still works"

echo "--- 4. metrics view shape"
M=$(curl -sf -H "$AUTH" "$API/tasks/omega/metrics")
echo "$M" | jq -e '.task == "omega" and (.net_tx_bytes | type) == "number"' >/dev/null || fail "metrics shape: $M"

echo "✅ 43 short-id + metrics suite passed"
