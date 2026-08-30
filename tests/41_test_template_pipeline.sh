#!/usr/bin/env bash
# 41_test_template_pipeline.sh — template build pipeline PENDING→READY with a
# local rootfs class, progress endpoint, rebuild semantics, watch CLI.
# CI-safe (uses an existing rootfs file — no pull, no root).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_TEMPLATE_ROOT"

# Rootfs image fixture: non-empty file passes the verify phase.
dd if=/dev/zero of="$TMP/base.img" bs=1024 count=64 2>/dev/null

PORT=18042
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"
export PVM_API="http://127.0.0.1:$PORT"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/templates" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/templates" >/dev/null || fail "server failed to start"

echo "--- 1. create returns 201 + PENDING"
RESP=$(curl -sf -X POST "$API/templates" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"image_ref\":\"$TMP/base.img\"}")
TPL=$(echo "$RESP" | jq -r .template_id)
[ "$TPL" != "null" ] && [ -n "$TPL" ] || fail "template id missing: $RESP"
echo "$RESP" | jq -e '.status == "PENDING"' >/dev/null || fail "creation must be PENDING: $RESP"

echo "--- 2. build converges to done/READY"
PHASE=""
for _ in $(seq 1 40); do
    PHASE=$(curl -sf -H "$AUTH" "$API/templates/$TPL/build?wait=1s" | jq -r .phase)
    [ "$PHASE" = "done" ] || [ "$PHASE" = "failed" ] && break
    sleep 0.3
done
[ "$PHASE" = "done" ] || fail "build phase = $PHASE, want done"
STATUS=$(curl -sf -H "$AUTH" "$API/templates/$TPL" | jq -r .status)
[ "$STATUS" = "READY" ] || fail "record must be READY, got $STATUS"

echo "--- 3. image_path bound + progress persisted"
curl -sf -H "$AUTH" "$API/templates/$TPL" | jq -e --arg p "$TMP/base.img" '.image_path == $p' >/dev/null || fail "image_path must bind rootfs"
curl -sf -H "$AUTH" "$API/templates/$TPL/build" | jq -e '.pct == 100 and .log_tail != ""' >/dev/null || fail "progress must show 100% + log tail"

echo "--- 4. rebuild on READY is 409"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/templates/$TPL/rebuild" -H "$AUTH")
[ "$CODE" = "409" ] || fail "rebuild on READY must 409, got $CODE"

echo "--- 5. alias binds once READY (then sandbox-grade readiness holds)"
curl -sf -X POST "$API/templates/$TPL/alias" -H "$AUTH" -H "Content-Type: application/json" -d '{"alias":"base-alias"}' | jq -e '.alias == "base-alias"' >/dev/null || fail "alias bind"

echo "--- 6. template watch CLI reports progress/READY"
OUT=$(cd "$TMP" && timeout 20 ./agentpvm template watch "$TPL" 2>&1 || true)
echo "$OUT" | grep -q "template READY" || fail "watch CLI must reach READY: $OUT"

echo "--- 7. FAILED template can rebuild"
BAD=$(curl -sf -X POST "$API/templates" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"image_ref":"/nonexistent/definitely-missing.img"}' | jq -r .template_id)
for _ in $(seq 1 40); do
    ST=$(curl -sf -H "$AUTH" "$API/templates/$BAD" | jq -r .status)
    [ "$ST" = "FAILED" ] && break
    sleep 0.3
done
[ "$ST" = "FAILED" ] || fail "missing rootfs must flip FAILED, got $ST"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/templates/$BAD/rebuild" -H "$AUTH")
[ "$CODE" = "202" ] || fail "rebuild on FAILED must be 202, got $CODE"

echo "✅ 41 template pipeline suite passed"
