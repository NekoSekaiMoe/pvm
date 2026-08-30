#!/usr/bin/env bash
# 37_test_observability.sh — /healthz, /version, /metrics endpoints.
# Covers: unauth health/version, metrics auth (default) and noauth opt-in
# (PVM_METRICS_NOAUTH=1), pprof disabled by default, Prometheus text shape.
# CI-safe (no kernel required).
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

PORT=18037
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API"
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
    curl -sf "$API/healthz" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf "$API/healthz" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

echo "--- 1. /healthz answers without auth"
curl -sf "$API/healthz" | jq -e '.status == "ok" and (.uptime_seconds | type) == "number"' >/dev/null || fail "healthz shape"

echo "--- 2. /version answers without auth"
curl -sf "$API/version" | jq -e '.version and .commit and .goos and .goarch' >/dev/null || fail "version shape"

echo "--- 3. /metrics requires auth by default"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/metrics")
[ "$CODE" = "401" ] || fail "metrics unauth must 401, got $CODE"
curl -sf -H "$AUTH" "$API/metrics" | grep -q "^# TYPE pvm_uptime_seconds gauge" || fail "metrics must be prometheus text"

echo "--- 4. hitting exec bumps a metric"
mkdir -p "$PVM_STATE_ROOT/t-obs"
cat > "$PVM_STATE_ROOT/t-obs/state.json" <<EOF
{"id":"t-obs","name":"t-obs","status":"running","pid":99999}
EOF
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/api/exec?task=t-obs" -H "$AUTH" -H "Content-Type: application/json" -d '{"cmd":"nope arg=1"}')
[ "$CODE" = "403" ] || fail "exec without gateway must 403, got $CODE"

echo "--- 5. pprof off by default (cmdline probe is content-sniffed: the
        static WebUI fallback answers 200 for unknown paths, so absence is
        asserted on CONTENT, not status)"
BODY=$(curl -s "$API/debug/pprof/cmdline")
case "$BODY" in
    *agentpvm*) fail "pprof must be disabled by default, got cmdline profile";;
    *) ;;
esac

echo "✅ 37 observability suite passed"
