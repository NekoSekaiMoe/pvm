#!/usr/bin/env bash
# 44_test_watchdog_deadlines.sh — the deadline executor: E2B refresh
# deadlines and lifecycle TTL are enforced (killed + Destroy state).
# CI-safe (mock state files; no real processes).
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

PORT=18045
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

echo "--- 1. expired refresh deadline is enforced"
PAST=$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$PVM_STATE_ROOT/t-dl"
cat > "$PVM_STATE_ROOT/t-dl/state.json" <<EOF
{"id":"t-dl","name":"t-dl","status":"running","pid":99999,"deadline":"$PAST"}
EOF
for _ in $(seq 1 20); do
    ST=$(curl -sf -H "$AUTH" "$API/tasks/t-dl" | jq -r .status)
    [ "$ST" = "destroy" ] || [ "$ST" = "destroyed" ] && break
    sleep 0.3
done
echo "deadline task status: $ST"
case "$ST" in destroy*) ;; *) fail "expired deadline must destroy, got $ST";; esac

echo "--- 2. future deadline is NOT enforced"
FUT=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+1H +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$PVM_STATE_ROOT/t-live"
cat > "$PVM_STATE_ROOT/t-live/state.json" <<EOF
{"id":"t-live","name":"t-live","status":"running","pid":99999,"deadline":"$FUT"}
EOF
sleep 2
ST=$(curl -sf -H "$AUTH" "$API/tasks/t-live" | jq -r .status)
[ "$ST" = "running" ] || fail "future deadline must keep running, got $ST"

echo "--- 3. lifecycle TTL enforced via spec.json"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$PVM_STATE_ROOT/t-ttl"
cat > "$PVM_STATE_ROOT/t-ttl/state.json" <<EOF
{"id":"t-ttl","name":"t-ttl","status":"running","pid":99999,"started_at":"$NOW"}
EOF
cat > "$PVM_STATE_ROOT/t-ttl/spec.json" <<'EOF'
{"runtime":{"name":"t-ttl"},"lifecycle":{"ttl":"2s"}}
EOF
for _ in $(seq 1 20); do
    ST=$(curl -sf -H "$AUTH" "$API/tasks/t-ttl" | jq -r .status)
    case "$ST" in destroy*) break;; esac
    sleep 0.4
done
case "$ST" in destroy*) ;; *) fail "ttl expiry must destroy, got $ST";; esac

echo "✅ 44 watchdog suite passed"
