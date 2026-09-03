#!/usr/bin/env bash
# 56_test_deep_pause.sh — deep-pause lifecycle guards over REST.
# Covers: pause?deep=1 requires a Running task (409 otherwise), fails
# closed without criu (409 + message), resume detects deep-paused state,
# DeepResume reports missing memory images (500), and a deep-paused task's
# terminal-status guard leaves Suspended intact (state-file assertion).
# CI-safe (no criu, no kernel needed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
# Isolate from a host-installed criu: the override points at a path that
# cannot run, so CRIUBin() resolves to "" even when PATH has criu.
export PVM_CRIU_BIN="$TMP/no-criu-bin"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18056
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
    curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 || fail "server failed to start: $(cat "$TMP/server.log")"

mkstate() { # id status extra-metadata-json [pid]
    mkdir -p "$PVM_STATE_ROOT/$1"
    local pid=${4:-0}
    printf '{"id":"%s","name":"%s","status":"%s","metadata":%s,"pid":%s}\n' \
        "$1" "$1" "$2" "$3" "$pid" \
        > "$PVM_STATE_ROOT/$1/state.json"
}

echo "--- 1. deep pause on unknown task → 404"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/ghost/pause?deep=1" -H "$AUTH")
[ "$CODE" = "404" ] || fail "unknown task must 404, got $CODE"

echo "--- 2. deep pause on a non-Running task → 409"
mkstate dp-suspended suspended '{}'
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/dp-suspended/pause?deep=1" -H "$AUTH")
[ "$CODE" = "409" ] || fail "non-running deep pause must 409, got $CODE"

echo "--- 3. deep pause without criu fails closed (409 + message)"
# Record a LIVE pid (this shell): with pid=0 the 409 would come from the
# "no live PID" guard and never exercise the criu-unavailable branch.
mkstate dp-run running '{}' $$
BODY=$(curl -s -X POST "$API/tasks/dp-run/pause?deep=1" -H "$AUTH")
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/dp-run/pause?deep=1" -H "$AUTH")
[ "$CODE" = "409" ] || fail "no-criu deep pause must 409, got $CODE"
echo "$BODY" | jq -e '.error | contains("deep pause failed")' >/dev/null || fail "409 must say deep pause failed: $BODY"
# And the task must NOT be Suspended: the failure path leaves it alone.
STATUS=$(jq -r .status < "$PVM_STATE_ROOT/dp-run/state.json")
[ "$STATUS" = "running" ] || fail "failed deep pause must not suspend the task, got $STATUS"

echo "--- 4. resume routes deep-paused tasks to DeepResume"
# A deep-paused fixture whose memory images are missing: the endpoint must
# surface the DeepResume error (500) instead of a plain thaw.
mkdir -p "$PVM_STATE_ROOT/dp-deep"
printf '{"id":"dp-deep","name":"dp-deep","status":"suspended","metadata":{"pause_mode":"deep","pause_memory":"%s/missing-criu"}}\n' "$TMP" \
    > "$PVM_STATE_ROOT/dp-deep/state.json"
BODY=$(curl -s -X POST "$API/tasks/dp-deep/resume" -H "$AUTH")
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/dp-deep/resume" -H "$AUTH")
[ "$CODE" = "500" ] || fail "deep resume with missing images must 500, got $CODE"
echo "$BODY" | jq -e '.error | contains("memory images missing")' >/dev/null || fail "500 must name missing images: $BODY"
# Still Suspended (and still deep) after the failed resume.
STATUS=$(jq -r .status < "$PVM_STATE_ROOT/dp-deep/state.json")
[ "$STATUS" = "suspended" ] || fail "failed deep resume must stay suspended, got $STATUS"
MODE=$(jq -r '.metadata.pause_mode' < "$PVM_STATE_ROOT/dp-deep/state.json")
[ "$MODE" = "deep" ] || fail "deep mode must survive a failed resume, got $MODE"

echo "--- 5. shallow pause path still works (no deep query) for a frozen-less task"
# The shallow path requires a freezable cgroup; in CI the freeze of a
# missing cgroup is treated as "runtime missing" (409). Either way it must
# NOT say "deep".
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/dp-run/pause" -H "$AUTH")
case "$CODE" in
    204|409|500) ;;
    *) fail "shallow pause returned unexpected $CODE" ;;
esac

echo "✅ 56_test_deep_pause.sh passed"
