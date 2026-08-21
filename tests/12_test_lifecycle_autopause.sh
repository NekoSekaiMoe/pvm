#!/usr/bin/env bash
# 12_test_lifecycle_autopause.sh — E2E test for AutoPause, Manual Pause/Resume, and AutoResume.
# Covers: POST /api/tasks/:id/pause, POST /api/tasks/:id/resume, cgroup.freeze synchronization,
# invalid transition rejection (409), and API activity auto-resume.
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

PORT=18092
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"

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

req_status() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}

echo "--- 1. Setup mock running task with mock cgroup root"
TASK_ID="t-auto-01"
mkdir -p "$PVM_STATE_ROOT/$TASK_ID" "$PVM_CGROUP_ROOT/$TASK_ID"
echo "0" > "$PVM_CGROUP_ROOT/$TASK_ID/cgroup.freeze"
cat > "$PVM_STATE_ROOT/$TASK_ID/state.json" <<EOF
{
  "id": "$TASK_ID",
  "name": "$TASK_ID",
  "status": "running",
  "pid": 99999,
  "idle_timeout": "30m",
  "auto_resume": true
}
EOF

echo "--- 2. POST /api/tasks/:id/pause pauses running task"
STATUS=$(req_status POST "/tasks/$TASK_ID/pause")
[ "$STATUS" = "204" ] || fail "expected 204 for pause, got: $STATUS"
STATE=$(curl -s "$API/tasks/$TASK_ID" -H "$AUTH" | jq -r .status)
[ "$STATE" = "suspended" ] || fail "expected status suspended, got: $STATE"
FROZEN=$(cat "$PVM_CGROUP_ROOT/$TASK_ID/cgroup.freeze")
[ "$FROZEN" = "1" ] || fail "expected cgroup.freeze=1, got: $FROZEN"
echo "   paused -> status=suspended, cgroup.freeze=1 ✓"

echo "--- 3. Pausing already suspended task returns 409 Conflict"
STATUS=$(req_status POST "/tasks/$TASK_ID/pause")
[ "$STATUS" = "409" ] || fail "expected 409 when pausing suspended task, got: $STATUS"
echo "   duplicate pause rejected 409 ✓"

echo "--- 4. POST /api/tasks/:id/resume resumes suspended task"
STATUS=$(req_status POST "/tasks/$TASK_ID/resume")
[ "$STATUS" = "200" ] || fail "expected 200 for resume, got: $STATUS"
STATE=$(curl -s "$API/tasks/$TASK_ID" -H "$AUTH" | jq -r .status)
[ "$STATE" = "running" ] || fail "expected status running, got: $STATE"
THAWED=$(cat "$PVM_CGROUP_ROOT/$TASK_ID/cgroup.freeze")
[ "$THAWED" = "0" ] || fail "expected cgroup.freeze=0, got: $THAWED"
echo "   resumed -> status=running, cgroup.freeze=0 ✓"

echo "--- 5. Resuming already running task returns 409 Conflict"
STATUS=$(req_status POST "/tasks/$TASK_ID/resume")
[ "$STATUS" = "409" ] || fail "expected 409 when resuming running task, got: $STATUS"
echo "   duplicate resume rejected 409 ✓"

echo "--- 6. Pause on non-existent task returns 404"
STATUS=$(req_status POST "/tasks/non-existent/pause")
[ "$STATUS" = "404" ] || fail "expected 404 for pause non-existent, got: $STATUS"
STATUS=$(req_status POST "/tasks/non-existent/resume")
[ "$STATUS" = "404" ] || fail "expected 404 for resume non-existent, got: $STATUS"
echo "   non-existent pause/resume 404 ✓"

echo "--- 7. Autopause on idle_timeout and AutoResume on API activity"
TASK_ID2="t-auto-02"
mkdir -p "$PVM_STATE_ROOT/$TASK_ID2" "$PVM_CGROUP_ROOT/$TASK_ID2"
echo "0" > "$PVM_CGROUP_ROOT/$TASK_ID2/cgroup.freeze"
cat > "$PVM_STATE_ROOT/$TASK_ID2/state.json" <<EOF
{
  "id": "$TASK_ID2",
  "name": "$TASK_ID2",
  "status": "running",
  "pid": 99998,
  "idle_timeout": "600ms",
  "auto_resume": true
}
EOF

# Restart server to trigger rearmAllAutopause with the short timeout
kill "$SRV" 2>/dev/null || true
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done

# Wait for idle_timeout (600ms) to trigger autopause
AUTOPAUSED=false
for _ in $(seq 1 20); do
    STATE=$(curl -s "$API/tasks/$TASK_ID2" -H "$AUTH" | jq -r .status)
    if [ "$STATE" = "suspended" ]; then
        AUTOPAUSED=true
        break
    fi
    sleep 0.15
done
[ "$AUTOPAUSED" = "true" ] || fail "task did not auto-pause after idle_timeout; state=$STATE"
FROZEN=$(cat "$PVM_CGROUP_ROOT/$TASK_ID2/cgroup.freeze")
[ "$FROZEN" = "1" ] || fail "expected cgroup.freeze=1 after autopause, got: $FROZEN"
echo "   idle_timeout triggered autopause -> status=suspended, cgroup.freeze=1 ✓"

# Trigger API activity via /api/exec which triggers auto_resume
curl -s -X POST "$API/exec?task=$TASK_ID2" -H "$AUTH" -H "Content-Type: application/json" -d '{"cmd":"help"}' >/dev/null || true
STATE=$(curl -s "$API/tasks/$TASK_ID2" -H "$AUTH" | jq -r .status)
[ "$STATE" = "running" ] || fail "task did not auto-resume on API activity; state=$STATE"
THAWED=$(cat "$PVM_CGROUP_ROOT/$TASK_ID2/cgroup.freeze")
[ "$THAWED" = "0" ] || fail "expected cgroup.freeze=0 after autoresume, got: $THAWED"
echo "   API activity triggered autoresume -> status=running, cgroup.freeze=0 ✓"

echo ""
echo "✅ 12_test_lifecycle_autopause: ALL PASS"

