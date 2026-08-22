#!/usr/bin/env bash
# 21_test_state_fsm_durability.sh — E2E test for Task Lifecycle FSM State Transitions & Durability.
# Covers: Full lifecycle happy path, invalid edge rejection (409), quarantine transition,
# and idempotent transitions.
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

PORT=18097
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET
# (both the first boot and the restart in step 2b inherit it).
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

transition() {
    local task=$1 to=$2 actor=$3 reason=$4
    curl -s -X POST "$API/tasks/$task/transition" -H "$AUTH" -H "Content-Type: application/json" \
      -d "{\"to\":\"$to\",\"actor\":\"$actor\",\"reason\":\"$reason\"}"
}
transition_status() {
    local task=$1 to=$2 actor=$3 reason=$4
    curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/$task/transition" -H "$AUTH" -H "Content-Type: application/json" \
      -d "{\"to\":\"$to\",\"actor\":\"$actor\",\"reason\":\"$reason\"}"
}

echo "--- 1. Seed task in pending status"
TASK="t-fsm-01"
mkdir -p "$PVM_STATE_ROOT/$TASK"
echo "{\"id\":\"$TASK\",\"name\":\"$TASK\",\"status\":\"pending\"}" > "$PVM_STATE_ROOT/$TASK/state.json"

echo "--- 2. Full lifecycle transitions: pending -> provisioning -> ready -> running -> review -> completed"
transition "$TASK" "provisioning" "controller" "starting" >/dev/null
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "provisioning" ] || fail "failed provisioning"

transition "$TASK" "ready" "controller" "booted" >/dev/null
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "ready" ] || fail "failed ready"

transition "$TASK" "running" "agent" "executing" >/dev/null
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "running" ] || fail "failed running"

transition "$TASK" "review" "agent" "finished work" >/dev/null
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "review" ] || fail "failed review"

transition "$TASK" "completed" "human" "approved" >/dev/null
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "completed" ] || fail "failed completed"
echo "   happy path lifecycle verified ✓"

echo "--- 2b. Durability across server restart: verify state persisted after service restart"
kill "$SRV" 2>/dev/null || true
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
[ "$(curl -s "$API/tasks/$TASK" -H "$AUTH" | jq -r .status)" = "completed" ] || fail "task state not preserved across restart"
echo "   persisted state verified across service restart ✓"

echo "--- 3. Terminal state completed rejects outgoing transitions (409)"
STATUS=$(transition_status "$TASK" "running" "human" "retry")
[ "$STATUS" = "409" ] || fail "expected 409 when transitioning from terminal completed, got: $STATUS"
echo "   terminal state locked ✓"

echo "--- 4. Illegal FSM transition rejected (409)"
TASK2="t-fsm-02"
mkdir -p "$PVM_STATE_ROOT/$TASK2"
echo "{\"id\":\"$TASK2\",\"name\":\"$TASK2\",\"status\":\"provisioning\"}" > "$PVM_STATE_ROOT/$TASK2/state.json"
STATUS=$(transition_status "$TASK2" "completed" "human" "skip")
[ "$STATUS" = "409" ] || fail "expected 409 for illegal edge provisioning->completed, got: $STATUS"
echo "   illegal edge rejected 409 ✓"

echo "--- 5. Quarantine transition from running status and idempotent re-application"
TASK3="t-fsm-03"
mkdir -p "$PVM_STATE_ROOT/$TASK3"
echo "{\"id\":\"$TASK3\",\"name\":\"$TASK3\",\"status\":\"running\"}" > "$PVM_STATE_ROOT/$TASK3/state.json"
STATUS=$(transition_status "$TASK3" "quarantined" "incident" "anomaly detected")
[ "$STATUS" = "200" ] || fail "failed quarantine transition: $STATUS"
[ "$(curl -s "$API/tasks/$TASK3" -H "$AUTH" | jq -r .status)" = "quarantined" ] || fail "failed quarantine status check"
COUNT1=$(curl -s "$API/tasks/$TASK3" -H "$AUTH" | jq -r '.transitions | length')
[ "$COUNT1" = "1" ] || fail "expected 1 transition, got: $COUNT1"

# Repeated submission of the same valid transition (idempotent from==to edge)
STATUS2=$(transition_status "$TASK3" "quarantined" "incident" "repeated notice")
[ "$STATUS2" = "200" ] || fail "expected 200 for idempotent transition, got: $STATUS2"
[ "$(curl -s "$API/tasks/$TASK3" -H "$AUTH" | jq -r .status)" = "quarantined" ] || fail "status changed unexpectedly after idempotent transition"
COUNT2=$(curl -s "$API/tasks/$TASK3" -H "$AUTH" | jq -r '.transitions | length')
[ "$COUNT2" = "2" ] || fail "expected 2 recorded transitions, got: $COUNT2"
echo "   quarantine transition and idempotent re-transition verified ✓"

echo ""
echo "✅ 21_test_state_fsm_durability: ALL PASS"
