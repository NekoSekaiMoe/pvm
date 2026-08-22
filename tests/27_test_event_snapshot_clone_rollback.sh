#!/usr/bin/env bash
# 27_test_event_snapshot_clone_rollback.sh — tests for event-level snapshots,
# instant cloning (zero-copy CoW branching), and historical rollback with audit verification.
# Does NOT require a UML kernel; safe to run in CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

PORT=41890
SECRET="test-sec-snap-$$"
export API_SECRET="$SECRET"
export PVM_STATE_ROOT="$TMP/containers"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_VOLUME_ROOT="$TMP/volumes"
export PVM_COW_ROOT="$TMP/cow"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_VOLUME_ROOT" "$PVM_COW_ROOT"

echo "=== Building agentpvm ==="
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "=== Starting E2B API server on port $PORT ==="
"$TMP/agentpvm" api --port "$PORT" >"$TMP/srv.log" 2>&1 &
SRV=$!

READY=0
for _ in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$PORT/api/containers" -H "Authorization: Bearer $SECRET" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done
[ "$READY" = "1" ] || fail "server failed to become ready on port $PORT"

AUTH="Authorization: Bearer $SECRET"
JSON_HDR="Content-Type: application/json"

fail() {
    echo "FAIL: $*" >&2
    if [ -f "$TMP/srv.log" ]; then
        echo "=== Server Log ==="
        cat "$TMP/srv.log"
    fi
    exit 1
}

# =========================================================================
# Part 1: Event-Level Snapshot Lifecycle
# =========================================================================
echo "--- 1. Event Snapshot Lifecycle ---"

TASK_ID="task-snap-01"
mkdir -p "$PVM_STATE_ROOT/$TASK_ID"
cat << JSON > "$PVM_STATE_ROOT/$TASK_ID/state.json"
{
  "id": "$TASK_ID",
  "name": "$TASK_ID",
  "status": "running",
  "pid": 12345
}
JSON

# 1.1 Create snapshot linked to event
SNAP_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/snapshots" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"event_id":"evt-step-101","audit_hash":"sha256:abc123456","metadata":{"tool":"bash_exec","cmd":"ls -la"}}')

SNAP_ID=$(echo "$SNAP_RESP" | jq -r .id)
[ -n "$SNAP_ID" ] && [ "$SNAP_ID" != "null" ] || fail "snapshot ID missing in response: $SNAP_RESP"
EVENT_ID=$(echo "$SNAP_RESP" | jq -r .event_id)
[ "$EVENT_ID" = "evt-step-101" ] || fail "event_id missing in response: $SNAP_RESP"
echo "   Snapshot created: $SNAP_ID ✓"

# 1.2 List snapshots
LIST_RESP=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/snapshots" -H "$AUTH")
echo "$LIST_RESP" | grep -q "$SNAP_ID" || fail "snapshot not in list: $LIST_RESP"
echo "   Snapshot listed in task snapshot index ✓"

# 1.3 Get snapshot detail
GET_RESP=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/snapshots/$SNAP_ID" -H "$AUTH")
[ "$(echo "$GET_RESP" | jq -r .event_id)" = "evt-step-101" ] || fail "snapshot detail mismatch: $GET_RESP"
echo "   Snapshot detail verified ✓"

# =========================================================================
# Part 2: Instant Task & Container Cloning
# =========================================================================
echo "--- 2. Instant Clone ---"

CLONE_TASK_ID="task-cloned-01"
CLONE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"new_id\":\"$CLONE_TASK_ID\"}")

[ "$(echo "$CLONE_RESP" | jq -r .status)" = "cloned" ] || fail "clone failed: $CLONE_RESP"
[ "$(echo "$CLONE_RESP" | jq -r .id)" = "$CLONE_TASK_ID" ] || fail "new_id missing: $CLONE_RESP"
echo "   Task cloned instantly to $CLONE_TASK_ID ✓"

# Verify cloned task state is isolated and ready
CLONED_STATE=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$CLONE_TASK_ID" -H "$AUTH")
[ "$(echo "$CLONED_STATE" | jq -r .status)" = "ready" ] || fail "cloned state not ready: $CLONED_STATE"
[ "$(echo "$CLONED_STATE" | jq -r .pid)" = "0" ] || fail "cloned pid should be 0: $CLONED_STATE"
echo "   Cloned task state verified as ready and isolated ✓"

# Verify duplicate clone returns 409 Conflict
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"new_id\":\"$CLONE_TASK_ID\"}")
[ "$HTTP_CODE" = "409" ] || fail "expected 409 for duplicate clone, got $HTTP_CODE"
echo "   Duplicate clone rejected with 409 Conflict ✓"

# Container route parity: /api/containers/:id/clone
CONT_CLONE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/containers/$TASK_ID/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"new_id":"cont-cloned-02"}')
[ "$(echo "$CONT_CLONE_RESP" | jq -r .status)" = "cloned" ] || fail "container clone failed: $CONT_CLONE_RESP"
echo "   Container clone endpoint verified ✓"

# =========================================================================
# Part 3: Historical Rollback
# =========================================================================
echo "--- 3. Historical Rollback ---"

# Alter task status to failed
curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/transition" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"to":"failed","actor":"system","reason":"simulated error"}' >/dev/null

STATE_BEFORE_RB=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$TASK_ID" -H "$AUTH")
[ "$(echo "$STATE_BEFORE_RB" | jq -r .status)" = "failed" ] || fail "transition to failed failed"

# Rollback to snapshot
RB_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/rollback" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"snapshot_id\":\"$SNAP_ID\"}")
[ "$(echo "$RB_RESP" | jq -r .status)" = "rolled_back" ] || fail "rollback failed: $RB_RESP"

STATE_AFTER_RB=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$TASK_ID" -H "$AUTH")
echo "$STATE_AFTER_RB" | grep -q '"status":"running"' || fail "state not restored to running: $STATE_AFTER_RB"
echo "   Task state successfully rolled back to snapshot point ✓"

# Verify audit trail recorded rollback and chain is intact
AUDIT_VERIFY=$(curl -s "http://127.0.0.1:$PORT/api/audit/$TASK_ID/verify" -H "$AUTH")
echo "$AUDIT_VERIFY" | grep -q '"valid":true' || fail "audit chain broken after rollback: $AUDIT_VERIFY"
echo "   Audit chain verified after rollback ✓"

# Non-existent snapshot rollback returns 404
RB_404=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/rollback" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"snapshot_id":"snap-does-not-exist"}')
[ "$RB_404" = "404" ] || fail "expected 404 for invalid rollback snapshot, got $RB_404"
echo "   Invalid snapshot rollback returned 404 ✓"

# =========================================================================
# Part 4: Volume Cloning & Rollback
# =========================================================================
echo "--- 4. Volume Cloning & Rollback ---"

# Create volume
VOL_CREATE=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"name":"vol-test-01","driver":"builtin"}')
echo "$VOL_CREATE" | grep -q "vol-test-01" || fail "volume create failed: $VOL_CREATE"

# Clone volume
VOL_CLONE=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes/vol-test-01/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"new_id":"vol-test-01-cloned"}')
echo "$VOL_CLONE" | grep -q '"status":"cloned"' || fail "volume clone failed: $VOL_CLONE"

# Verify cloned volume appears in list
VOL_LIST=$(curl -s "http://127.0.0.1:$PORT/api/volumes" -H "$AUTH")
echo "$VOL_LIST" | grep -q "vol-test-01-cloned" || fail "cloned volume not in list: $VOL_LIST"
echo "   Volume cloned and listed successfully ✓"

# =========================================================================
# Part 5: CLI Subcommand Verification
# =========================================================================
echo "--- 5. CLI Subcommand Verification ---"

CLI_TASK="cli-task-01"
mkdir -p "$PVM_STATE_ROOT/$CLI_TASK"
cat << JSON > "$PVM_STATE_ROOT/$CLI_TASK/state.json"
{
  "id": "$CLI_TASK",
  "status": "ready"
}
JSON

# CLI create snapshot
CLI_SNAP_OUT=$("$TMP/agentpvm" snapshot create "$CLI_TASK" "cli-evt-1" "sha256:cli123")
echo "$CLI_SNAP_OUT" | grep -q "Event snapshot created" || fail "CLI snapshot create failed: $CLI_SNAP_OUT"
CLI_SNAP_ID=$(echo "$CLI_SNAP_OUT" | grep -o 'snap-[^ ]*' | head -1)

# CLI list snapshots
CLI_LIST_OUT=$("$TMP/agentpvm" snapshot list "$CLI_TASK")
echo "$CLI_LIST_OUT" | grep -q "$CLI_SNAP_ID" || fail "CLI snapshot list failed: $CLI_LIST_OUT"
echo "   CLI snapshot create & list verified ✓"

# CLI clone
CLI_CLONE_OUT=$("$TMP/agentpvm" snapshot clone "$CLI_TASK" "cli-task-cloned")
echo "$CLI_CLONE_OUT" | grep -q "Cloned cli-task-01 -> cli-task-cloned" || fail "CLI clone failed: $CLI_CLONE_OUT"
[ -f "$PVM_STATE_ROOT/cli-task-cloned/state.json" ] || fail "cloned state file missing"
echo "   CLI snapshot clone verified ✓"

# CLI rollback
CLI_RB_OUT=$("$TMP/agentpvm" snapshot rollback "$CLI_TASK" "$CLI_SNAP_ID")
echo "$CLI_RB_OUT" | grep -q "Rolled back" || fail "CLI rollback failed: $CLI_RB_OUT"
echo "   CLI snapshot rollback verified ✓"

echo ""
echo "✅ 27_test_event_snapshot_clone_rollback: ALL PASS"
