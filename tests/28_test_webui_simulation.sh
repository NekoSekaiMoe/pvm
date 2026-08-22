#!/usr/bin/env bash
# 28_test_webui_simulation.sh — end-to-end verification of WebUI HTML5 SPA
# routing, static assets, and page-dependent REST API workflows.
# Does NOT require a UML kernel; safe to run in CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

PORT=42380
SECRET="test-sec-webui-$$"
export API_SECRET="$SECRET"
export PVM_STATE_ROOT="$TMP/containers"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_VOLUME_ROOT="$TMP/volumes"
export PVM_COW_ROOT="$TMP/cow"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_VOLUME_ROOT" "$PVM_COW_ROOT"

echo "=== Building agentpvm ==="
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "=== Starting agentpvm WebUI server on port $PORT ==="
"$TMP/agentpvm" webui --port "$PORT" >"$TMP/webui.log" 2>&1 &
SRV=$!

READY=0
for _ in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done
[ "$READY" = "1" ] || fail "webui server failed to become ready on port $PORT"

AUTH="Authorization: Bearer $SECRET"
JSON_HDR="Content-Type: application/json"

fail() {
    echo "FAIL: $*" >&2
    if [ -f "$TMP/webui.log" ]; then
        echo "=== WebUI Server Log ==="
        cat "$TMP/webui.log"
    fi
    exit 1
}

# =========================================================================
# Step 1: WebUI HTML5 SPA Routing & Static Assets
# =========================================================================
echo "--- 1. WebUI HTML5 SPA Route Serving ---"

ROUTES=("/" "/tasks" "/volumes" "/approvals" "/policy" "/gate" "/identity" "/templates" "/pool")
for r in "${ROUTES[@]}"; do
    HTML=$(curl -s "http://127.0.0.1:$PORT$r")
    [ -n "$HTML" ] || fail "empty response for route $r"
    echo "$HTML" | grep -qi "<!DOCTYPE html" || fail "route $r did not return HTML document"
    echo "   Route $r -> 200 OK ✓"
done

# =========================================================================
# Step 2: Simulate Dashboard Page (index.vue)
# =========================================================================
echo "--- 2. Dashboard Interaction Simulation (index.vue) ---"

# 2.1 Load containers
CONT_RESP=$(curl -s "http://127.0.0.1:$PORT/api/containers" -H "$AUTH")
echo "$CONT_RESP" | grep -q "\[" || fail "invalid containers response: $CONT_RESP"

# 2.2 Load task list
TASK_RESP=$(curl -s "http://127.0.0.1:$PORT/api/tasks" -H "$AUTH")
echo "$TASK_RESP" | grep -q "\[" || fail "invalid tasks response: $TASK_RESP"

# 2.3 Load pool stats
POOL_RESP=$(curl -s "http://127.0.0.1:$PORT/api/pool/stats" -H "$AUTH")
echo "$POOL_RESP" | grep -q "total" || fail "invalid pool stats: $POOL_RESP"
echo "   Dashboard metrics & pollers verified ✓"

# =========================================================================
# Step 3: Simulate Tasks Page (tasks.vue)
# =========================================================================
echo "--- 3. Tasks Page Interaction Simulation (tasks.vue) ---"

# 3.1 Button Click: "Validate / Fingerprint" TaskSpec TOML
SPEC_TOML='version = 1
caller = "webui-tester"
tenant = "qa"
[runtime]
name = "webui-task"
cpu = 1000
memory = "512M"
[workspace]
base_image = "rootfs.img"
init = "/sbin/init"
[kernel]
path = "./bin/linux"
[network]
enabled = false
'
VAL_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/load-spec" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"content\":$(echo "$SPEC_TOML" | jq -Rs .)}")

echo "$VAL_RESP" | grep -q "fingerprint" || fail "validate spec failed: $VAL_RESP"
FP=$(echo "$VAL_RESP" | grep -o '"fingerprint":"[^"]*' | cut -d'"' -f4)
echo "   Spec Validated. Fingerprint: $FP ✓"

# 3.2 Create sample task on host
TASK_ID="webui-task-01"
mkdir -p "$PVM_STATE_ROOT/$TASK_ID"
cat << JSON > "$PVM_STATE_ROOT/$TASK_ID/state.json"
{
  "id": "$TASK_ID",
  "name": "$TASK_ID",
  "status": "ready",
  "tenant": "qa"
}
JSON

# 3.3 Button Click: FSM Transition
TRANS_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/transition" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"to":"running","actor":"human","reason":"user clicked transition in webui"}')
echo "$TRANS_RESP" | grep -q '"status":"running"' || fail "transition failed: $TRANS_RESP"
echo "   FSM Transition to running applied ✓"

# 3.4 Button Click: "Take Snapshot" (Event Snapshot)
SNAP_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/snapshots" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"event_id":"step_0042","audit_hash":"sha256:ui-test","metadata":{"ui_action":"modal_take_snapshot"}}')
echo "$SNAP_RESP" | grep -q "step_0042" || fail "take snapshot failed: $SNAP_RESP"
SNAP_ID=$(echo "$SNAP_RESP" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
echo "   Take Snapshot modal action created $SNAP_ID ✓"

# 3.5 Button Click: "Clone Task"
CLONE_TASK_ID="webui-task-cloned"
CLONE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"new_id\":\"$CLONE_TASK_ID\"}")
echo "$CLONE_RESP" | grep -q '"status":"cloned"' || fail "clone task failed: $CLONE_RESP"
echo "   Clone Task modal action cloned to $CLONE_TASK_ID ✓"

# 3.6 Button Click: "Rollback" in Snapshot modal
# Set status to failed first
curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/transition" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"to":"failed","actor":"system","reason":"crash"}' >/dev/null

RB_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/tasks/$TASK_ID/rollback" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"snapshot_id\":\"$SNAP_ID\"}")
echo "$RB_RESP" | grep -q '"status":"rolled_back"' || fail "rollback task failed: $RB_RESP"

ST_CHECK=$(curl -s "http://127.0.0.1:$PORT/api/tasks/$TASK_ID" -H "$AUTH")
echo "$ST_CHECK" | grep -q '"status":"running"' || fail "task state not restored after UI rollback: $ST_CHECK"
echo "   Rollback modal action successfully restored task state ✓"

# =========================================================================
# Step 4: Simulate Volumes Page (volumes.vue)
# =========================================================================
echo "--- 4. Volumes Page Interaction Simulation (volumes.vue) ---"

# 4.1 Button Click: "Create Volume" modal
VOL_NAME="ui-vol-alpha"
VOL_CREATE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"name\":\"$VOL_NAME\",\"driver\":\"builtin\"}")
echo "$VOL_CREATE_RESP" | grep -q "$VOL_NAME" || fail "create volume failed: $VOL_CREATE_RESP"
API_VOL_ID=$(echo "$VOL_CREATE_RESP" | jq -r .volume_id 2>/dev/null || echo "$VOL_NAME")
[ -n "$API_VOL_ID" ] && [ "$API_VOL_ID" != "null" ] || API_VOL_ID="$VOL_NAME"
echo "   Create Volume modal created $API_VOL_ID ✓"

# 4.2 Button Click: "Clone Volume"
VOL_CLONE_NAME="ui-vol-alpha-clone"
VOL_CLONE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes/$API_VOL_ID/clone" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"new_id\":\"$VOL_CLONE_NAME\"}")
echo "$VOL_CLONE_RESP" | grep -q '"status":"cloned"' || fail "clone volume failed: $VOL_CLONE_RESP"
echo "   Clone Volume action cloned to $VOL_CLONE_NAME ✓"

# 4.3 Button Click: "Delete Volume"
VOL_DEL_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://127.0.0.1:$PORT/api/volumes/$VOL_CLONE_NAME" -H "$AUTH")
[ "$VOL_DEL_RESP" = "204" ] || fail "delete volume failed with code $VOL_DEL_RESP"
echo "   Delete Volume action deleted $VOL_CLONE_NAME ✓"

# 4.4 Button Click: "Snapshot Volume" + "Rollback Volume" (restore)
VOL_RB_NAME="ui-vol-rb"
VOL_RB_CREATE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"name\":\"$VOL_RB_NAME\",\"driver\":\"builtin\",\"size\":1048576}")
echo "$VOL_RB_CREATE_RESP" | grep -q "$VOL_RB_NAME" || fail "create rollback volume failed: $VOL_RB_CREATE_RESP"

# Snapshot via the REST endpoint; a fresh volume avoids the
# dependent-reference rejection on rollback.
VOL_SNAP_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes/$VOL_RB_NAME/snapshots" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"snapshot":"ui-point"}')
echo "$VOL_SNAP_RESP" | grep -q '"status":"created"' || fail "snapshot volume failed: $VOL_SNAP_RESP"

# The rollback modal loads the volume's snapshot list for one-click pick.
VOL_SNAP_LIST=$(curl -s "http://127.0.0.1:$PORT/api/volumes/$VOL_RB_NAME/snapshots" -H "$AUTH")
echo "$VOL_SNAP_LIST" | grep -q '"name":"ui-point"' || fail "snapshot list missing ui-point: $VOL_SNAP_LIST"
echo "$VOL_SNAP_LIST" | grep -q '"origin_volume":"'"$VOL_RB_NAME"'"' || fail "snapshot origin mismatch: $VOL_SNAP_LIST"

echo "   Snapshot Volume action created ui-point and listed it ✓"

VOL_RB_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/volumes/$VOL_RB_NAME/rollback" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d "{\"snapshot\":\"ui-point\"}")
echo "$VOL_RB_RESP" | grep -q '"status":"rolled_back"' || fail "rollback volume failed: $VOL_RB_RESP"
[ "$(head -c 3 "$PVM_VOLUME_ROOT/$VOL_RB_NAME.qcow2")" = "QFI" ] || fail "rolled-back volume is not a qcow2 image"
VOL_RB_STATE=$(curl -s "http://127.0.0.1:$PORT/api/volumes/$VOL_RB_NAME" -H "$AUTH")
echo "$VOL_RB_STATE" | grep -q "$VOL_RB_NAME" || fail "volume state missing after rollback: $VOL_RB_STATE"
echo "   Rollback Volume action restored snapshot state ✓"

# =========================================================================
# Step 5: Simulate Approvals Page (approvals.vue)
# =========================================================================
echo "--- 5. Approvals Page Interaction Simulation (approvals.vue) ---"

# 5.1 Create approval ticket
APPR_REQ=$(curl -s -X POST "http://127.0.0.1:$PORT/api/approvals" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"task_id":"webui-task-01","tool":"bash","command":"rm -rf /tmp/data","risk_level":"high"}')
TICKET_ID=$(echo "$APPR_REQ" | grep -o '"ticket_id":"[^"]*' | cut -d'"' -f4 || echo "$APPR_REQ" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
[ -n "$TICKET_ID" ] || fail "failed to get ticket id: $APPR_REQ"

# 5.2 Button Click: "Approve"
APPR_DECIDE=$(curl -s -X POST "http://127.0.0.1:$PORT/api/approvals/$TICKET_ID/decide" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"approved":true,"by":"webui-operator"}')
echo "$APPR_DECIDE" | grep -qi '"state":"approved"' || fail "approve ticket failed: $APPR_DECIDE"
echo "   Approval Ticket $TICKET_ID approved via WebUI ✓"

# =========================================================================
# Step 6: Simulate Policy & Audit Pages (policy.vue, audit/[id].vue)
# =========================================================================
echo "--- 6. Policy & Audit Simulation (policy.vue, audit/[id].vue) ---"

# 6.1 Button Click: "Update Policy"
POL_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/policy/$TASK_ID" \
    -H "$AUTH" -H "$JSON_HDR" \
    -d '{"rules":[{"name":"bash","action":"allow"}]}')
echo "$POL_RESP" | grep -q "registered" || fail "update policy failed: $POL_RESP"

# 6.2 Load Audit Log & Verify Chain in Audit Page
AUDIT_LIST=$(curl -s "http://127.0.0.1:$PORT/api/audit/$TASK_ID" -H "$AUTH")
echo "$AUDIT_LIST" | grep -q "\[" || fail "audit list failed: $AUDIT_LIST"

AUDIT_VERIFY=$(curl -s "http://127.0.0.1:$PORT/api/audit/$TASK_ID/verify" -H "$AUTH")
echo "$AUDIT_VERIFY" | grep -q '"valid":true' || fail "audit verification failed: $AUDIT_VERIFY"
echo "   Audit Ledger & Policy loaded and verified ✓"

echo ""
echo "✅ 28_test_webui_simulation: ALL PASS"
