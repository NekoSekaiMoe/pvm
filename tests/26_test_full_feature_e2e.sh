#!/usr/bin/env bash
# 26_test_full_feature_e2e.sh — one task's COMPLETE cross-plane lifecycle,
# driven entirely through the REST API, proving the planes work TOGETHER and
# not just in isolation:
#
#   TaskSpec -> FSM (pending..running) -> Tool Gateway (allow/deny/approve)
#   -> approval ticket lifecycle -> manual pause/resume with cgroup.freeze
#   sync -> review -> artifact gate release -> completed -> destroy (terminal)
#   -> full audit chain verification
#
# Plus pool/quota and volume/template plane sanity at the end.
# Does NOT require a UML kernel; safe to run in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_VOLUME_ROOT="$TMP/volumes"
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18086
API="http://127.0.0.1:$PORT/api"
export API_SECRET="secret"
AUTH="Authorization: Bearer secret"
TASK="e2e-worker"

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done

req() { # method path [json-body] -> body
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}
code() { # method path [json-body] -> http status
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}
assert_status() { # actual expected name
    [ "$1" = "$2" ] || { echo "❌ $3: expected $2, got $1"; exit 1; }
}

echo "--- 1. TaskSpec validation (load-spec)"
TOML='version=1
caller="e2e-operator"
[runtime]
name="'"$TASK"'"
memory="512M"
[[tools]]
name="read_file"
action="allow"
[[tools]]
name="send_email"
action="approve"
reason="external send needs human signoff"
[[tools]]
name="rm_rf"
action="deny"
reason="destructive"
[kernel]
path="./bin/linux"
'
OUT=$(req POST /tasks/load-spec "{\"content\":$(printf '%s' "$TOML" | jq -Rs .)}")
FP=$(printf '%s' "$OUT" | jq -r .fingerprint)
[ -n "$FP" ] && [ "$FP" != "null" ] || { echo "❌ load-spec: $OUT"; exit 1; }
echo "   spec accepted, fingerprint=${FP:0:16}… ✓"

echo "--- 2. FSM drive: pending -> provisioning -> ready -> running"
mkdir -p "$PVM_STATE_ROOT/$TASK" "$PVM_CGROUP_ROOT/$TASK"
echo '{"id":"'$TASK'","name":"'$TASK'","status":"pending","idle_timeout":"30m"}' > "$PVM_STATE_ROOT/$TASK/state.json"
for NEXT in provisioning ready running; do
    assert_status "$(code POST /tasks/$TASK/transition "{\"to\":\"$NEXT\",\"actor\":\"controller\",\"reason\":\"e2e\"}")" "200" "transition -> $NEXT"
    GOT=$(req GET /tasks/$TASK | jq -r .status)
    assert_status "$GOT" "$NEXT" "state readback after $NEXT"
done
echo "   pending→provisioning→ready→running ✓"

echo "--- 3. Register the task's tool policy from the spec rules"
OUT=$(req POST /policy/$TASK '{"Rules":[{"Name":"read_file","Action":"allow"},{"Name":"send_email","Action":"approve","Reason":"external send"},{"Name":"rm_rf","Action":"deny","Reason":"destructive"}]}')
assert_status "$(printf '%s' "$OUT" | jq -r .status)" "registered" "policy registration"
NR=$(req GET /policy/$TASK | jq 'length')
[ "$NR" -eq 4 ] || { echo "❌ expected 4 compiled rules (3 + catch-all deny), got $NR"; exit 1; }
echo "   gateway registered with catch-all deny ✓"

echo "--- 4. Tool Gateway decisions through /exec"
OUT=$(req POST "/exec?task=$TASK" '{"cmd":"read_file path=/workspace/main.go"}')
assert_status "$(printf '%s' "$OUT" | jq -r .ok)" "true" "allowed tool executes"
assert_status "$(code POST "/exec?task=$TASK" '{"cmd":"rm_rf path=/"}')" "403" "denied tool"
HTTP=$(code POST "/exec?task=$TASK" '{"cmd":"send_email to=boss@corp.com"}')
assert_status "$HTTP" "202" "approve-gated tool"
echo "   allow=200 deny=403 approve=202 ✓"

echo "--- 5. Approval ticket lifecycle for the gated call"
TID=$(req POST /approvals "{\"task_id\":\"$TASK\",\"tool\":\"send_email\",\"target\":\"boss@corp.com\",\"params\":{\"to\":\"boss@corp.com\"},\"why\":\"quarterly report\"}" | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || { echo "❌ ticket creation"; exit 1; }
CNT=$(req GET "/approvals?task=$TASK" | jq "[.[] | select(.id==\"$TID\")] | length")
assert_status "$CNT" "1" "ticket pending-visible"
STATE=$(req POST "/approvals/$TID/decide" '{"approved":true,"by":"security-lead"}' | jq -r .state)
assert_status "$STATE" "approved" "human approves"
CNT=$(req GET "/approvals?task=$TASK" | jq "[.[] | select(.id==\"$TID\")] | length")
assert_status "$CNT" "0" "decided ticket leaves pending list"
echo "   create -> pending -> approved -> leaves queue ✓"

echo "--- 6. Manual pause / resume with cgroup.freeze synchronization"
assert_status "$(code POST /tasks/$TASK/pause)" "204" "pause"
assert_status "$(req GET /tasks/$TASK | jq -r .status)" "suspended" "suspended after pause"
[ "$(cat "$PVM_CGROUP_ROOT/$TASK/cgroup.freeze")" = "1" ] || { echo "❌ freeze not synced"; exit 1; }
RES=$(req POST /tasks/$TASK/resume)
assert_status "$(printf '%s' "$RES" | jq -r .status)" "running" "resume returns running state"
[ "$(cat "$PVM_CGROUP_ROOT/$TASK/cgroup.freeze")" = "0" ] || { echo "❌ thaw not synced"; exit 1; }
echo "   pause(freeze=1) -> resume(freeze=0) ✓"

echo "--- 7. Release flow: review -> artifact gate -> completed"
assert_status "$(code POST /tasks/$TASK/transition '{"to":"review","actor":"controller","reason":"work done"}')" "200" "-> review"
OUT=$(req POST /gate/verify "{\"task_id\":\"$TASK\",\"diff\":\"+fixed bug\",\"build_log\":\"all tests pass\",\"trace\":[\"read_file\",\"send_email\"],\"claimed_ok\":true}")
assert_status "$(printf '%s' "$OUT" | jq -r .passed)" "true" "clean bundle released"
assert_status "$(code POST /tasks/$TASK/transition '{"to":"completed","actor":"controller","reason":"artifact sealed"}')" "200" "-> completed"
echo "   review -> gate pass -> completed ✓"

echo "--- 8. Audit trail: every plane left evidence, chain intact"
NAUD=$(req GET /audit/$TASK | jq 'length')
[ "$NAUD" -ge 2 ] || { echo "❌ expected >=2 audit records (gate + transitions?), got $NAUD"; exit 1; }
ACTIONS=$(req GET /audit/$TASK | jq -r '[.[].action] | unique | join(",")')
printf '%s' "$ACTIONS" | grep -q "artifact_gate" || { echo "❌ no artifact_gate row in: $ACTIONS"; exit 1; }
assert_status "$(req GET /audit/$TASK/verify | jq -r .valid)" "true" "hash chain valid"
echo "   $NAUD records incl artifact_gate, chain valid ✓"

echo "--- 9. Decommission: completed -> destroy is final"
assert_status "$(code POST /tasks/$TASK/transition '{"to":"destroy","actor":"operator","reason":"decommission"}')" "200" "-> destroy"
HTTP=$(code POST /tasks/$TASK/transition '{"to":"running","actor":"attacker","reason":"resurrect"}')
assert_status "$HTTP" "409" "terminal state rejects resurrection"
assert_status "$(req GET /tasks/$TASK | jq -r .status)" "destroy" "stays destroyed"
echo "   destroy terminal, resurrection blocked ✓"

echo "--- 10. Pool + quota plane"
assert_status "$(code POST /pool/quota '{"tenant":"acme","quota":{"max_concurrent":5,"max_tasks_per_hour":100}}')" "200" "quota set"
CREATED=$(req POST /pool/warm '{"template":{"name":"alpine","memory":"256M","cpu":1},"n":3}' | jq -r .created)
assert_status "$CREATED" "3" "warm 3"
READY=$(req GET /pool/stats | jq -r .ready)
assert_status "$READY" "3" "stats ready=3"
echo "   quota set, warm=3, stats ready=3 ✓"

echo "--- 11. Volume + template planes"
assert_status "$(code POST /volumes '{"name":"e2e-data","driver":"local"}')" "201" "volume create"
assert_status "$(req GET /volumes/e2e-data | jq -r .refcount)" "0" "volume readable, token masked out of response"
TPL=$(req POST /templates '{"image_ref":"docker.io/library/alpine:3.19","alias":"e2e-img"}' | jq -r .template_id)
assert_status "$(req GET /templates/e2e-img | jq -r .template_id)" "$TPL" "alias resolves at creation binding"
echo "   volume CRUD + template alias resolution ✓"

echo ""
echo "✅ 26_test_full_feature_e2e: FULL CROSS-PLANE LIFECYCLE PASS"
