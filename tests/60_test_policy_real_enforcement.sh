#!/usr/bin/env bash
# 60_test_policy_real_enforcement.sh — policy 真断言伴生（对应 14/45 sim）。
# 关键区别：全程不设 PVM_EXEC_SIM（无 sim 后端），断言决策层与执行层分离：
#   1. deny 规则必须 403，且审计只有 exec:deny、绝无 exec:ok（真没跑起来）；
#   2. approve 规则未审批前必须 202，且同样无 exec:ok；
#   3. 审批通过后恰好放行一次（Allow once），第二次回到 202/403（无粘滞放行）。
# CI-safe：无内核、无 guest；console 缺席正是断言点（sim 下反而看不出来）。
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
unset PVM_EXEC_SIM

PORT=18060
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

# Print the failure message in $1 to stdout and exit the script with status 1.
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
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start"

TASK="t-pol-real"
mkdir -p "$PVM_STATE_ROOT/$TASK"
cat > "$PVM_STATE_ROOT/$TASK/state.json" <<EOF
{"id":"$TASK","name":"$TASK","status":"running","pid":99999}
EOF

echo "--- 1. register rules: read=allow, deploy=approve(prod), pay=deny"
curl -sf -X POST "$API/policy/$TASK" -H "$AUTH" -H "Content-Type: application/json" -d '{
  "rules": [
    {"name":"read-files","action":"allow","effect":"read"},
    {"name":"deploy","action":"approve","effect":"prod"},
    {"name":"pay","action":"deny"},
    {"name":"*","action":"deny","reason":"default deny"}
  ], "force": true}' >/dev/null || fail "policy register"

echo "--- 2. deny 403 且无 exec:ok（真没执行）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=$TASK" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"pay amount=100"}')
[ "$CODE" = "403" ] || fail "deny must 403, got $CODE"
AUD=$(curl -sf -H "$AUTH" "$API/audit/$TASK")
echo "$AUD" | jq -e 'any(.action == "tool:pay" and .decision == "deny")' >/dev/null || fail "deny must leave an audit deny row: $AUD"
echo "$AUD" | jq -e 'any(.phase == "execution" and (.decision == "allow" or .decision == "constrain")) | not' >/dev/null \
    || fail "deny must never produce exec:ok: $AUD"

echo "--- 3. approve 未审批前 202，且无 exec:ok"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=$TASK" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"deploy env=prod effect=prod"}')
[ "$CODE" = "202" ] || fail "approve-class must 202, got $CODE"
AUD2=$(curl -sf -H "$AUTH" "$API/audit/$TASK")
echo "$AUD2" | jq -e 'any(.phase == "execution" and (.decision == "allow" or .decision == "constrain")) | not' >/dev/null \
    || fail "pre-approval must not execute: $AUD2"

echo "--- 4. 审批后恰好放行一次，第二次回到 202/403"
TICKET=$(curl -sf -X POST "$API/approvals" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"task_id\":\"$TASK\",\"tool\":\"deploy\",\"params\":{\"env\":\"prod\"}}")
TID=$(echo "$TICKET" | jq -r '.id // .ticket.id // empty')
[ -n "$TID" ] || fail "ticket create failed: $TICKET"
curl -sf -X POST "$API/approvals/$TID/decide" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"approved":true}' >/dev/null || fail "ticket approve failed"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=$TASK" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"deploy env=prod effect=prod"}')
[ "$CODE" = "200" ] || fail "post-approval first exec must 200, got $CODE"
CODE2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=$TASK" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"deploy env=prod effect=prod"}')
case "$CODE2" in 202|403) : ;; *) fail "second exec must return to 202/403 (Allow once), got $CODE2" ;; esac

echo "✅ 60 policy real enforcement suite passed"
