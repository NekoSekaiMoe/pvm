#!/usr/bin/env bash
# 45_test_exec_sim_gateway.sh — tool gateway full loop with the sim executor:
# register rules via /api/policy, drive /api/exec deny → approve-202 →
# approval unlocks ONE execution (Allow once), console tail endpoint.
# CI-safe (PVM_EXEC_SIM=1; no guest needed).
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

PORT=18046
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"
export PVM_EXEC_SIM=1

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

mkdir -p "$PVM_STATE_ROOT/t-gw"
cat > "$PVM_STATE_ROOT/t-gw/state.json" <<EOF
{"id":"t-gw","name":"t-gw","status":"running","pid":99999}
EOF

echo "--- 1. register rules: read=allow, deploy=approve(prod), pay=deny"
curl -sf -X POST "$API/policy/t-gw" -H "$AUTH" -H "Content-Type: application/json" -d '{
  "rules": [
    {"name":"read-files","action":"allow","effect":"read"},
    {"name":"deploy","action":"approve","effect":"prod"},
    {"name":"pay","action":"deny"},
    {"name":"*","action":"deny","reason":"default deny"}
  ], "force": true}' >/dev/null || fail "policy register"

echo "--- 2. allow rule executes (sim)"
curl -sf -X POST "$API/exec?task=t-gw" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"read-files path=/etc/hosts effect=read"}' | jq -e '.ok == true' >/dev/null || fail "allow exec"

echo "--- 3. deny rule 403"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=t-gw" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"pay amount=100"}')
[ "$CODE" = "403" ] || fail "deny must 403, got $CODE"

echo "--- 4. approve rule returns 202 until a ticket is approved"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=t-gw" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"cmd":"deploy env=prod effect=prod"}')
[ "$CODE" = "202" ] || fail "approve-class must 202, got $CODE"

echo "--- 5. create + approve a matching ticket unlocks ONE execution"
TID=$(curl -sf -X POST "$API/approvals" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"task_id":"t-gw","tool":"deploy","target":"payments","params":{"env":"prod"},"why":"release"}' | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || fail "ticket create"
curl -sf -X POST "$API/approvals/$TID/decide" -H "$AUTH" -H "Content-Type: application/json" -d '{"approved":true,"by":"op"}' >/dev/null || fail "approve ticket"

RES=$(curl -sf -X POST "$API/exec?task=t-gw" -H "$AUTH" -H "Content-Type: application/json" -d '{"cmd":"deploy env=prod effect=prod"}')
echo "$RES" | jq -e '.ok == true' >/dev/null || fail "approved exec must run: $RES"

echo "--- 6. consumed ticket no longer unlocks"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec?task=t-gw" -H "$AUTH" -H "Content-Type: application/json" -d '{"cmd":"deploy env=prod effect=prod"}')
[ "$CODE" = "202" ] || fail "second run must require a NEW approval, got $CODE"

echo "--- 7. console tail endpoint answers 404 for task without session"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "$API/tasks/t-gw/console")
[ "$CODE" = "404" ] || fail "no-session console must 404, got $CODE"

echo "✅ 45 exec sim gateway suite passed"
