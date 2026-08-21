#!/usr/bin/env bash
# 14_test_policy_gateway.sh — E2E test for Tool/Policy Gateway & /api/exec command parser.
# Covers: Command argument parsing, missing task gating (400), unregistered task (403),
# policy rules endpoint (/api/policy/:task), and 202 approval vs 403 deny enforcement.
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

PORT=18094
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

echo "--- 1. /api/exec requires task ID (400)"
STATUS=$(req_status POST "/exec" '{"cmd":"read_file path=/etc/hosts"}')
[ "$STATUS" = "400" ] || fail "expected 400 when task ID missing, got: $STATUS"
echo "   missing task ID rejected 400 ✓"

echo "--- 2. /api/exec rejects empty command (400)"
STATUS=$(req_status POST "/exec?task=tk-1" '{"cmd":""}')
[ "$STATUS" = "400" ] || fail "expected 400 for empty cmd, got: $STATUS"
echo "   empty command rejected 400 ✓"

echo "--- 3. /api/exec rejects task with no policy gateway (403)"
STATUS=$(req_status POST "/exec?task=tk-unregistered" '{"cmd":"read_file path=/etc/hosts"}')
[ "$STATUS" = "403" ] || fail "expected 403 for unregistered task, got: $STATUS"
echo "   unregistered task returns 403 ✓"

echo "--- 4. GET /api/policy/:task returns 404 for unregistered task"
STATUS=$(req_status GET "/policy/tk-unregistered")
[ "$STATUS" = "404" ] || fail "expected 404 for non-existent policy, got: $STATUS"
echo "   non-existent policy 404 ✓"

echo "--- 5. Register policy gateway with action=approve and execute command with quoted spaces (202)"
REG_STATUS=$(req_status POST "/policy/tk-approve" '{"rules":[{"name":"send_msg","action":"approve"}]}')
[ "$REG_STATUS" = "200" ] || fail "failed to register policy rules for tk-approve: $REG_STATUS"
EXEC_STATUS=$(req_status POST "/exec?task=tk-approve" '{"cmd":"send_msg to=\"security-team\" message=\"hello world space test\""}')
[ "$EXEC_STATUS" = "202" ] || fail "expected 202 for approve action, got: $EXEC_STATUS"
echo "   approval required command with quoted spaces returned 202 ✓"

echo "--- 6. Register policy gateway with action=deny and execute command with quoted spaces (403)"
REG_STATUS=$(req_status POST "/policy/tk-deny" '{"rules":[{"name":"rm_file","action":"deny"}]}')
[ "$REG_STATUS" = "200" ] || fail "failed to register policy rules for tk-deny: $REG_STATUS"
EXEC_STATUS=$(req_status POST "/exec?task=tk-deny" '{"cmd":"rm_file path=\"/var/log/my test file.log\""}')
[ "$EXEC_STATUS" = "403" ] || fail "expected 403 for deny action, got: $EXEC_STATUS"
echo "   denied command with quoted spaces returned 403 ✓"

echo ""
echo "✅ 14_test_policy_gateway: ALL PASS"
