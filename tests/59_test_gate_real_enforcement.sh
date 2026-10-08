#!/usr/bin/env bash
# 59_test_gate_real_enforcement.sh — gate 真断言伴生（对应 46 sim）。
# 不断言 verdict JSON 形状，断言执行副作用：
#   1. FAIL  verdict 必须落一条可验证的审计行（gate:fail），且链校验仍过；
#   2. FAIL 必须触发 incident（artifact:gate-failed），且未 PASS 前无 gate:pass 行；
#   3. 同一 task 的干净 bundle 仍能 PASS（无粘滞误杀），PASS 后才出现 gate:pass。
# CI-safe：无内核、无 root；只用已有 HTTP API（与 46 相同的端点）。
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

PORT=18059
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
    curl -sf -H "$AUTH" "$API/incidents" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/incidents" >/dev/null || fail "server failed to start"

TASK="t-gate-real"
mkdir -p "$PVM_STATE_ROOT/$TASK"
cat > "$PVM_STATE_ROOT/$TASK/state.json" <<EOF
{"id":"$TASK","name":"$TASK","status":"running","pid":99999}
EOF
cat > "$PVM_STATE_ROOT/$TASK/spec.json" <<'EOF'
{
  "runtime": {"name": "t-gate-real"},
  "artifacts": {
    "declared": ["report.md"],
    "require_tests_passed": true,
    "block_secrets": true
  }
}
EOF

# Encode $1 as base64 on stdout without line wrapping or a trailing newline.
b64() { printf '%s' "$1" | base64 -w0; }
# POST the JSON payload in $1 to $API/gate/verify using $AUTH; print the response
# body to stdout and return curl's status (nonzero for HTTP or transport errors).
gate() { curl -sf -X POST "$API/gate/verify" -H "$AUTH" -H "Content-Type: application/json" -d "$1"; }

echo "--- 1. smuggled bundle FAIL：审计必须有 gate:fail 行，且链校验过"
V=$(gate "{\"task_id\":\"$TASK\",\"claimed_ok\":true,\"build_log\":\"go test ./...\\nok\\nPASS\",\"files\":{\"smuggled.txt\":\"$(b64 hello)\"}}")
echo "$V" | jq -e '.passed == false' >/dev/null || fail "smuggled must fail: $V"
curl -sf -H "$AUTH" "$API/audit/$TASK/verify" | jq -e '.valid == true' >/dev/null || fail "audit chain must verify after FAIL"
AUD=$(curl -sf -H "$AUTH" "$API/audit/$TASK")
echo "$AUD" | jq -e 'any(.action == "artifact_gate" and .decision == "deny")' >/dev/null || fail "FAIL must leave a gate audit row: $AUD"
echo "$AUD" | jq -e 'any(.action == "artifact_gate" and .decision == "allow") | not' >/dev/null || fail "no gate:pass may exist before a PASS: $AUD"

echo "--- 2. FAIL 必须触发 incident，且未 PASS 前 releases 仍为空"
INC=$(curl -sf -H "$AUTH" "$API/incidents")
echo "$INC" | jq -e 'any(.signal == "artifact:gate-failed")' >/dev/null || fail "gate sensor must fire: $INC"

echo "--- 3. 干净 bundle PASS：出现 gate:pass，且链依然过"
LOG=$(printf '$ go test ./...\nok  pkg  0.1s\nPASS')
V=$(gate "$(jq -nc --arg log "$LOG" --arg b64 "$(b64 'all good')" \
    '{task_id:"t-gate-real",claimed_ok:true,build_log:$log,files:{"report.md":$b64}}')")
echo "$V" | jq -e '.passed == true' >/dev/null || fail "clean bundle must pass: $V"
AUD2=$(curl -sf -H "$AUTH" "$API/audit/$TASK")
echo "$AUD2" | jq -e 'any(.action == "artifact_gate" and .decision == "allow")' >/dev/null || fail "PASS must leave gate:pass: $AUD2"
curl -sf -H "$AUTH" "$API/audit/$TASK/verify" | jq -e '.valid == true' >/dev/null || fail "audit chain must verify after PASS"

echo "✅ 59 gate real enforcement suite passed"
