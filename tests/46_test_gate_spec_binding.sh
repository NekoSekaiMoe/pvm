#!/usr/bin/env bash
# 46_test_gate_spec_binding.sh — the artifact gate honors the task's
# spec.json artifacts policy: declare check, secret blocking vs advisory,
# and the gate-failure incident sensor.
# CI-safe.
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

PORT=18047
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
    curl -sf -H "$AUTH" "$API/incidents" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/incidents" >/dev/null || fail "server failed to start"

TASK="t-gate"
mkdir -p "$PVM_STATE_ROOT/$TASK"
cat > "$PVM_STATE_ROOT/$TASK/state.json" <<EOF
{"id":"$TASK","name":"$TASK","status":"running","pid":99999}
EOF
cat > "$PVM_STATE_ROOT/$TASK/spec.json" <<'EOF'
{
  "runtime": {"name": "t-gate"},
  "artifacts": {
    "declared": ["report.md"],
    "require_tests_passed": true,
    "block_secrets": true
  }
}
EOF

gate() { # body -> echo verdict json (files values are base64, matching
      # the API's map[string][]byte JSON contract)
    curl -sf -X POST "$API/gate/verify" -H "$AUTH" -H "Content-Type: application/json" -d "$1"
}

# base64 helpers for file bodies.
b64() { printf '%s' "$1" | base64 -w0; }

echo "--- 1. undeclared file fails the declare step"
V=$(gate "{\"task_id\":\"t-gate\",\"claimed_ok\":true,\"build_log\":\"go test ./...\\\nok\\\nPASS\",\"files\":{\"smuggled.txt\":\"$(b64 hello)\"}}")
echo "$V" | jq -e '.passed == false' >/dev/null || fail "undeclared must fail: $V"
echo "$V" | jq -e '.step.declare | startswith("fail")' >/dev/null || fail "declare step must fail: $V"

echo "--- 2. secret in a declared file fails when block_secrets=true"
SECRET="aws_secret_access_key=$(printf 'a%.0s' $(seq 1 40))"
V=$(gate "{\"task_id\":\"t-gate\",\"claimed_ok\":true,\"build_log\":\"go test ./...\nok\nPASS\",\"files\":{\"report.md\":\"$(b64 "$SECRET")\"}}")
echo "$V" | jq -e '.passed == false' >/dev/null || fail "secret must block: $V"
echo "$V" | jq -e '.step.secret_scan | startswith("fail")' >/dev/null || fail "secret_scan must fail: $V"

echo "--- 3. clean bundle with test evidence passes"
# Build the payload with jq so build_log carries REAL newlines: the old
# inline double-quoted JSON left literal "\\n" sequences, which the loose
# keyword-based tests_rerun verifier accepted but the strict (spec-bound)
# terminal-state match rejects — `^ok\s` must anchor on a real line.
LOG=$(printf '$ go test ./...\nok  pkg  0.1s\nPASS')
V=$(gate "$(jq -nc --arg log "$LOG" --arg b64 "$(b64 'all good')" \
    '{task_id:"t-gate",claimed_ok:true,build_log:$log,files:{"report.md":$b64}}')")
echo "$V" | jq -e '.passed == true' >/dev/null || fail "clean bundle must pass: $V"

echo "--- 4. strict tests: no evidence fails when require_tests_passed=true"
V=$(gate "{\"task_id\":\"t-gate\",\"claimed_ok\":true,\"build_log\":\"built it\",\"files\":{\"report.md\":\"$(b64 x)\"}}")
echo "$V" | jq -e '.passed == false' >/dev/null || fail "no test evidence must fail strict: $V"

echo "--- 5. failing gate reports an incident"
INC=$(curl -sf -H "$AUTH" "$API/incidents")
echo "$INC" | jq -e 'any(.signal == "artifact:gate-failed")' >/dev/null || fail "gate sensor must fire: $INC"

echo "--- 6. malformed diff fails baseline replay"
V=$(gate "{\"task_id\":\"t-gate\",\"diff\":\"@@ broken @@\\\n\",\"claimed_ok\":true,\"build_log\":\"PASS\",\"files\":{\"report.md\":\"$(b64 x)\"}}")
echo "$V" | jq -e '.step.baseline_replay | startswith("fail")' >/dev/null || fail "broken diff must fail replay: $V"

echo "✅ 46 gate spec binding suite passed"
