#!/usr/bin/env bash
# 05_test_controlplane_api.sh — black-box REST test of the new control-plane
# endpoints. Does NOT require a UML kernel; only needs the agentpvm binary and
# curl + jq. Safe to run in CI.
#
# Covers: /api/tasks/load-spec, /api/tasks transition (FSM), /api/audit verify,
# /api/approvals create+decide, /api/pool warm+stats, /api/gate/verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18081
API="http://127.0.0.1:$PORT/api"
# The server refuses to start without a secret (no default credential);
# tests/13 covers the custom-secret path, this one uses the conventional one.
export API_SECRET="secret"
AUTH="Authorization: Bearer secret"

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

echo "==> starting server on :$PORT"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done

req() { # method path [json-body]
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}
assert_status() { # actual expected name
    [ "$1" = "$2" ] || { echo "❌ $3: expected $2, got $1"; exit 1; }
}

# --- 1. tasks/load-spec (valid) ---
echo "--- tasks/load-spec (valid)"
TOML='version=1
caller="alice"
[runtime]
name="tk1"
memory="512M"
[kernel]
path="./bin/linux"
'
OUT=$(req POST /tasks/load-spec "{\"content\":$(printf '%s' "$TOML" | jq -Rs .)}")
FP=$(printf '%s' "$OUT" | jq -r .fingerprint)
[ -n "$FP" ] && [ "$FP" != "null" ] || { echo "❌ load-spec: no fingerprint: $OUT"; exit 1; }
echo "   fp=$FP ✓"

# --- 2. tasks/load-spec (reject bad caller) ---
echo "--- tasks/load-spec (bad: missing caller)"
OUT=$(req POST /tasks/load-spec '{"content":"version=1\n[runtime]\nname=x\n"}')
STATUS=$(printf '%s' "$OUT" | jq -r 'has("error")')
[ "$STATUS" = "true" ] || { echo "❌ expected error for missing caller: $OUT"; exit 1; }
echo "   rejected ✓"

# --- 3. FSM transition ---
echo "--- tasks transition (FSM)"
# seed a task by hand into state dir
mkdir -p "$PVM_STATE_ROOT/tk2"
echo '{"id":"tk2","name":"tk2","status":"pending"}' > "$PVM_STATE_ROOT/tk2/state.json"
req POST /tasks/tk2/transition '{"to":"provisioning","actor":"controller","reason":"go"}' >/dev/null
STATUS=$(curl -s "$API/tasks/tk2" -H "$AUTH" | jq -r .status)
assert_status "$STATUS" "provisioning" "valid transition pending->provisioning"
echo "   pending->provisioning ✓"

# invalid edge: provisioning -> suspended (must be 409 conflict)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/tasks/tk2/transition" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"to":"suspended","actor":"x"}')
assert_status "$HTTP" "409" "invalid transition rejected"
echo "   illegal edge 409 ✓"

# --- 4. audit verify ---
echo "--- audit verify (tamper-evident)"
# create a ledger with two records via the in-process audit package isn't
# reachable from shell; instead exercise it through the policy gateway path
# by warming/creating approval tickets (which write audit rows). For a pure
# smoke we just verify the empty-ledger path returns valid=true.
OUT=$(curl -s "$API/audit/tk-nonexistent/verify" -H "$AUTH")
VALID=$(printf '%s' "$OUT" | jq -r .valid)
assert_status "$VALID" "true" "empty ledger verifies clean"
echo "   empty ledger valid ✓"

# --- 5. approvals create + decide ---
echo "--- approvals create + decide"
# first create an un-approved pending ticket
echo '{"id":"tk3","name":"tk3","status":"pending"}' > /dev/null
TID=$(req POST /approvals '{"task_id":"tk3","tool":"send_email","target":"prod","params":{"to":"x@y.com"},"why":"first"}' | jq -r .id)
[ -n "$TID" ] || { echo "❌ no ticket id"; exit 1; }

# duplicate (same task+tool+params) while still pending must be rejected (409)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/approvals" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"task_id":"tk3","tool":"send_email","target":"prod","params":{"to":"x@y.com"}}')
assert_status "$HTTP" "409" "duplicate pending ticket rejected"
echo "   duplicate rejected ✓"

# now decide it
STATE=$(req POST "/approvals/$TID/decide" '{"approved":true,"by":"ui"}' | jq -r .state)
assert_status "$STATE" "approved" "approval decided"
echo "   approve ticket ✓"

# --- 6. pool warm + stats ---
echo "--- pool warm + stats"
CREATED=$(req POST /pool/warm '{"template":{"name":"alpine","memory":"256M","cpu":1},"n":2}' | jq -r .created)
assert_status "$CREATED" "2" "warm created 2"
READY=$(curl -s "$API/pool/stats" -H "$AUTH" | jq -r .ready)
assert_status "$READY" "2" "stats ready=2"
echo "   warm + stats ✓"

# --- 7. gate/verify rejects secret ---
echo "--- gate/verify (secret scan)"
PASSED=$(req POST /gate/verify '{"task_id":"tk4","diff":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","claimed_ok":true}' | jq -r .passed)
assert_status "$PASSED" "false" "gate rejects GitHub token"
echo "   secret blocked ✓"

# --- 8. /api/exec requires task id (400) ---
echo "--- /exec requires task id"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/exec" \
    -H "$AUTH" -H "Content-Type: application/json" -d '{"cmd":"ls"}')
assert_status "$HTTP" "400" "/exec without task id -> 400"
echo "   /exec gating ✓"

echo ""
echo "✅ 05_test_controlplane_api: ALL PASS"
