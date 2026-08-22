#!/usr/bin/env bash
# 24_test_tasks_audit_api.sh — black-box REST test of the task-read endpoints,
# load-spec path mode (PVM_SPEC_ROOT sandbox), and the audit ledger read API.
# Does NOT require a UML kernel; only needs the agentpvm binary and curl + jq.
# Safe to run in CI.
#
# Covers: GET /api/tasks (list), GET /api/tasks/:id (400/404/200),
# transition on unknown task (404), POST /api/tasks/load-spec path mode
# (disabled without PVM_SPEC_ROOT, traversal escape rejected, in-root ok),
# GET /api/audit/:id (records written by the Artifact Gate) + verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18084
API="http://127.0.0.1:$PORT/api"
export API_SECRET="secret"
AUTH="Authorization: Bearer secret"

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT (no PVM_SPEC_ROOT)"
# The first boot asserts the path-loading-disabled branch; a PVM_SPEC_ROOT
# inherited from the caller's environment would flip that branch and fail
# the test for environment reasons, not code reasons.
unset PVM_SPEC_ROOT

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
http_code() { # method path [json-body]
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}
start_server() { # waits until ready
    "$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
    SRV=$!
    for _ in $(seq 1 40); do
        if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then return 0; fi
        sleep 0.25
    done
    echo "❌ server did not become ready"; exit 1
}



start_server

# --- seed two tasks by hand into the state dir ---
mkdir -p "$PVM_STATE_ROOT/task-a" "$PVM_STATE_ROOT/task-b"
echo '{"id":"task-a","name":"task-a","status":"pending"}' > "$PVM_STATE_ROOT/task-a/state.json"
echo '{"id":"task-b","name":"task-b","status":"pending"}' > "$PVM_STATE_ROOT/task-b/state.json"

# --- 1. GET /api/tasks lists seeded tasks ---
echo "--- tasks list"
IDS=$(req GET /tasks | jq -r '[.[].id] | sort | join(",")')
assert_status "$IDS" "task-a,task-b" "GET /tasks lists both seeds"
echo "   list contains both ✓"

# --- 2. GET /api/tasks/:id validation ---
echo "--- task detail validation"
HTTP=$(http_code GET "/tasks/bad%24id")
assert_status "$HTTP" "400" "invalid task id -> 400"
HTTP=$(http_code GET "/tasks/no-such-task")
assert_status "$HTTP" "404" "unknown task -> 404"
STATUS=$(req GET /tasks/task-a | jq -r .status)
assert_status "$STATUS" "pending" "seeded task readable"
echo "   detail gating ✓"

# --- 3. transition on unknown task -> 404 (before FSM evaluation) ---
echo "--- transition unknown task"
HTTP=$(http_code POST /tasks/no-such-task/transition '{"to":"provisioning","actor":"x","reason":"y"}')
assert_status "$HTTP" "404" "transition unknown task -> 404"
echo "   unknown 404 ✓"

# --- 4. load-spec path mode: PVM_SPEC_ROOT sandbox ---
echo "--- load-spec path mode"
# without PVM_SPEC_ROOT the path mode must be disabled entirely
HTTP=$(http_code POST /tasks/load-spec "{\"path\":\"$TMP/specs/t.toml\"}")
assert_status "$HTTP" "400" "path loading disabled without PVM_SPEC_ROOT"
OUT=$(req POST /tasks/load-spec "{\"path\":\"$TMP/specs/t.toml\"}")
ERR=$(printf '%s' "$OUT" | jq -r '.error // empty' | grep -c "PVM_SPEC_ROOT" || true)
[ "$ERR" -ge 1 ] || { echo "❌ expected PVM_SPEC_ROOT hint: $OUT"; exit 1; }

mkdir -p "$TMP/specs"
cat > "$TMP/specs/t.toml" <<'EOF'
version=1
caller="alice"
[runtime]
name="path-loaded"
memory="256M"
[kernel]
path="./bin/linux"
EOF
# now enable the root: env is read once at startup, so restart the server
# with PVM_SPEC_ROOT set (this is also exactly how an operator would run it)
kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
export PVM_SPEC_ROOT="$TMP/specs"
echo "==> restarting server with PVM_SPEC_ROOT=$PVM_SPEC_ROOT"
start_server
OUT=$(req POST /tasks/load-spec "{\"path\":\"$TMP/specs/t.toml\"}")
FP=$(printf '%s' "$OUT" | jq -r .fingerprint)
[ -n "$FP" ] && [ "$FP" != "null" ] || { echo "❌ in-root path load failed: $OUT"; exit 1; }
HTTP=$(http_code POST /tasks/load-spec "{\"path\":\"$TMP/specs/t.toml\"}")
assert_status "$HTTP" "200" "absolute in-root path ok"
# traversal escape must be rejected even when the target file exists
HTTP=$(http_code POST /tasks/load-spec "{\"path\":\"$TMP/specs/../../etc/hostname\"}")
assert_status "$HTTP" "400" "spec-root traversal rejected"
echo "   spec-root sandbox ✓"

# --- 5. audit ledger read API ---
echo "--- audit read API"
# invalid id -> 400 before any directory access
HTTP=$(http_code GET "/audit/bad%24id")
assert_status "$HTTP" "400" "audit rejects invalid id"
# unknown-but-valid id -> empty ledger, serialized as [] (non-nil slice)
TYPE=$(req GET /audit/empty-ledger | jq -r 'type')
assert_status "$TYPE" "array" "empty ledger is [], not null"
N=$(req GET /audit/empty-ledger | jq 'length')
assert_status "$N" "0" "empty ledger has no records"

# the Artifact Gate records a verdict regardless of outcome -> use it to
# produce a real ledger row, then read it back through GET /audit/:id
req POST /gate/verify '{"task_id":"audited","diff":"","build_log":"","claimed_ok":true}' >/dev/null
N=$(req GET /audit/audited | jq 'length')
[ "$N" -ge 1 ] || { echo "❌ expected >=1 audit record after gate verify"; exit 1;}
HASH=$(req GET /audit/audited | jq -r '.[0].hash')
[ -n "$HASH" ] && [ "$HASH" != "null" ] || { echo "❌ record missing hash chain field"; exit 1; }
ACTION=$(req GET /audit/audited | jq -r '.[0].action')
assert_status "$ACTION" "artifact_gate" "record action is artifact_gate"
VALID=$(req GET /audit/audited/verify | jq -r .valid)
assert_status "$VALID" "true" "populated ledger verifies clean"
echo "   ledger read + chain verify ✓ ($N record)"

echo ""
echo "✅ 24_test_tasks_audit_api: ALL PASS"
