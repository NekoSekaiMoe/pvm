#!/usr/bin/env bash
# 23_test_container_api.sh — black-box REST test of the legacy E2B container
# endpoints that no other suite touches. Does NOT require a UML kernel; only
# needs the agentpvm binary and curl + jq. Safe to run in CI.
#
# Covers: GET /api/containers (list shape), GET /api/containers/:id/logs,
# DELETE /api/containers/:id, POST /api/containers/:id/snapshot|restore
# (id-validation paths), and the /api/containers/start request-validation
# chain (name format, CPU range, rootfs injection defense, memory parsing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18083
API="http://127.0.0.1:$PORT/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET.
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET=$(openssl rand -hex 16 2>/dev/null || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

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
# The loop alone can fall through without the server ever being ready; the
# poll's own curl doubles as the readiness probe (auth + startup combined).
curl -sf -H "$AUTH" "$API/containers" >/dev/null || {
    echo "❌ server did not become ready; $TMP/server.log contents:"
    cat "$TMP/server.log"
    exit 1
}

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

# --- 1. GET /api/containers returns valid JSON ---
# Empty and non-empty alike must be a JSON array ([] not null): the Go
# handlers guarantee a non-nil slice (regression-locked by
# TestAPI_EmptyListsAreArraysNotNull in internal/api).
echo "--- containers list shape"
BODY=$(req GET /containers)
TYPE=$(printf '%s' "$BODY" | jq -r 'type')
assert_status "$TYPE" "array" "GET /containers returns JSON array (empty state must be [], not null)"
# seed one record and the list must reflect it as an array element
mkdir -p "$PVM_STATE_ROOT/box1"
echo '{"id":"box1","name":"box1","status":"pending"}' > "$PVM_STATE_ROOT/box1/state.json"
COUNT=$(req GET /containers | jq 'length')
assert_status "$COUNT" "1" "seeded container listed"
echo "   list ok ✓"

# --- 2. logs endpoint id validation ---
echo "--- logs id validation"
# '$' is outside ^[a-zA-Z0-9_-]+$ -> must 400 before any filesystem access
HTTP=$(http_code GET "/containers/bad%24id/logs")
assert_status "$HTTP" "400" "logs rejects invalid id"
# well-formed but never-started id -> console.log missing -> 404
HTTP=$(http_code GET "/containers/no-such-box/logs")
assert_status "$HTTP" "404" "logs of unknown container -> 404"
echo "   logs gating ✓"

# --- 3. delete endpoint id validation ---
echo "--- delete id validation"
HTTP=$(http_code DELETE "/containers/bad%24id")
assert_status "$HTTP" "400" "delete rejects invalid id"
# well-formed unknown id: RemoveAll on a missing dir is a no-op -> 200 Deleted
BODY=$(req DELETE /containers/no-such-box)
assert_status "$BODY" "Deleted" "delete unknown container succeeds"
echo "   delete gating ✓"

# --- 4. snapshot / restore REST id validation ---
echo "--- snapshot/restore id validation"
HTTP=$(http_code POST "/containers/bad%24id/snapshot")
assert_status "$HTTP" "400" "snapshot rejects invalid id"
HTTP=$(http_code POST "/containers/bad%24id/restore")
assert_status "$HTTP" "400" "restore rejects invalid id"
# valid id but no such container: Export must fail (never write outside) ->
# anything but 400-rejected-or-crash; we accept 4xx/5xx error JSON
HTTP=$(http_code POST "/containers/no-such-box/snapshot")
[ "$HTTP" = "500" ] || [ "$HTTP" = "404" ] || { echo "❌ snapshot unknown container: got $HTTP"; exit 1; }
echo "   snapshot/restore gating ✓"

# --- 5. containers/start request validation chain ---
echo "--- containers/start validation"
# bad name format: assert the HTTP status like the rest of the chain (the
# body check alone would pass on any 4xx/5xx).
HTTP=$(http_code POST /containers/start '{"name":"bad name!"}')
assert_status "$HTTP" "400" "start bad name rejection"
OUT=$(req POST /containers/start '{"name":"bad name!"}')
ERR=$(printf '%s' "$OUT" | jq -r 'has("error")')
[ "$ERR" = "true" ] || { echo "❌ start bad name not rejected: $OUT"; exit 1; }
# CPU out of range
HTTP=$(http_code POST /containers/start '{"name":"ok1","cpu":9999}')
assert_status "$HTTP" "400" "start CPU range check"
# negative CPU
HTTP=$(http_code POST /containers/start '{"name":"ok1","cpu":-1}')
assert_status "$HTTP" "400" "start negative CPU check"
# rootfs kernel-cmdline injection defense: '..' traversal
HTTP=$(http_code POST /containers/start '{"name":"ok1","rootfs":"/var/lib/uml-container/images/../etc"}')
assert_status "$HTTP" "400" "start rootfs traversal rejected"
# rootfs outside the image root
HTTP=$(http_code POST /containers/start '{"name":"ok1","rootfs":"/etc"}')
assert_status "$HTTP" "400" "start rootfs outside image root rejected"
# unparseable memory
HTTP=$(http_code POST /containers/start '{"name":"ok1","rootfs":"/var/lib/uml-container/images/alpine","mem":"garbage"}')
assert_status "$HTTP" "400" "start bad memory rejected"
echo "   start validation chain ✓"

echo ""
echo "✅ 23_test_container_api: ALL PASS"
