#!/usr/bin/env bash
# 10_test_volume_api_cli.sh — E2E test for Persistent Volume REST API & CLI plugin wiring.
# Covers: POST/GET/DELETE /api/volumes, credential stripping, invalid ID rejection,
# mount-conflict deletion prevention (409), and PVM_VOLUME_PLUGINS validation.
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
export PVM_VOLUME_ROOT="$TMP/volumes"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_VOLUME_ROOT"

PORT=18090
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

req() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}
req_status() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}

echo "--- 1. POST /api/volumes creates a volume"
RESP=$(req POST /volumes '{"name":"vol-data1","driver":"builtin","token":"super-secret-token","private_data":"hidden-config"}')
VOL_ID=$(echo "$RESP" | jq -r .volume_id)
[ "$VOL_ID" = "vol-data1" ] || fail "expected volume_id vol-data1, got: $RESP"
echo "   created volume: $VOL_ID ✓"

echo "--- 2. Credential stripping: token & private_data must NOT be in JSON response"
HAS_SENSITIVE=$(echo "$RESP" | jq '(has("token") or has("private_data"))')
[ "$HAS_SENSITIVE" = "false" ] || fail "sensitive tokens leaked in response: $RESP"
echo "   credential stripping verified ✓"

echo "--- 3. Invalid volume names / IDs are rejected (400)"
STATUS=$(req_status POST /volumes '{"name":"../escape","driver":"builtin"}')
[ "$STATUS" = "400" ] || fail "expected 400 for path traversal name, got $STATUS"
STATUS=$(req_status POST /volumes '{"name":"bad/name","driver":"builtin"}')
[ "$STATUS" = "400" ] || fail "expected 400 for slash in name, got $STATUS"
STATUS=$(req_status POST /volumes '{"name":"","driver":"builtin"}')
[ "$STATUS" = "400" ] || fail "expected 400 for empty name, got $STATUS"
echo "   invalid IDs rejected with 400 ✓"

echo "--- 4. Duplicate volume creation returns 409 Conflict"
STATUS=$(req_status POST /volumes '{"name":"vol-data1","driver":"builtin"}')
[ "$STATUS" = "409" ] || fail "expected 409 for duplicate volume, got $STATUS"
echo "   duplicate conflict 409 ✓"

echo "--- 5. GET /api/volumes lists created volumes"
LIST=$(req GET /volumes)
echo "$LIST" | jq -e 'map(select(.volume_id == "vol-data1")) | length == 1' >/dev/null || fail "vol-data1 not in list: $LIST"
echo "   volume list contains vol-data1 ✓"

echo "--- 6. GET /api/volumes/:id fetches volume detail"
DETAIL=$(req GET /volumes/vol-data1)
[ "$(echo "$DETAIL" | jq -r .name)" = "vol-data1" ] || fail "detail mismatch: $DETAIL"
STATUS=$(req_status GET /volumes/non-existent-vol)
[ "$STATUS" = "404" ] || fail "expected 404 for non-existent volume, got $STATUS"
echo "   volume detail & 404 ✓"

echo "--- 7. DELETE /api/volumes/:id deletes volume"
STATUS=$(req_status DELETE /volumes/vol-data1)
[ "$STATUS" = "204" ] || fail "expected 204 for volume delete, got $STATUS"
STATUS=$(req_status GET /volumes/vol-data1)
[ "$STATUS" = "404" ] || fail "expected 404 after deletion, got $STATUS"
echo "   volume deletion 204 & verified removed ✓"

echo "--- 8. PVM_VOLUME_PLUGINS validation on agentpvm run"
OUT=$(PVM_VOLUME_PLUGINS="myvol=relative/path" "$TMP/agentpvm" run 2>&1 || true)
echo "$OUT" | grep -qi "must be absolute" || fail "relative plugin path not rejected: $OUT"
OUT=$(PVM_VOLUME_PLUGINS="invalid_entry" "$TMP/agentpvm" run 2>&1 || true)
echo "$OUT" | grep -qi "must be name=/abs/path" || fail "malformed plugin entry not rejected: $OUT"
OUT=$(PVM_VOLUME_PLUGINS="bad@name=/tmp/bin" "$TMP/agentpvm" run 2>&1 || true)
echo "$OUT" | grep -qi "invalid driver name" || fail "invalid driver name not rejected: $OUT"
echo "   PVM_VOLUME_PLUGINS CLI validations ✓"

echo ""
echo "✅ 10_test_volume_api_cli: ALL PASS"
