#!/usr/bin/env bash
# 11_test_template_api.sh — E2E test for Template Center REST API & Alias Resolution.
# Covers: POST/GET/DELETE /api/templates, PENDING/READY lifecycle, alias claims,
# alias conflict detection (409), dual resolution (ID vs Alias), and deletion.
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
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_TEMPLATE_ROOT"

PORT=18091
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

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

echo "--- 1. POST /api/templates creates template in PENDING status"
RESP=$(req POST /templates '{"image_ref":"alpine:3.19"}')
TID=$(echo "$RESP" | jq -r .template_id)
STATUS=$(echo "$RESP" | jq -r .status)
echo "$TID" | grep -qE '^tpl-[a-f0-9]{24}$' || fail "unexpected template_id format: $TID"
[ "$STATUS" = "PENDING" ] || fail "expected status PENDING, got: $STATUS"
echo "   created template: $TID (status: $STATUS) ✓"

echo "--- 2. POST /api/templates rejects missing image_ref (400)"
STATUS=$(req_status POST /templates '{}')
[ "$STATUS" = "400" ] || fail "expected 400 for empty image_ref, got $STATUS"
echo "   empty image_ref rejected 400 ✓"

echo "--- 3. Rejects setting alias on PENDING template (409)"
STATUS=$(req_status POST "/templates/$TID/alias" '{"alias":"my-alpine"}')
[ "$STATUS" = "409" ] || fail "expected 409 when aliasing non-READY template, got $STATUS"
echo "   aliasing PENDING template rejected 409 ✓"

echo "--- 4. GET /api/templates lists templates"
LIST=$(req GET /templates)
echo "$LIST" | jq -e "map(select(.template_id == \"$TID\")) | length == 1" >/dev/null || fail "template not in list: $LIST"
echo "   template listed ✓"

echo "--- 5. Transition template to READY on disk, then assign alias"
# Simulate image build completion by updating meta.json to READY
META_FILE="$PVM_TEMPLATE_ROOT/$TID/meta.json"
TMP_META=$(jq '.status = "READY"' "$META_FILE")
echo "$TMP_META" > "$META_FILE"

RESP=$(req POST "/templates/$TID/alias" '{"alias":"my-alpine"}')
ALIAS=$(echo "$RESP" | jq -r .alias)
[ "$ALIAS" = "my-alpine" ] || fail "expected alias my-alpine, got: $RESP"
echo "   alias assigned: $ALIAS ✓"

echo "--- 6. GET /api/templates/:alias resolves template via Alias"
BY_ALIAS=$(req GET "/templates/my-alpine")
[ "$(echo "$BY_ALIAS" | jq -r .template_id)" = "$TID" ] || fail "alias resolution mismatch: $BY_ALIAS"
echo "   alias resolved to template $TID ✓"

echo "--- 7. Alias conflict rejection (409)"
# Create a second template and mark READY
RESP2=$(req POST /templates '{"image_ref":"ubuntu:22.04"}')
TID2=$(echo "$RESP2" | jq -r .template_id)
echo "$(jq '.status = "READY"' "$PVM_TEMPLATE_ROOT/$TID2/meta.json")" > "$PVM_TEMPLATE_ROOT/$TID2/meta.json"

STATUS=$(req_status POST "/templates/$TID2/alias" '{"alias":"my-alpine"}')
[ "$STATUS" = "409" ] || fail "expected 409 for duplicate alias, got $STATUS"
echo "   duplicate alias rejected 409 ✓"

echo "--- 8. DELETE /api/templates/:id deletes template and unbinds alias"
STATUS=$(req_status DELETE "/templates/$TID")
[ "$STATUS" = "204" ] || fail "expected 204 for template delete, got $STATUS"
STATUS=$(req_status GET "/templates/$TID")
[ "$STATUS" = "404" ] || fail "expected 404 after ID delete, got $STATUS"
STATUS=$(req_status GET "/templates/my-alpine")
[ "$STATUS" = "404" ] || fail "expected 404 after alias unbind, got $STATUS"
echo "   template and alias cleanly deleted ✓"

echo ""
echo "✅ 11_test_template_api: ALL PASS"
