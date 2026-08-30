#!/usr/bin/env bash
# 39_test_approval_lifecycle.sh — approval tickets: create/edit/decide,
# persistence across restart, webhook notification.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
HOOK_PID=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; [ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18039
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

# Minimal webhook receiver: logs request lines to hooks.log.
HOOK_PORT=18040
cat > "$TMP/hook.py" <<'PYEOF'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        with open("hooks.log", "ab") as f:
            f.write(body + b"\n")
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 18040), H).serve_forever()
PYEOF
(cd "$TMP" && python3 hook.py &>"$TMP/hook.err" &)
HOOK_PID=$(pgrep -f "python3 hook.py" | head -1 || true)
# Webhook delivery is at-most-once (async goroutine, no retry): a POST
# against a not-yet-listening receiver is dropped for good. CI runners can
# take >1s to spawn python3, so wait for the socket before starting the
# API server that will fire the first "create" event.
for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$HOOK_PORT/" && break
    sleep 0.25
done
export PVM_APPROVAL_WEBHOOK_URL="http://127.0.0.1:$HOOK_PORT/"

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/approvals" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/approvals" >/dev/null || fail "server failed to start"

echo "--- 1. create ticket"
TID=$(curl -sf -X POST "$API/approvals" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"task_id":"t-ap","tool":"deploy","params":{"env":"prod"},"target":"payments","why":"release"}' | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || fail "ticket create"

echo "--- 2. duplicate pending ticket is 409"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/approvals" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"task_id":"t-ap","tool":"deploy","params":{"env":"prod"}}')
[ "$CODE" = "409" ] || fail "duplicate must 409, got $CODE"

echo "--- 3. edit pending ticket amends params"
EDITED=$(curl -sf -X POST "$API/approvals/$TID/edit" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"params":{"env":"staging"},"reason":"safer","by":"op"}')
echo "$EDITED" | jq -e '.params.env == "staging"' >/dev/null || fail "edit must amend params: $EDITED"
echo "$EDITED" | jq -e '.state == "pending"' >/dev/null || fail "edited ticket stays pending"

echo "--- 4. decide + immutability"
curl -sf -X POST "$API/approvals/$TID/decide" -H "$AUTH" -H "Content-Type: application/json" -d '{"approved":true,"by":"op"}' | jq -e '.state == "approved"' >/dev/null || fail "decide approve"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/approvals/$TID/edit" -H "$AUTH" -H "Content-Type: application/json" -d '{"params":{"x":1}}')
[ "$CODE" = "409" ] || fail "decided ticket must be immutable, got $CODE"

echo "--- 5. persistence: approved ticket survives restart"
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server2.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/approvals?all=1" >/dev/null 2>&1 && break
    sleep 0.25
done
# Pending list is empty; the durable store file exists with the ticket.
[ -f "$PVM_STATE_ROOT/approvals.json" ] || fail "approvals.json must persist"
jq -e --arg id "$TID" '.tickets[] | select(.id == $id and .state == "approved")' "$PVM_STATE_ROOT/approvals.json" >/dev/null || fail "approved ticket must be in the store"

echo "--- 6. webhook received create/decide events"
sleep 1
[ -f "$TMP/hooks.log" ] || fail "webhook receiver never called"
grep -q '"event":"create"' "$TMP/hooks.log" || fail "webhook create event missing"
grep -q '"event":"decide"' "$TMP/hooks.log" || fail "webhook decide event missing"

echo "✅ 39 approval suite passed"
