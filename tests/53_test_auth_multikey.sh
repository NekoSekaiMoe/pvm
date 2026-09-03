#!/usr/bin/env bash
# 53_test_auth_multikey.sh — multi-key authentication + auth-callback
# delegation (fail-closed semantics).
# Covers: named keys via PVM_API_KEYS (operator/tenant attribution lives in
# the server), X-API-KEY header parity, PVM_API_KEYS_FILE with comments,
# callback 200-allow / 403-deny, unreachable callback → 500 (fail CLOSED),
# metrics endpoint accepts local keys but never delegates.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
CB=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; [ -n "$CB" ] && kill "$CB" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18053
API="http://127.0.0.1:$PORT/api"
export API_SECRET="master-secret"
export PVM_API_KEYS="k-alice:alice:tenant-a, k-bob:bob"

fail() { echo "❌ $1"; exit 1; }

# These suites lean on python3 (callback server / JSON escaping) like 34.
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

start_server() {
    "$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
    SRV=$!
    for _ in $(seq 1 40); do
        curl -sf -H "Authorization: Bearer $API_SECRET" "$API/containers" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    fail "server failed to start: $(cat "$TMP/server.log")"
}

echo "--- 1. named keys authenticate"
start_server
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer k-alice" "$API/containers")
[ "$CODE" = "200" ] || fail "named key k-alice must 200, got $CODE"

echo "--- 2. X-API-KEY header parity"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-KEY: k-bob" "$API/containers")
[ "$CODE" = "200" ] || fail "X-API-KEY named key must 200, got $CODE"

echo "--- 3. unknown key without callback → 401"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer nope" "$API/containers")
[ "$CODE" = "401" ] || fail "unknown key must 401, got $CODE"

echo "--- 4. /metrics accepts local keys"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer k-bob" "http://127.0.0.1:$PORT/metrics")
[ "$CODE" = "200" ] || fail "metrics with local key must 200, got $CODE"
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""

echo "--- 5. PVM_API_KEYS_FILE with comments"
cat > "$TMP/keys" <<'EOF'
# operators
k-carol:carol

k-dave
EOF
unset PVM_API_KEYS
export PVM_API_KEYS_FILE="$TMP/keys"
start_server
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer k-carol" "$API/containers")
[ "$CODE" = "200" ] || fail "file key k-carol must 200, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer k-dave" "$API/containers")
[ "$CODE" = "200" ] || fail "file key k-dave (operator defaults to key) must 200, got $CODE"
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""

echo "--- 6. auth callback delegation"
CBPORT=18099
python3 - "$CBPORT" > "$TMP/callback.log" 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        ok = b'"key":"cb-good"' in body
        self.send_response(200 if ok else 403)
        self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
CB=$!
for _ in $(seq 1 20); do
    python3 -c "import socket; socket.create_connection(('127.0.0.1', $CBPORT), 1)" 2>/dev/null && break
    sleep 0.25
done
export PVM_AUTH_CALLBACK_URL="http://127.0.0.1:$CBPORT/auth"
start_server
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer cb-good" "$API/containers")
[ "$CODE" = "200" ] || fail "callback-approved key must 200, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer cb-bad" "$API/containers")
[ "$CODE" = "401" ] || fail "callback-denied key must 401, got $CODE"

echo "--- 7. metrics never delegates (unknown key → 401 even with callback)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer cb-good" "http://127.0.0.1:$PORT/metrics")
[ "$CODE" = "401" ] || fail "metrics must not consult the callback, got $CODE"

echo "--- 8. unreachable callback fails CLOSED (500)"
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""
kill "$CB" 2>/dev/null || true; wait "$CB" 2>/dev/null || true; CB=""
# Keep the URL pointing at the now-dead port.
start_server
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer any-key" "$API/containers")
[ "$CODE" = "500" ] || fail "broken callback must fail closed as 500, got $CODE"

echo "✅ 53_test_auth_multikey.sh passed"
