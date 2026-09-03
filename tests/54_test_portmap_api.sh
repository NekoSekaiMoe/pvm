#!/usr/bin/env bash
# 54_test_portmap_api.sh — inbound host-port mapping REST surface.
# Covers: GET empty list, validation errors (ports/protocol/guest ip),
# unknown task 404, tc-mode task 409 with the typed reason, DELETE
# nonexistent 404. Rule EXECUTION needs root+iptables and is exercised by
# the root-only suites; the registry round-trip is unit-tested in Go.
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

PORT=18054
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
    curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 || fail "server failed to start: $(cat "$TMP/server.log")"

# Fixture tasks: one bridge-mode with a guest IP, one tc-mode.
mkdir -p "$PVM_STATE_ROOT/pm-bridge" "$PVM_STATE_ROOT/pm-tc"
cat > "$PVM_STATE_ROOT/pm-bridge/state.json" <<'EOF'
{"id":"pm-bridge","name":"pm-bridge","status":"running","metadata":{"dataplane":"bridge","guest_ip":"10.0.0.100","tap":"tapX"}}
EOF
cat > "$PVM_STATE_ROOT/pm-tc/state.json" <<'EOF'
{"id":"pm-tc","name":"pm-tc","status":"running","metadata":{"dataplane":"tc","guest_ip":"169.254.68.6","tap":"tapY"}}
EOF

echo "--- 1. GET portmaps is an empty list"
OUT=$(curl -sf -H "$AUTH" "$API/network/portmaps")
[ "$(echo "$OUT" | jq 'length')" = "0" ] || fail "expected empty list, got $OUT"

echo "--- 2. unknown task → 404"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"ghost","host_port":8080,"guest_port":80}')
[ "$CODE" = "404" ] || fail "unknown task must 404, got $CODE"

echo "--- 3. tc-mode task → 409 with the typed reason"
BODY=$(curl -s -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-tc","host_port":8080,"guest_port":80}')
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-tc","host_port":8081,"guest_port":80}')
[ "$CODE" = "409" ] || fail "tc task must 409, got $CODE"
echo "$BODY" | jq -e '.error | contains("bridge dataplane")' >/dev/null || fail "409 body must name the bridge requirement: $BODY"

echo "--- 4. validation: bad ports / protocol"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-bridge","host_port":0,"guest_port":80}')
[ "$CODE" = "400" ] || fail "host_port 0 must 400, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-bridge","host_port":8080,"guest_port":70000}')
[ "$CODE" = "400" ] || fail "guest_port 70000 must 400, got $CODE"
BODY=$(curl -s -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-bridge","host_port":8080,"guest_port":80,"protocol":"sctp"}')
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-bridge","host_port":8080,"guest_port":80,"protocol":"sctp"}')
[ "$CODE" = "400" ] || fail "sctp must 400, got $CODE"
echo "$BODY" | jq -e '.error | contains("tcp or udp")' >/dev/null || fail "protocol error must be specific: $BODY"

echo "--- 5. bridge task without recorded guest_ip → 400"
mkdir -p "$PVM_STATE_ROOT/pm-noip"
cat > "$PVM_STATE_ROOT/pm-noip/state.json" <<'EOF'
{"id":"pm-noip","name":"pm-noip","status":"running","metadata":{"dataplane":"bridge"}}
EOF
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-noip","host_port":8080,"guest_port":80}')
[ "$CODE" = "400" ] || fail "missing guest_ip must 400, got $CODE"

echo "--- 6. DELETE nonexistent → 404"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API/network/portmaps/pm-bridge/9999" -H "$AUTH")
[ "$CODE" = "404" ] || fail "delete nonexistent must 404, got $CODE"

echo "--- 7. bridge task + iptables unavailable → 400 (fail closed, no phantom mapping)"
# In CI (non-root) AddPortMapping cannot apply rules; the API must refuse
# instead of recording a mapping that does not exist in the kernel. On a
# root-capable host this same call SUCCEEDS — then assert the happy path.
# ONE request captures body and code: a second identical POST would hit
# the duplicate-mapping refusal (400 "already mapped") and desync the
# BODY/CODE pair on exactly the root hosts that take the 201 branch.
RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/network/portmaps" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"pm-bridge","host_port":18080,"guest_port":80}')
CODE=$(printf '%s\n' "$RESP" | tail -n 1)
BODY=$(printf '%s\n' "$RESP" | sed '$d')
if [ "$CODE" = "201" ]; then
    echo "    (root host: mapping applied)"
    echo "$BODY" | jq -e '.guest_ip == "10.0.0.100" and .host_port == 18080' >/dev/null || fail "201 body wrong: $BODY"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API/network/portmaps/pm-bridge/18080" -H "$AUTH")
    [ "$CODE" = "204" ] || fail "delete applied mapping must 204, got $CODE"
else
    [ "$CODE" = "400" ] || fail "non-root add must 400, got $CODE"
    echo "$BODY" | jq -e '.error | length > 0' >/dev/null || fail "400 must carry an error: $BODY"
    # And nothing was recorded.
    OUT=$(curl -sf -H "$AUTH" "$API/network/portmaps")
    [ "$(echo "$OUT" | jq 'length')" = "0" ] || fail "failed add must not record a mapping: $OUT"
fi

echo "✅ 54_test_portmap_api.sh passed"
