#!/usr/bin/env bash
# 57_test_spec_new_fields.sh — TaskSpec validation for the new control
# fields, through POST /api/tasks/load-spec (content mode).
# Covers: [[network.port_mappings]] range/protocol/duplicate checks,
# network.dataplane enum incl. "auto", volumes host_path charset rules,
# lifecycle.deep_pause accepted.
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

PORT=18057
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

# These suites lean on python3 (callback server / JSON escaping) like 34.
command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

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

loadspec() { # toml → "code body"
    local BODY CODE
    BODY=$(python3 -c 'import json,sys; print(json.dumps({"content": sys.stdin.read()}))' <<<"$1")
    CODE=$(curl -s -o "$TMP/out.json" -w "%{http_code}" -X POST "$API/tasks/load-spec" \
        -H "$AUTH" -H "Content-Type: application/json" -d "$BODY")
    echo "$CODE $(cat "$TMP/out.json")"
}

BASE='version=1
caller="alice"
[runtime]
name="spec-t"
cpu=100
memory="128M"
[workspace]
base_image="/tmp/x.img"
[network]
enabled=true
bridge="br0"
gateway_ip="10.0.0.1/24"
'

echo "--- 1. dataplane enum accepts bridge/tc/auto, rejects junk"
for dp in bridge tc auto; do
    read -r CODE BODY <<<"$(loadspec "${BASE}dataplane=\"$dp\"")"
    [ "$CODE" = "200" ] || fail "dataplane=$dp must validate, got $CODE: $BODY"
done
read -r CODE BODY <<<"$(loadspec "${BASE}dataplane=\"quantum\"")"
[ "$CODE" = "400" ] || fail "bogus dataplane must 400, got $CODE"
echo "$BODY" | jq -e '.error | contains("dataplane")' >/dev/null || fail "error must name dataplane: $BODY"

echo "--- 2. port_mappings: valid, range-checked, protocol-checked, duplicates rejected"
PM='[[network.port_mappings]]
host_port = 18080
guest_port = 80
protocol = "tcp"

[[network.port_mappings]]
host_port = 15353
guest_port = 53
protocol = "udp"
'
read -r CODE BODY <<<"$(loadspec "${BASE}${PM}")"
[ "$CODE" = "200" ] || fail "valid port mappings must validate, got $CODE: $BODY"

read -r CODE BODY <<<"$(loadspec "${BASE}[[network.port_mappings]]
host_port = 0
guest_port = 80
")"
[ "$CODE" = "400" ] || fail "host_port 0 must 400, got $CODE"
echo "$BODY" | jq -e '.error | contains("host_port")' >/dev/null || fail "error must name host_port: $BODY"

read -r CODE BODY <<<"$(loadspec "${BASE}[[network.port_mappings]]
host_port = 8080
guest_port = 80
protocol = \"sctp\"
")"
[ "$CODE" = "400" ] || fail "sctp must 400, got $CODE"

read -r CODE BODY <<<"$(loadspec "${BASE}${PM}[[network.port_mappings]]
host_port = 18080
guest_port = 8081
")"
[ "$CODE" = "400" ] || fail "duplicate host port must 400, got $CODE"
echo "$BODY" | jq -e '.error | contains("duplicates")' >/dev/null || fail "error must say duplicates: $BODY"

echo "--- 3. volumes host_path: absolute + kernel-arg charset"
read -r CODE BODY <<<"$(loadspec "${BASE}[[volumes]]
name = \"v1\"
path = \"/workspace\"
driver = \"builtin\"
host_path = \"/srv/shared/data\"
")"
[ "$CODE" = "200" ] || fail "absolute host_path must validate, got $CODE: $BODY"

read -r CODE BODY <<<"$(loadspec "${BASE}[[volumes]]
name = \"v2\"
path = \"/workspace\"
host_path = \"relative/path\"
")"
[ "$CODE" = "400" ] || fail "relative host_path must 400, got $CODE"
echo "$BODY" | jq -e '.error | contains("absolute")' >/dev/null || fail "error must say absolute: $BODY"

read -r CODE BODY <<<"$(loadspec "${BASE}[[volumes]]
name = \"v3\"
path = \"/workspace\"
host_path = \"/has:colon\"
")"
[ "$CODE" = "400" ] || fail "colon in host_path must 400 (kernel arg charset), got $CODE"

echo "--- 4. lifecycle.deep_pause accepted"
read -r CODE BODY <<<"$(loadspec "${BASE}[lifecycle]
idle_timeout = \"10m\"
deep_pause = true
")"
[ "$CODE" = "200" ] || fail "deep_pause must validate, got $CODE: $BODY"

echo "✅ 57_test_spec_new_fields.sh passed"
