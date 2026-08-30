#!/usr/bin/env bash
# 40_test_incident_api.sh — incident report API: validation, classification
# actions, listing.
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

PORT=18041
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

echo "--- 1. invalid severity rejected"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/incidents/t-1/report" -H "$AUTH" -H "Content-Type: application/json" -d '{"severity":"mega"}')
[ "$CODE" = "400" ] || fail "bad severity must 400, got $CODE"

echo "--- 2. severity -> action classification"
for pair in "low:block" "medium:pause" "high:quarantine" "critical:terminate"; do
    SEV="${pair%%:*}"; WANT="${pair##*:}"
    ACT=$(curl -sf -X POST "$API/incidents/t-1/report" -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"severity\":\"$SEV\",\"kind\":\"test\",\"detail\":\"x\"}" | jq -r .action)
    [ "$ACT" = "$WANT" ] || fail "$SEV must map to $WANT, got $ACT"
done

echo "--- 3. list contains the reports"
LIST=$(curl -sf -H "$AUTH" "$API/incidents")
echo "$LIST" | jq -e 'length >= 4' >/dev/null || fail "incident list too short: $LIST"
echo "$LIST" | jq -e 'any(.signal == "test")' >/dev/null || fail "list must carry the signal"

echo "✅ 40 incident suite passed"
