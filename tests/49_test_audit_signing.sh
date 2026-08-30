#!/usr/bin/env bash
# 49_test_audit_signing.sh — ed25519-signed ledger: signed appends verify,
# tampering breaks verification (signature or chain).
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
export PVM_AUDIT_SIGNING=1

PORT=18049
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

TASK="t-audit"
mkdir -p "$PVM_STATE_ROOT/$TASK"
cat > "$PVM_STATE_ROOT/$TASK/state.json" <<EOF
{"id":"$TASK","name":"$TASK","status":"running","pid":99999}
EOF

echo "--- 1. appends produce signed records"
curl -sf -X POST "$API/incidents/$TASK/report" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"severity":"low","kind":"test","detail":"x"}' >/dev/null || fail "report"
curl -sf -X POST "$API/gate/verify" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"task_id\":\"$TASK\",\"claimed_ok\":true}" >/dev/null || fail "gate"
LEDGER="$PVM_AUDIT_ROOT/$TASK/ledger.jsonl"
[ -f "$LEDGER" ] || fail "ledger must exist at $LEDGER"
jq -e 'select(.sig != null and .sig != "")' "$LEDGER" >/dev/null || fail "records must carry sig"
[ -f "$PVM_AUDIT_ROOT/key_ed25519" ] || fail "signing key must exist"
PERM=$(stat -c "%a" "$PVM_AUDIT_ROOT/key_ed25519")
[ "$PERM" = "600" ] || fail "key must be 0600, got $PERM"

echo "--- 2. Verify endpoint accepts the signed chain"
curl -sf -H "$AUTH" "$API/audit/$TASK/verify" | jq -e '.valid == true' >/dev/null || fail "verify must pass"

echo "--- 3. tampering breaks verification"
sed -i 's/"decision":"allow"/"decision":"deny"/' "$LEDGER" 2>/dev/null || true
# If the sed matched nothing (field layout), flip a param string instead.
if ! grep -q '"decision":"deny"' "$LEDGER"; then
    sed -i '0,/test/s//tampered/' "$LEDGER"
fi
V=$(curl -s -H "$AUTH" "$API/audit/$TASK/verify")
echo "$V" | jq -e '.valid == false' >/dev/null || fail "tampered ledger must fail verify: $V"

echo "✅ 49 audit signing suite passed"
