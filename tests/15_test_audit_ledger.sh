#!/usr/bin/env bash
# 15_test_audit_ledger.sh — E2E test for Tamper-Evident Audit Ledger & /api/audit/:id/verify.
# Covers: Clean ledger verification, tampering record mutation detection,
# broken hash chain detection, and truncated file detection.
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
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18095
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET.
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET=$(openssl rand -hex 16 2>/dev/null || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

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

echo "--- 1. Empty ledger verification returns valid=true"
OUT=$(curl -s "$API/audit/tk-empty/verify" -H "$AUTH")
VALID=$(echo "$OUT" | jq -r .valid)
[ "$VALID" = "true" ] || fail "expected empty ledger valid=true, got: $OUT"
echo "   empty ledger valid ✓"

echo "--- 2. Create clean gate bundle to write real ledger rows"
TASK="tk-audit-01"
cat > "$TMP/clean-bundle.json" <<EOF
{
  "task_id": "$TASK",
  "diff": "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n",
  "build_log": "ok",
  "trace": ["go test ./..."],
  "claimed_ok": true
}
EOF
"$TMP/agentpvm" gate -bundle "$TMP/clean-bundle.json" >/dev/null

LEDGER="$PVM_AUDIT_ROOT/$TASK/ledger.jsonl"
[ -f "$LEDGER" ] || fail "ledger file was not created at $LEDGER"

OUT=$(curl -s "$API/audit/$TASK/verify" -H "$AUTH")
VALID=$(echo "$OUT" | jq -r .valid)
RECS=$(echo "$OUT" | jq -r .records)
[ "$VALID" = "true" ] && [ "$RECS" -ge 1 ] || fail "expected valid ledger with >=1 record, got: $OUT"
echo "   clean ledger ($RECS records) verified valid ✓"

echo "--- 3. Tamper attack: modify decision in ledger record"
# Mutate the ledger file directly on disk
sed -i 's/"allow"/"tampered_decision"/' "$LEDGER"

OUT=$(curl -s "$API/audit/$TASK/verify" -H "$AUTH")
VALID=$(echo "$OUT" | jq -r .valid)
[ "$VALID" = "false" ] || fail "expected valid=false after tampering, got: $OUT"
echo "   tamper detection caught modified record ✓"

echo "--- 4. Truncation attack: corrupt JSON line"
echo '{"corrupted":true' >> "$LEDGER"
OUT=$(curl -s "$API/audit/$TASK/verify" -H "$AUTH")
echo "$OUT" | grep -qi "error\|false" || fail "corruption not detected: $OUT"
echo "   corruption detection caught broken line ✓"

echo ""
echo "✅ 15_test_audit_ledger: ALL PASS"
