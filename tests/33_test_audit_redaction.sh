#!/usr/bin/env bash
# 33_test_audit_redaction.sh — E2E test for audit ledger secret redaction (脱敏).
# Covers: (a) planted secrets never land in the on-disk ledger bytes,
# (b) GET /api/audit/:id redacted markers, (c) hash-chain verify still passes,
# (d) GET+PUT /api/audit/redaction-policy round trip, (e) disabled redaction
# stores unredacted (documented escape hatch) + read-side defense on re-enable.
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

PORT=18096
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

req() { # method path [json-body]
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}

# Planted secrets: shapes the redactor must catch (GitHub token pattern).
GHP_A="ghp_$(printf 'A%.0s' $(seq 1 40))"
GHP_B="ghp_$(printf 'B%.0s' $(seq 1 40))"

gate_verify() { # task secret-filename
    req POST "/gate/verify" "{
      \"task_id\": \"$1\",
      \"diff\": \"--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n\",
      \"build_log\": \"ok\",
      \"trace\": [\"go test ./...\"],
      \"claimed_ok\": true,
      \"files\": {\"leak_$2.txt\": \"b2s=\"}
    }" >/dev/null
}

echo "--- 1. Planted secret via gate flow never lands in ledger bytes"
gate_verify "tk-redact-a" "$GHP_A"
LEDGER_A="$PVM_AUDIT_ROOT/tk-redact-a/ledger.jsonl"
[ -f "$LEDGER_A" ] || fail "ledger file was not created at $LEDGER_A"
if grep -qF "$GHP_A" "$LEDGER_A"; then
    fail "plaintext secret found in ledger bytes: $(cat "$LEDGER_A")"
fi
grep -qF "[REDACTED]" "$LEDGER_A" || fail "expected [REDACTED] marker in ledger: $(cat "$LEDGER_A")"
echo "   plaintext absent, [REDACTED] marker present ✓"

echo "--- 2. GET /api/audit/:id marks redacted rows"
OUT=$(req GET "/audit/tk-redact-a")
echo "$OUT" | grep -qF "[REDACTED]" || fail "read view missing [REDACTED]: $OUT"
REDACTED_ROWS=$(echo "$OUT" | jq '[.[] | select(.redacted == true)] | length')
[ "$REDACTED_ROWS" -ge 1 ] || fail "expected >=1 row flagged redacted:true, got: $OUT"
echo "   $REDACTED_ROWS row(s) flagged redacted ✓"

echo "--- 3. Hash-chain verify still passes on redacted ledger"
OUT=$(req GET "/audit/tk-redact-a/verify")
VALID=$(echo "$OUT" | jq -r .valid)
RECS=$(echo "$OUT" | jq -r .records)
[ "$VALID" = "true" ] && [ "$RECS" -ge 1 ] || fail "expected valid redacted ledger, got: $OUT"
echo "   redacted ledger ($RECS records) verified valid ✓"

echo "--- 4. GET /api/audit/redaction-policy reports posture"
OUT=$(req GET "/audit/redaction-policy")
[ "$(echo "$OUT" | jq -r .enabled)" = "true" ] || fail "expected enabled=true, got: $OUT"
[ "$(echo "$OUT" | jq -r .patterns_count)" -ge 6 ] || fail "expected >=6 patterns, got: $OUT"
echo "$OUT" | jq -e '.key_denylist | index("token")' >/dev/null || fail "key_denylist missing 'token': $OUT"
echo "   policy: enabled, $(echo "$OUT" | jq -r .patterns_count) patterns, denylist present ✓"

echo "--- 5. PUT redaction-policy disable -> new records stored UNREDACTED (escape hatch)"
OUT=$(req PUT "/audit/redaction-policy" '{"enabled": false}')
[ "$(echo "$OUT" | jq -r .enabled)" = "false" ] || fail "PUT did not disable redaction: $OUT"
gate_verify "tk-redact-b" "$GHP_B"
LEDGER_B="$PVM_AUDIT_ROOT/tk-redact-b/ledger.jsonl"
[ -f "$LEDGER_B" ] || fail "ledger file was not created at $LEDGER_B"
grep -qF "$GHP_B" "$LEDGER_B" || fail "disabled redaction should store plaintext (escape hatch), got: $(cat "$LEDGER_B")"
echo "   disabled redactor stored plaintext as documented ✓"

echo "--- 6. Re-enable; read-side defense redacts the legacy unredacted row"
OUT=$(req PUT "/audit/redaction-policy" '{"enabled": true}')
[ "$(echo "$OUT" | jq -r .enabled)" = "true" ] || fail "PUT did not re-enable redaction: $OUT"
OUT=$(req GET "/audit/tk-redact-b")
echo "$OUT" | grep -qF "$GHP_B" && fail "read view leaked the legacy plaintext secret: $OUT"
echo "$OUT" | grep -qF "[REDACTED]" || fail "read view missing [REDACTED] for legacy row: $OUT"
[ "$(echo "$OUT" | jq '[.[] | select(.redacted == true)] | length')" -ge 1 ] || fail "legacy row not flagged redacted:true: $OUT"
echo "   legacy plaintext masked on read with redacted marker ✓"

echo "--- 7. Verify endpoint stays byte-accurate for the unredacted-on-disk ledger"
OUT=$(req GET "/audit/tk-redact-b/verify")
[ "$(echo "$OUT" | jq -r .valid)" = "true" ] || fail "expected valid ledger for tk-redact-b, got: $OUT"
echo "   unredacted-on-disk ledger still verifies ✓"

echo ""
echo "✅ 33_test_audit_redaction: ALL PASS"
