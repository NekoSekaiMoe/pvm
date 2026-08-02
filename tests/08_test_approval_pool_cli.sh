#!/usr/bin/env bash
# 08_test_approval_pool_cli.sh — exercise the `agentpvm approval` and
# `agentpvm pool` subcommands against a live API server. The subcommands are
# thin HTTP clients ($PVM_API + $API_SECRET), so this suite starts the real
# webui binary and drives the full CLI -> HTTP -> control-plane path.
# No UML kernel required; CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18082
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"

fail() { echo "❌ $1"; exit 1; }

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server did not come up: $(cat "$TMP/server.log")"

req() { # method path [json-body]
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}

# =========================================================================
# approval CLI
# =========================================================================

# --- 1. API_SECRET is mandatory (no silent default auth) ---
echo "--- approval list: missing API_SECRET is a hard error"
OUT=$(env -u API_SECRET "$TMP/agentpvm" approval list 2>&1) && fail "approval list without API_SECRET should exit 1"
echo "$OUT" | grep -q "API_SECRET environment variable is required" || fail "unexpected error: $OUT"
echo "   secret required ✓"

export API_SECRET="secret"

# --- 2. empty ticket list ---
echo "--- approval list: no pending tickets"
OUT=$("$TMP/agentpvm" approval list)
[ "$OUT" = "(no pending tickets)" ] || fail "expected empty marker, got: $OUT"
echo "   empty marker ✓"

# --- 3. ticket created via REST shows up in the CLI listing ---
echo "--- approval list: shows tickets created via REST"
TID=$(req POST /approvals '{"task_id":"cli-tk","tool":"send_email","target":"prod","params":{"to":"a@b.c"},"why":"cli-test"}' | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || fail "ticket creation failed"
OUT=$("$TMP/agentpvm" approval list)
echo "$OUT" | grep -q "send_email" || fail "tool missing from CLI listing: $OUT"
echo "$OUT" | grep -q "prod"       || fail "target missing from CLI listing: $OUT"
echo "$OUT" | grep -q "cli-test"   || fail "why missing from CLI listing: $OUT"
echo "   ticket visible ✓"

# --- 4. after the ticket is decided, the pending list drains ---
echo "--- approval list: decided tickets disappear"
STATE=$(req POST "/approvals/$TID/decide" '{"approved":true,"by":"cli"}' | jq -r .state)
[ "$STATE" = "approved" ] || fail "decide failed"
OUT=$("$TMP/agentpvm" approval list)
[ "$OUT" = "(no pending tickets)" ] || fail "decided ticket still listed: $OUT"
echo "   pending list drained ✓"

# --- 5. usage line with no args ---
echo "--- approval: usage"
OUT=$("$TMP/agentpvm" approval 2>&1)
echo "$OUT" | grep -q "Usage: agentpvm approval" || fail "expected usage line: $OUT"
echo "   usage ✓"

# =========================================================================
# pool CLI
# =========================================================================

# --- 6. API_SECRET is mandatory for pool too ---
echo "--- pool stats: missing API_SECRET is a hard error"
OUT=$(env -u API_SECRET "$TMP/agentpvm" pool stats 2>&1) && fail "pool stats without API_SECRET should exit 1"
echo "$OUT" | grep -q "API_SECRET environment variable is required" || fail "unexpected error: $OUT"
echo "   secret required ✓"

# --- 7. stats against an empty pool ---
echo "--- pool stats: empty pool"
OUT=$("$TMP/agentpvm" pool stats)
[ "$OUT" = "ready=0 claimed=0 total=0" ] || fail "unexpected empty stats: $OUT"
echo "   empty stats ✓"

# --- 8. warm via REST, observe via CLI ---
echo "--- pool stats: reflects warm pool"
CREATED=$(req POST /pool/warm '{"template":{"name":"alpine","memory":"256M","cpu":1},"n":2}' | jq -r .created)
[ "$CREATED" = "2" ] || fail "warm failed"
OUT=$("$TMP/agentpvm" pool stats)
[ "$OUT" = "ready=2 claimed=0 total=2" ] || fail "unexpected stats after warm: $OUT"
echo "   ready=2 claimed=0 total=2 ✓"

# --- 9. `pool warm` over HTTP is explicitly not implemented yet ---
echo "--- pool warm: documents the CLI gap"
OUT=$("$TMP/agentpvm" pool warm alpine 2 2>&1)
echo "$OUT" | grep -q "unknown subcommand: warm" || fail "unexpected output: $OUT"
echo "   warm gap documented ✓"

# --- 10. usage line with no args ---
echo "--- pool: usage"
OUT=$("$TMP/agentpvm" pool 2>&1)
echo "$OUT" | grep -q "Usage: agentpvm pool" || fail "expected usage line: $OUT"
echo "   usage ✓"

echo ""
echo "✅ 08_test_approval_pool_cli: ALL PASS"
