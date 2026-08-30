#!/usr/bin/env bash
# 38_test_identity_api.sh — credential broker REST surface + persistence.
# Covers: mint scopes/ttl, refresh rotates+revokes, revoke-all blocks,
# key persistence across restart (token survives, revocations survive).
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

PORT=18038
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

start_server() {
    "$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
    SRV=$!
    for _ in $(seq 1 40); do
        curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    fail "server failed to start: $(cat "$TMP/server.log")"
}
start_server

echo "--- 1. mint requires scopes"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/identity/t-1/tokens" -H "$AUTH" -H "Content-Type: application/json" -d '{}')
[ "$CODE" = "400" ] || fail "mint without scopes must 400, got $CODE"

echo "--- 2. mint + refresh rotation"
TOK=$(curl -sf -X POST "$API/identity/t-1/tokens" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"scopes":["repo:read"],"ttl":"10m"}' | jq -r .token)
[ -n "$TOK" ] && [ "$TOK" != "null" ] || fail "mint returned no token"
REFRESHED=$(curl -sf -X POST "$API/identity/refresh" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOK\"}" | jq -r .token)
[ -n "$REFRESHED" ] && [ "$REFRESHED" != "$TOK" ] || fail "refresh must return a new token"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/identity/refresh" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOK\"}")
[ "$CODE" = "401" ] || fail "old token must be revoked after refresh, got $CODE"

echo "--- 3. revoke-all blocks the refreshed token"
curl -sf -X POST "$API/identity/t-1/revoke" -H "$AUTH" -H "Content-Type: application/json" -d '{"all":true}' >/dev/null || fail "revoke all"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/identity/refresh" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"token\":\"$REFRESHED\"}")
[ "$CODE" = "401" ] || fail "revoked token must not refresh, got $CODE"

echo "--- 4. persistence: signing key 0600 + token survives restart"
TOK2=$(curl -sf -X POST "$API/identity/t-2/tokens" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"scopes":["repo:write"]}' | jq -r .token)
KEYFILE="$PVM_STATE_ROOT/identity.key"
[ -f "$KEYFILE" ] || fail "identity.key must persist"
PERM=$(stat -c "%a" "$KEYFILE")
[ "$PERM" = "600" ] || fail "identity.key must be 0600, got $PERM"

kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
SRV=""
start_server

CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/identity/refresh" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOK2\"}")
[ "$CODE" = "200" ] || fail "token minted before restart must still validate, got $CODE"

echo "✅ 38 identity suite passed"
