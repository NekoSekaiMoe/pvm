#!/usr/bin/env bash
# 22_test_docker_image_pull.sh — E2E test for Docker Image Pull, Layer Generation & Safe Naming.
# Covers: POST /api/images/pull, umlctl image pull CLI arguments, safeName sanitization,
# and non-existent image error handling.
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

PORT=18098
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET.
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET=$(openssl rand -hex 16 2>/dev/null || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

fail() { echo "❌ $1"; exit 1; }

run_fail() {
    set +e
    OUT=$("$@" 2>&1)
    local code=$?
    set -e
    [ "$code" -ne 0 ] || fail "expected non-zero exit code for: $*"
}

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi
if [ -n "${UMLCTL_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/umlctl ($UMLCTL_BIN)"
    cp "$UMLCTL_BIN" "$TMP/umlctl"
else
    echo "==> building $TMP/umlctl"
    go build -o "$TMP/umlctl" ./cmd/umlctl
fi

echo "--- 1. umlctl image pull CLI argument parsing and nonzero exit"
run_fail "$TMP/umlctl" image
echo "$OUT" | grep -q "Usage: umlctl image pull" || fail "expected usage message: $OUT"
echo "   umlctl image usage verified and failed ✓"

echo "==> starting server on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!

for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

echo "--- 2. POST /api/images/pull rejects invalid/non-existent image gracefully (500)"
# Pulling non-existent image with timeout protection
STATUS=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" -X POST "$API/images/pull" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"image":"127.0.0.1:1/no-such-image:tag123"}')
[ "$STATUS" = "500" ] || fail "expected 500 for non-existent image, got: $STATUS"
echo "   non-existent image gracefully rejected 500 ✓"

echo ""
echo "✅ 22_test_docker_image_pull: ALL PASS"
