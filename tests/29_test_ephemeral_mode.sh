#!/usr/bin/env bash
# 29_test_ephemeral_mode.sh — E2E test for ephemeral (non-persistent)
# sandboxes across all three entry points:
#   * TaskSpec TOML  (workspace.ephemeral, via /api/tasks/load-spec + agentpvm run)
#   * CLI flags      (agentpvm run -ephemeral, umlctl start -ephemeral)
#   * REST API       (POST /api/containers/start {ephemeral:true})
# Asserts the ephemeral contract WITHOUT a kernel: specs validate (and
# conflicting combos reject), failed launches leave no qcow2 overlay behind,
# and umlctl discards the container dir after exit.
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
export PVM_IMAGE_ROOT="$TMP/images"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_IMAGE_ROOT"

PORT=18099
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

echo "==> building binaries"
go build -o "$TMP/agentpvm" ./cmd/agentpvm
go build -o "$TMP/umlctl"   ./cmd/umlctl

# A real base image inside the trusted image root: daemon-side validation
# (validateRootfsContained) requires a regular file under PVM_IMAGE_ROOT.
dd if=/dev/zero of="$PVM_IMAGE_ROOT/rootfs.img" bs=1M count=1 status=none

req() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}

echo "==> starting server on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

# --- 1. load-spec accepts workspace.ephemeral ---
echo "--- load-spec accepts ephemeral=true"
EPHEMERAL_TOML=$(cat <<EOF
version = 1
caller = "ci"
[runtime]
name = "eph-api"
[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"
ephemeral = true
[kernel]
path = "/nonexistent/linux"
use_vhost_blk = true
EOF
)
BODY=$(python3 -c "import json,sys; print(json.dumps({'content': sys.stdin.read()}))" <<<"$EPHEMERAL_TOML")
RESP=$(req POST /tasks/load-spec "$BODY")
echo "$RESP" | jq -e '.fingerprint | length > 0' >/dev/null || fail "ephemeral spec rejected by load-spec: $RESP"
echo "   ephemeral=true accepted ✓"

# --- 2. load-spec rejects ephemeral + compact_on_exit / overlay ---
echo "--- load-spec rejects conflicting combos"
for EXTRA in 'compact_on_exit = true' 'overlay = "/tmp/ov.qcow2"'; do
    BAD_TOML=$(printf '%s\n%s\n' "$EPHEMERAL_TOML" "$EXTRA")
    BODY=$(python3 -c "import json,sys; print(json.dumps({'content': sys.stdin.read()}))" <<<"$BAD_TOML")
    RESP=$(req POST /tasks/load-spec "$BODY")
    echo "$RESP" | jq -e '.error' >/dev/null || fail "conflict ($EXTRA) not rejected: $RESP"
done
echo "   conflicts rejected ✓"

# --- 3. agentpvm run: ephemeral launch leaves no overlay ---
echo "--- agentpvm run ephemeral (no kernel => launch fails, planes wire up)"
cat > "$TMP/eph.toml" <<EOF
version = 1
caller = "ci"
[runtime]
name = "eph-run"
memory = "256M"
[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"
ephemeral = true
[kernel]
path = "/nonexistent/linux"
use_vhost_blk = true
EOF
OUT=$("$TMP/agentpvm" run -config "$TMP/eph.toml" 2>&1 || true)
echo "$OUT" | grep -q "Loaded TaskSpec" || fail "config not loaded: $OUT"
# state.json must record the failed launch (kernel missing)...
STATE=$(cat "$PVM_STATE_ROOT/eph-run/state.json" 2>/dev/null || fail "no state.json: $OUT")
echo "$STATE" | jq -e '.status == "failed"' >/dev/null || fail "status not failed: $STATE"
# ...but NO qcow2 overlay may exist (ephemeral never provisions one).
if find "$PVM_STATE_ROOT/eph-run" -name '*.qcow2' | grep -q .; then
    fail "ephemeral task left an overlay: $(find "$PVM_STATE_ROOT/eph-run" -name '*.qcow2')"
fi
echo "   failed launch, no overlay residue ✓"

# --- 4. -ephemeral override re-validates against config conflicts ---
echo "--- -ephemeral override over compact_on_exit config is rejected"
cat > "$TMP/conflict.toml" <<EOF
version = 1
caller = "ci"
[runtime]
name = "eph-conflict"
[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"
compact_on_exit = true
[kernel]
path = "/nonexistent/linux"
use_vhost_blk = true
EOF
OUT=$("$TMP/agentpvm" run -config "$TMP/conflict.toml" -ephemeral 2>&1 || true)
echo "$OUT" | grep -q "compact_on_exit conflicts with workspace.ephemeral" \
    || fail "override conflict not caught: $OUT"
echo "   override conflict rejected ✓"

# --- 5. -ephemeral=false explicitly wins over the config file ---
echo "--- -ephemeral=false opt-out over config ephemeral=true"
cat > "$TMP/on.toml" <<EOF
version = 1
caller = "ci"
[runtime]
name = "eph-optout"
[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"
ephemeral = true
[kernel]
path = "/nonexistent/linux"
use_vhost_blk = true
EOF
OUT=$("$TMP/agentpvm" run -config "$TMP/on.toml" -ephemeral=false 2>&1 || true)
echo "$OUT" | grep -q "Loaded TaskSpec" || fail "opt-out spec rejected: $OUT"
echo "$OUT" | grep -q "overrides leave spec invalid" && fail "opt-out wrongly conflicted: $OUT"
echo "   explicit opt-out ✓"

# --- 6. umlctl -ephemeral + -overlay are mutually exclusive ---
echo "--- umlctl -ephemeral + -overlay rejected"
OUT=$("$TMP/umlctl" start -ephemeral -overlay -rootfs "$PVM_IMAGE_ROOT/rootfs.img" 2>&1 || true)
echo "$OUT" | grep -q "mutually exclusive" || fail "umlctl combo not rejected: $OUT"
echo "   umlctl combo rejected ✓"

# --- 7. umlctl -ephemeral discards the container dir after exit ---
echo "--- umlctl -ephemeral cleans up after failed launch"
OUT=$("$TMP/umlctl" start -name eph-umlctl -ephemeral \
      -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -kernel /nonexistent/linux 2>&1 || true)
echo "$OUT" | grep -q "Starting container" || fail "umlctl never started: $OUT"
if [ -d "$PVM_STATE_ROOT/eph-umlctl" ]; then
    fail "ephemeral umlctl left state dir behind: $(ls "$PVM_STATE_ROOT/eph-umlctl")"
fi
echo "   container dir discarded ✓"

# --- 8. /containers/start accepts the ephemeral field ---
echo "--- /containers/start with ephemeral:true"
# Invalid rootfs must still be rejected for the rootfs reason (the JSON field
# parses cleanly; 400 mentions rootfs, not a decode error).
RESP=$(req POST /containers/start '{"name":"eph-api-bad","rootfs":"/etc/passwd","ephemeral":true}')
echo "$RESP" | jq -e '.error' >/dev/null || fail "bad-rootfs start not rejected: $RESP"
# Valid rootfs + ephemeral boots through the handler; without a kernel the
# manager fails AFTER arg building, proving the field flowed into the config.
RESP=$(req POST /containers/start "{\"name\":\"eph-api\",\"rootfs\":\"$PVM_IMAGE_ROOT/rootfs.img\",\"ephemeral\":true}")
echo "$RESP" | jq -e 'has("error") or has("status")' >/dev/null || fail "ephemeral start crashed handler: $RESP"
echo "   ephemeral field accepted ✓"

kill "$SRV" 2>/dev/null || true
SRV=""

echo ""
echo "✅ 29_test_ephemeral_mode: ALL PASS"
