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
[security]
allow_insecure_degraded = true
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

# --- 4. -ephemeral override drops the meaningless compact_on_exit knob ---
echo "--- -ephemeral override over compact_on_exit config is accepted"
# compact_on_exit is a no-op knob in ephemeral mode (no overlay exists to
# compact), so an explicit CLI flip wins and drops it instead of failing
# Validate — the spec-LEVEL conflict is still rejected by load-spec (case 2).
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
[security]
allow_insecure_degraded = true
EOF
OUT=$("$TMP/agentpvm" run -config "$TMP/conflict.toml" -ephemeral 2>&1 || true)
echo "$OUT" | grep -q "Loaded TaskSpec" || fail "config not loaded: $OUT"
echo "$OUT" | grep -q "overrides leave spec invalid" \
    && fail "CLI -ephemeral wrongly conflicted with compact_on_exit: $OUT"
# ...and the ephemeral launch still leaves no overlay behind.
if find "$PVM_STATE_ROOT/eph-conflict" -name '*.qcow2' 2>/dev/null | grep -q .; then
    fail "ephemeral override task left an overlay: $(find "$PVM_STATE_ROOT/eph-conflict" -name '*.qcow2')"
fi
echo "   override drops compact_on_exit, no conflict ✓"

# --- 5. repo default config + -ephemeral stays compatible ---
echo "--- agentpvm run -ephemeral over the repo default config"
# No -config: resolveConfigPath falls back to uml/agentpvm.toml, which sets
# compact_on_exit = true. The explicit CLI flip must drop that knob and pass
# the final Validate. The launch itself then fails on the missing kernel and
# out-of-root base image ("rootfs.img" is not under PVM_IMAGE_ROOT) — that is
# expected and NOT a validation failure.
OUT=$("$TMP/agentpvm" run -ephemeral 2>&1 || true)
echo "$OUT" | grep -q "Loaded TaskSpec from uml/agentpvm.toml" \
    || fail "repo default config not consulted: $OUT"
echo "$OUT" | grep -q "overrides leave spec invalid" \
    && fail "repo default config + -ephemeral wrongly conflicted: $OUT"
echo "   default config compatible with -ephemeral ✓"

# --- 6. -ephemeral=false explicitly wins over the config file ---
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

# --- 7. umlctl -ephemeral + -overlay are mutually exclusive ---
echo "--- umlctl -ephemeral + -overlay rejected"
OUT=$("$TMP/umlctl" start -ephemeral -overlay -rootfs "$PVM_IMAGE_ROOT/rootfs.img" 2>&1 || true)
echo "$OUT" | grep -q "mutually exclusive" || fail "umlctl combo not rejected: $OUT"
echo "   umlctl combo rejected ✓"

# --- 8. umlctl -ephemeral discards the container dir after exit ---
echo "--- umlctl -ephemeral cleans up after failed launch"
OUT=$("$TMP/umlctl" start -name eph-umlctl -ephemeral \
      -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -kernel /nonexistent/linux 2>&1 || true)
echo "$OUT" | grep -q "Starting container" || fail "umlctl never started: $OUT"
if [ -d "$PVM_STATE_ROOT/eph-umlctl" ]; then
    fail "ephemeral umlctl left state dir behind: $(ls "$PVM_STATE_ROOT/eph-umlctl")"
fi
echo "   container dir discarded ✓"

# --- 9. /containers/start accepts the ephemeral field ---
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

# --- 10. umlctl -config load failure exits non-zero ---
echo "--- umlctl -config with a broken TOML exits non-zero"
printf 'this is not = valid toml {{{\n' > "$TMP/broken.toml"
OUT=$("$TMP/umlctl" start -config "$TMP/broken.toml" 2>&1) && \
    fail "umlctl -config load failure exited 0: $OUT"
echo "$OUT" | grep -q "load failed" || fail "no load-failure diagnostic: $OUT"
echo "   bad -config fails fast ✓"

kill "$SRV" 2>/dev/null || true
SRV=""

echo ""
echo "✅ 29_test_ephemeral_mode: ALL PASS"
