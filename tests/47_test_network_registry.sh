#!/usr/bin/env bash
# 47_test_network_registry.sh — persistent subnet allocator driving
# `umlctl network create/rm`: distinct /24s per network, registry persists,
# release frees the name. Requires root (bridge setup); skips otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$(id -u)" != "0" ]; then
    echo "⋮ skipping 47: needs root for bridge setup (CI runs it on the privileged leg)"
    exit 0
fi

TMP="$(mktemp -d)"
# The created bridges outlive the process: remove BOTH networks on exit so
# reruns and later privileged suites do not inherit regnet-b (the trap's
# rm -rf only clears the temp state dir, not the host network resources).
trap '"$TMP/umlctl" network rm regnet-a &>/dev/null || true; "$TMP/umlctl" network rm regnet-b &>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
mkdir -p "$PVM_STATE_ROOT"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${UMLCTL_BIN:-}" ]; then
    cp "$UMLCTL_BIN" "$TMP/umlctl"
else
    go build -o "$TMP/umlctl" ./cmd/umlctl
fi

echo "--- 1. two networks get distinct subnets"
"$TMP/umlctl" network create regnet-a &>"$TMP/a.log" || fail "create a: $(cat "$TMP/a.log")"
"$TMP/umlctl" network create regnet-b &>"$TMP/b.log" || fail "create b: $(cat "$TMP/b.log")"
SUB_A=$(jq -r '.networks[] | select(.name=="regnet-a") | .subnet' "$PVM_STATE_ROOT/networks.json")
SUB_B=$(jq -r '.networks[] | select(.name=="regnet-b") | .subnet' "$PVM_STATE_ROOT/networks.json")
[ -n "$SUB_A" ] && [ -n "$SUB_B" ] || fail "registry must record both"
[ "$SUB_A" != "$SUB_B" ] || fail "subnets must differ: $SUB_A"

echo "--- 2. re-creating an existing name fails loudly (no silent dup bridge)"
# SetupBridge's ip link add is not idempotent by design: a re-create must
# fail with the RTNETLINK "File exists" error instead of silently adding a
# second bridge — and the registry must keep the recorded subnet intact.
if "$TMP/umlctl" network create regnet-a &>"$TMP/a2.log"; then
    fail "re-create of an existing bridge must fail"
fi
grep -q "File exists" "$TMP/a2.log" || fail "re-create must surface the existing device: $(cat "$TMP/a2.log")"
SUB_A2=$(jq -r '.networks[] | select(.name=="regnet-a") | .subnet' "$PVM_STATE_ROOT/networks.json")
[ "$SUB_A2" = "$SUB_A" ] || fail "failed re-create must keep the recorded subnet: $SUB_A -> $SUB_A2"

echo "--- 3. rm releases the reservation"
"$TMP/umlctl" network rm regnet-a &>"$TMP/rm.log" || fail "rm a: $(cat "$TMP/rm.log")"
if jq -e '.networks[] | select(.name=="regnet-a")' "$PVM_STATE_ROOT/networks.json" >/dev/null; then
    fail "rm must release the name"
fi

echo "✅ 47 network registry suite passed"
