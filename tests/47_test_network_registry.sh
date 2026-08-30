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
trap 'rm -rf "$TMP"' EXIT

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

echo "--- 2. create is idempotent for the same name"
"$TMP/umlctl" network create regnet-a &>"$TMP/a2.log" || fail "re-create a"
SUB_A2=$(jq -r '.networks[] | select(.name=="regnet-a") | .subnet' "$PVM_STATE_ROOT/networks.json")
[ "$SUB_A2" = "$SUB_A" ] || fail "same name must keep its subnet: $SUB_A -> $SUB_A2"

echo "--- 3. rm releases the reservation"
"$TMP/umlctl" network rm regnet-a &>"$TMP/rm.log" || fail "rm a: $(cat "$TMP/rm.log")"
if jq -e '.networks[] | select(.name=="regnet-a")' "$PVM_STATE_ROOT/networks.json" >/dev/null; then
    fail "rm must release the name"
fi

echo "✅ 47 network registry suite passed"
