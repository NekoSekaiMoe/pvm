#!/usr/bin/env bash
# 18_test_agentpvm_cli.sh — E2E test for agentpvm CLI subcommands and flag validation.
# Covers: agentpvm usage, gate, snapshot, network, cgroup, cow, approval, and pool usage messages.
# CI-safe (no kernel required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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

echo "--- 1. agentpvm with no args prints usage and fails"
run_fail "$TMP/agentpvm"
echo "$OUT" | grep -q "Usage: agentpvm" || fail "top usage missing: $OUT"
echo "   top-level usage ✓"

echo "--- 2. agentpvm unknown subcommand"
run_fail "$TMP/agentpvm" unknown_subcmd
echo "$OUT" | grep -qi "unknown command" || fail "unknown command message missing: $OUT"
echo "   unknown command handled ✓"

echo "--- 3. agentpvm gate without -bundle prints usage and fails"
run_fail "$TMP/agentpvm" gate
echo "$OUT" | grep -q "Usage: agentpvm gate" || fail "gate usage missing: $OUT"
echo "   gate usage ✓"

echo "--- 4. agentpvm snapshot without args prints usage and fails"
run_fail "$TMP/agentpvm" snapshot
echo "$OUT" | grep -q "Usage: agentpvm snapshot" || fail "snapshot usage missing: $OUT"
echo "   snapshot usage ✓"

echo "--- 5. agentpvm network without args prints usage and fails"
run_fail "$TMP/agentpvm" network
echo "$OUT" | grep -q "Usage: agentpvm network" || fail "network usage missing: $OUT"
echo "   network usage ✓"

echo "--- 6. agentpvm cgroup without args prints usage and fails"
run_fail "$TMP/agentpvm" cgroup
echo "$OUT" | grep -q "Usage: agentpvm cgroup" || fail "cgroup usage missing: $OUT"
echo "   cgroup usage ✓"

echo "--- 7. agentpvm cow without args prints usage and fails"
run_fail "$TMP/agentpvm" cow
echo "$OUT" | grep -q "Usage: agentpvm cow" || fail "cow usage missing: $OUT"
echo "   cow usage ✓"

echo "--- 8. agentpvm approval without args prints usage and fails"
run_fail "$TMP/agentpvm" approval
echo "$OUT" | grep -q "Usage: agentpvm approval" || fail "approval usage missing: $OUT"
echo "   approval usage ✓"

echo "--- 9. agentpvm pool without args prints usage and fails"
run_fail "$TMP/agentpvm" pool
echo "$OUT" | grep -q "Usage: agentpvm pool" || fail "pool usage missing: $OUT"
echo "   pool usage ✓"

echo ""
echo "✅ 18_test_agentpvm_cli: ALL PASS"
