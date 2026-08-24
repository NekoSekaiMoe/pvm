#!/usr/bin/env bash
# 17_test_umlctl_cli.sh — E2E test for umlctl CLI subcommands and parameter validation.
# Covers: umlctl start (CPU/mem/name/volume validation), umlctl logs (ID validation),
# umlctl ps, and umlctl network subcommands.
# CI-safe (no kernel required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

fail() { echo "❌ $1"; exit 1; }

run_fail() {
    set +e
    OUT=$("$@" 2>&1)
    local code=$?
    set -e
    [ "$code" -ne 0 ] || fail "expected non-zero exit code for: $*"
}

if [ -n "${UMLCTL_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/umlctl ($UMLCTL_BIN)"
    cp "$UMLCTL_BIN" "$TMP/umlctl"
else
    echo "==> building $TMP/umlctl"
    go build -o "$TMP/umlctl" ./cmd/umlctl
fi

echo "--- 1. umlctl with no args prints usage and fails"
run_fail "$TMP/umlctl"
echo "$OUT" | grep -q "Usage: umlctl" || fail "expected usage message: $OUT"
echo "   usage printed and failed ✓"

echo "--- 2. umlctl with unrecognized command"
run_fail "$TMP/umlctl" invalid_subcmd
echo "$OUT" | grep -qi "not recognized" || fail "expected not recognized message: $OUT"
echo "   unrecognized command handled and failed ✓"

echo "--- 3. umlctl start: negative CPU limit rejected"
run_fail "$TMP/umlctl" start -cpu -1
echo "$OUT" | grep -qi "cannot be negative" || fail "negative CPU not rejected: $OUT"
echo "   negative CPU rejected and failed ✓"

echo "--- 4. umlctl start: invalid memory size rejected"
run_fail "$TMP/umlctl" start -mem "512X"
echo "$OUT" | grep -qi "error\|invalid" || fail "invalid memory format not rejected: $OUT"
echo "   invalid memory rejected and failed ✓"

echo "--- 5. umlctl start: invalid container ID rejected"
run_fail "$TMP/umlctl" start -name "../evil"
echo "$OUT" | grep -qi "invalid container name" || fail "traversal name not rejected: $OUT"
echo "   invalid container name rejected and failed ✓"

echo "--- 6. umlctl start: invalid volume format rejected"
run_fail "$TMP/umlctl" start -volume "/host/path"
echo "$OUT" | grep -qi "invalid volume format" || fail "malformed volume not rejected: $OUT"
echo "   invalid volume rejected and failed ✓"

echo "--- 7. umlctl logs: missing container ID prints usage and fails"
run_fail "$TMP/umlctl" logs
echo "$OUT" | grep -q "Usage: umlctl logs" || fail "expected logs usage: $OUT"
echo "   logs usage and failed ✓"

echo "--- 8. umlctl logs: invalid ID rejected"
run_fail "$TMP/umlctl" logs "../escape"
echo "$OUT" | grep -qi "invalid container ID" || fail "invalid logs ID not rejected: $OUT"
echo "   invalid logs ID rejected and failed ✓"

echo "--- 9. umlctl ps: lists containers table"
OUT=$("$TMP/umlctl" ps 2>&1)
echo "$OUT" | grep -q "CONTAINER ID" || fail "ps output missing header: $OUT"
echo "   ps header verified ✓"

echo "--- 10. umlctl network: invalid subcommand prints usage and fails"
run_fail "$TMP/umlctl" network invalid_net_cmd
echo "$OUT" | grep -q "Usage: umlctl network" || fail "network usage missing: $OUT"
echo "   network usage and failed ✓"

echo ""
echo "✅ 17_test_umlctl_cli: ALL PASS"
