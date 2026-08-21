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

echo "==> building umlctl"
go build -o "$TMP/umlctl" ./cmd/umlctl

echo "--- 1. umlctl with no args prints usage"
OUT=$("$TMP/umlctl" 2>&1 || true)
echo "$OUT" | grep -q "Usage: umlctl" || fail "expected usage message: $OUT"
echo "   usage printed ✓"

echo "--- 2. umlctl with unrecognized command"
OUT=$("$TMP/umlctl" invalid_subcmd 2>&1 || true)
echo "$OUT" | grep -qi "not recognized" || fail "expected not recognized message: $OUT"
echo "   unrecognized command handled ✓"

echo "--- 3. umlctl start: negative CPU limit rejected"
OUT=$("$TMP/umlctl" start -cpu -1 2>&1 || true)
echo "$OUT" | grep -qi "cannot be negative" || fail "negative CPU not rejected: $OUT"
echo "   negative CPU rejected ✓"

echo "--- 4. umlctl start: invalid memory size rejected"
OUT=$("$TMP/umlctl" start -mem "512X" 2>&1 || true)
echo "$OUT" | grep -qi "error\|invalid" || fail "invalid memory format not rejected: $OUT"
echo "   invalid memory rejected ✓"

echo "--- 5. umlctl start: invalid container ID rejected"
OUT=$("$TMP/umlctl" start -name "../evil" 2>&1 || true)
echo "$OUT" | grep -qi "invalid container name" || fail "traversal name not rejected: $OUT"
echo "   invalid container name rejected ✓"

echo "--- 6. umlctl start: invalid volume format rejected"
OUT=$("$TMP/umlctl" start -volume "/host/path" 2>&1 || true)
echo "$OUT" | grep -qi "invalid volume format" || fail "malformed volume not rejected: $OUT"
echo "   invalid volume rejected ✓"

echo "--- 7. umlctl logs: missing container ID prints usage"
OUT=$("$TMP/umlctl" logs 2>&1 || true)
echo "$OUT" | grep -q "Usage: umlctl logs" || fail "expected logs usage: $OUT"
echo "   logs usage ✓"

echo "--- 8. umlctl logs: invalid ID rejected"
OUT=$("$TMP/umlctl" logs "../escape" 2>&1 || true)
echo "$OUT" | grep -qi "invalid container ID" || fail "invalid logs ID not rejected: $OUT"
echo "   invalid logs ID rejected ✓"

echo "--- 9. umlctl ps: lists containers table"
OUT=$("$TMP/umlctl" ps 2>&1)
echo "$OUT" | grep -q "CONTAINER ID" || fail "ps output missing header: $OUT"
echo "   ps header verified ✓"

echo "--- 10. umlctl network: invalid subcommand prints usage"
OUT=$("$TMP/umlctl" network invalid_net_cmd 2>&1 || true)
echo "$OUT" | grep -q "Usage: umlctl network" || fail "network usage missing: $OUT"
echo "   network usage verified ✓"

echo ""
echo "✅ 17_test_umlctl_cli: ALL PASS"
