#!/usr/bin/env bash
# 20_test_snapshot_security.sh — E2E test for container snapshot archiving and traversal security.
# Covers: Export/import round-trip, invalid ID rejection, and import onto existing ID prevention.
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

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "--- 1. Setup mock container and snapshot export"
mkdir -p "$PVM_STATE_ROOT/c-source/sub"
echo '{"id":"c-source","status":"stopped"}' > "$PVM_STATE_ROOT/c-source/state.json"
echo "data-file-1" > "$PVM_STATE_ROOT/c-source/file1.txt"
echo "data-file-2" > "$PVM_STATE_ROOT/c-source/sub/file2.txt"

OUT=$("$TMP/agentpvm" snapshot export c-source "$TMP/snap1.tgz")
echo "$OUT" | grep -q "Snapshot exported successfully" || fail "export failed: $OUT"
[ -f "$TMP/snap1.tgz" ] || fail "archive not created"
echo "   exported snapshot archive ✓"

echo "--- 2. Snapshot import restores directory structure byte-identically"
OUT=$("$TMP/agentpvm" snapshot import c-restored "$TMP/snap1.tgz")
echo "$OUT" | grep -q "Snapshot imported successfully" || fail "import failed: $OUT"
diff -r "$PVM_STATE_ROOT/c-source" "$PVM_STATE_ROOT/c-restored" >/dev/null || fail "imported files differ from source"
echo "   imported structure matches source ✓"

echo "--- 3. Invalid IDs rejected on export and import"
OUT=$("$TMP/agentpvm" snapshot export '../escape' "$TMP/x.tgz" 2>&1 || true)
echo "$OUT" | grep -qi "invalid container ID" || fail "export traversal not rejected: $OUT"

OUT=$("$TMP/agentpvm" snapshot import 'bad/id' "$TMP/snap1.tgz" 2>&1 || true)
echo "$OUT" | grep -qi "invalid container ID" || fail "import bad id not rejected: $OUT"
echo "   invalid ID checks passed ✓"

echo "--- 4. Import onto existing container ID is refused (no overwrite)"
OUT=$("$TMP/agentpvm" snapshot import c-restored "$TMP/snap1.tgz" 2>&1 || true)
echo "$OUT" | grep -qi "already exists" || fail "import overwrite not refused: $OUT"
echo "   existing ID overwrite prevented ✓"

echo ""
echo "✅ 20_test_snapshot_security: ALL PASS"
