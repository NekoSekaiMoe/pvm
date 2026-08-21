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

run_fail() {
    set +e
    OUT=$("$@" 2>&1)
    local code=$?
    set -e
    [ "$code" -ne 0 ] || fail "expected non-zero exit code for: $*"
}

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

echo "--- 3. Invalid IDs rejected on export and import (and fail with non-zero exit)"
run_fail "$TMP/agentpvm" snapshot export '../escape' "$TMP/x.tgz"
echo "$OUT" | grep -qi "invalid container ID" || fail "export traversal not rejected: $OUT"

run_fail "$TMP/agentpvm" snapshot import 'bad/id' "$TMP/snap1.tgz"
echo "$OUT" | grep -qi "invalid container ID" || fail "import bad id not rejected: $OUT"
echo "   invalid ID checks passed and failed with non-zero exit ✓"

echo "--- 4. Import onto existing container ID is refused (no overwrite)"
run_fail "$TMP/agentpvm" snapshot import c-restored "$TMP/snap1.tgz"
echo "$OUT" | grep -qi "already exists" || fail "import overwrite not refused: $OUT"
echo "   existing ID overwrite prevented and failed with non-zero exit ✓"

echo "--- 5. Symlink pivot directory traversal attack rejected"
OUTSIDE="$TMP/outside_target"
mkdir -p "$OUTSIDE"
ATTACK_DIR="$TMP/attack"
mkdir -p "$ATTACK_DIR"
ln -s "$OUTSIDE" "$ATTACK_DIR/pivot"
echo "evil_content" > "$ATTACK_DIR/pivot/evil.txt" || true
# Create malicious tarball with pivot symlink pointing to OUTSIDE
tar -czf "$TMP/pivot_attack.tgz" -C "$ATTACK_DIR" .
rm -f "$OUTSIDE/evil.txt"

run_fail "$TMP/agentpvm" snapshot import c-attack "$TMP/pivot_attack.tgz"
[ ! -f "$OUTSIDE/evil.txt" ] || fail "symlink pivot wrote file to outside directory!"
echo "   symlink pivot import rejected and outside directory unpolluted ✓"

echo ""
echo "✅ 20_test_snapshot_security: ALL PASS"
