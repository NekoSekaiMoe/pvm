#!/usr/bin/env bash
# 07_test_gate_snapshot_cli.sh — exercise the `agentpvm gate` and
# `agentpvm snapshot` subcommands without a UML kernel. CI-safe.
#
# Covers:
#   gate:     PASS path (exit 0), secret-scan FAIL path (exit 1 + per-step
#             reasons), missing/invalid bundle file, missing -bundle flag,
#             and the audit row the gate writes for both outcomes.
#   snapshot: export/import round trip with content comparison, invalid
#             container id rejection, and import-onto-existing-id rejection.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

fail() { echo "❌ $1"; exit 1; }

# =========================================================================
# gate
# =========================================================================

# --- 1. clean bundle passes (exit 0) and writes an allow audit row ---
echo "--- gate: clean bundle passes"
cat > "$TMP/bundle-clean.json" <<'EOF'
{
  "task_id": "gate-clean",
  "diff": "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n",
  "build_log": "build ok, tests ok",
  "trace": ["shell: go build ./...", "shell: go test ./..."],
  "files": {"out/report.txt": "aGVsbG8gd29ybGQ="},
  "claimed_ok": true
}
EOF
OUT=$("$TMP/agentpvm" gate -bundle "$TMP/bundle-clean.json") || fail "clean bundle should exit 0: $OUT"
echo "$OUT" | grep -q "^PASS (hash=[0-9a-f]\{64\})$" || fail "unexpected PASS output: $OUT"
jq -e 'select(.action == "artifact_gate" and .decision == "allow")' \
    "$PVM_AUDIT_ROOT/gate-clean/ledger.jsonl" >/dev/null \
    || fail "no allow audit row: $(cat "$PVM_AUDIT_ROOT/gate-clean/ledger.jsonl")"
echo "   PASS + audit allow row ✓"

# --- 2. bundle carrying an AWS key fails (exit 1) with step reasons ---
echo "--- gate: secret in diff is blocked"
cat > "$TMP/bundle-secret.json" <<'EOF'
{
  "task_id": "gate-secret",
  "diff": "+aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
  "build_log": "ok",
  "trace": [],
  "claimed_ok": true
}
EOF
OUT=$("$TMP/agentpvm" gate -bundle "$TMP/bundle-secret.json" 2>&1) && fail "secret bundle should exit 1"
echo "$OUT" | grep -q "^FAIL"            || fail "expected FAIL verdict: $OUT"
echo "$OUT" | grep -q "secret_scan: fail" || fail "expected secret_scan step failure: $OUT"
jq -e 'select(.action == "artifact_gate" and .decision == "deny")' \
    "$PVM_AUDIT_ROOT/gate-secret/ledger.jsonl" >/dev/null \
    || fail "no deny audit row for secret bundle"
echo "   FAIL + secret_scan reason + audit deny row ✓"

# --- 3. secret hidden in a declared file is also caught ---
echo "--- gate: secret inside files map is blocked"
# base64 without line wrapping; `-w0` is GNU-only, so use `tr` for BSD/macOS compat.
SECRET_B64=$(printf 'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' | base64 | tr -d '\n')
cat > "$TMP/bundle-filesecret.json" <<EOF
{"task_id": "gate-filesecret", "diff": "", "build_log": "", "trace": [],
 "files": {"config.env": "$SECRET_B64"}, "claimed_ok": true}
EOF
OUT=$("$TMP/agentpvm" gate -bundle "$TMP/bundle-filesecret.json" 2>&1) && fail "file-secret bundle should exit 1"
echo "$OUT" | grep -q "secret_scan: fail" || fail "expected secret_scan failure for file content: $OUT"
echo "   file content scanned ✓"

# --- 4. missing bundle file ---
echo "--- gate: missing bundle file"
OUT=$("$TMP/agentpvm" gate -bundle "$TMP/does-not-exist.json" 2>&1) && fail "missing file should exit 1"
echo "$OUT" | grep -qi "read bundle" || fail "expected read error: $OUT"
echo "   missing file rejected ✓"

# --- 5. malformed JSON ---
echo "--- gate: malformed JSON"
echo '{not json' > "$TMP/bundle-bad.json"
OUT=$("$TMP/agentpvm" gate -bundle "$TMP/bundle-bad.json" 2>&1) && fail "malformed JSON should exit 1"
echo "$OUT" | grep -qi "parse bundle" || fail "expected parse error: $OUT"
echo "   malformed JSON rejected ✓"

# --- 6. missing -bundle flag prints usage ---
echo "--- gate: missing -bundle flag"
OUT=$("$TMP/agentpvm" gate 2>&1) && fail "no -bundle should exit 1"
echo "$OUT" | grep -q "Usage: agentpvm gate" || fail "expected usage line: $OUT"
echo "   usage ✓"

# =========================================================================
# snapshot
# =========================================================================

# --- 7. export/import round trip preserves content ---
echo "--- snapshot: export/import round trip"
mkdir -p "$PVM_STATE_ROOT/src01/data/nested"
echo '{"id":"src01","status":"exited"}' > "$PVM_STATE_ROOT/src01/state.json"
echo "payload-one" > "$PVM_STATE_ROOT/src01/data/file1.txt"
echo "payload-two" > "$PVM_STATE_ROOT/src01/data/nested/file2.txt"

OUT=$("$TMP/agentpvm" snapshot export src01 "$TMP/src01.tgz")
echo "$OUT" | grep -q "Snapshot exported successfully" || fail "export failed: $OUT"
[ -f "$TMP/src01.tgz" ] || fail "archive not created"

OUT=$("$TMP/agentpvm" snapshot import dst02 "$TMP/src01.tgz")
echo "$OUT" | grep -q "Snapshot imported successfully" || fail "import failed: $OUT"
diff -r "$PVM_STATE_ROOT/src01" "$PVM_STATE_ROOT/dst02" >/dev/null \
    || fail "imported tree differs from source"
echo "   round trip identical ✓"

# --- 8. invalid container ids are rejected on both directions ---
echo "--- snapshot: invalid ids rejected"
OUT=$("$TMP/agentpvm" snapshot export '../evil' "$TMP/x.tgz" 2>&1)
echo "$OUT" | grep -q "Export failed: invalid container ID" || fail "export traversal not rejected: $OUT"
OUT=$("$TMP/agentpvm" snapshot import 'a/b' "$TMP/src01.tgz" 2>&1)
echo "$OUT" | grep -q "Import failed: invalid container ID" || fail "import bad id not rejected: $OUT"
[ ! -e "$PVM_STATE_ROOT/evil" ] || fail "traversal id created a directory"
echo "   invalid ids rejected ✓"

# --- 9. import onto an existing id is refused (no silent overlay) ---
echo "--- snapshot: import onto existing id refused"
OUT=$("$TMP/agentpvm" snapshot import dst02 "$TMP/src01.tgz" 2>&1)
echo "$OUT" | grep -q "Import failed: container directory already exists" \
    || fail "re-import not refused: $OUT"
echo "   existing id refused ✓"

# --- 10. usage line with no args ---
echo "--- snapshot: usage"
OUT=$("$TMP/agentpvm" snapshot 2>&1)
echo "$OUT" | grep -q "Usage: agentpvm snapshot" || fail "expected usage line: $OUT"
echo "   usage ✓"

echo ""
echo "✅ 07_test_gate_snapshot_cli: ALL PASS"
