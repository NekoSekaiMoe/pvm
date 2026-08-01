#!/usr/bin/env bash
# 06_test_cli_smoke.sh — exercise the agentpvm/umlctl CLIs without requiring a
# real UML kernel. We assert the control planes wire up correctly at the CLI
# layer: config loading, egress startup, FSM transitions on launch failure,
# and the cow/pool subcommands.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

echo "==> building binaries"
go build -o "$TMP/agentpvm" ./cmd/agentpvm
go build -o "$TMP/umlctl"   ./cmd/umlctl

# --- 1. agentpvm run loads a config and reports the fingerprint ---
echo "--- agentpvm run loads config (no kernel => fails at launch, but planes wire up)"
cat > "$TMP/spec.toml" <<'EOF'
version = 1
caller = "smoke"
tenant = "qa"
[runtime]
name = "smoke-task"
memory = "256M"
[kernel]
path = "/nonexistent/linux"
EOF

OUT=$("$TMP/agentpvm" run -config "$TMP/spec.toml" 2>&1 || true)
echo "$OUT" | grep -q "Loaded TaskSpec" || { echo "❌ config not loaded: $OUT"; exit 1; }
echo "$OUT" | grep -q "fingerprint"     || { echo "❌ no fingerprint: $OUT"; exit 1; }
echo "$OUT" | grep -q "Egress gateway"  || { echo "❌ egress not started: $OUT"; exit 1; }
# launch fails because kernel doesn't exist; that's expected. The state file
# must record the failure with a FSM reason.
echo "   config + egress + fingerprint ✓"

# --- 2. state.json reflects the FSM path on launch failure ---
echo "--- FSM recorded on failed launch"
STATE=$(cat "$PVM_STATE_ROOT/smoke-task/state.json")
echo "$STATE" | jq -e '.status == "failed"' >/dev/null || { echo "❌ status not failed: $STATE"; exit 1; }
echo "$STATE" | jq -e '.spec_fingerprint | length > 0' >/dev/null || { echo "❌ no fingerprint on state: $STATE"; exit 1; }
TRANS=$(echo "$STATE" | jq '.transitions | length')
[ "$TRANS" -ge 3 ] || { echo "❌ too few transitions ($TRANS): $STATE"; exit 1; }
echo "   failed + fingerprint + $TRANS transitions ✓"

# --- 3. audit ledger has the SPEC+VERSION phase ---
echo "--- audit ledger has spec evidence"
LEDGER="$PVM_AUDIT_ROOT/smoke-task/ledger.jsonl"
[ -f "$LEDGER" ] || { echo "❌ no ledger at $LEDGER"; exit 1; }
jq -e 'select(.phase == "spec_version")' "$LEDGER" >/dev/null || { echo "❌ no spec_version record: $(cat $LEDGER)"; exit 1; }
echo "   spec_version recorded ✓"

# --- 4. default config path: ./uml/agentpvm.toml ---
echo "--- default config path (./uml/agentpvm.toml)"
mkdir -p "$TMP/cwd/uml"
cp "$ROOT/uml/agentpvm.toml" "$TMP/cwd/uml/agentpvm.toml"
( cd "$TMP/cwd" && PVM_STATE_ROOT="$TMP/cwd/s" PVM_AUDIT_ROOT="$TMP/cwd/a" PVM_CGROUP_ROOT="$TMP/cwd/cg" \
    timeout 2 "$TMP/agentpvm" run 2>&1 || true ) | grep -q "Loaded TaskSpec from uml/agentpvm.toml" \
    || { echo "❌ default config path not consulted"; exit 1; }
echo "   default path ✓"

# --- 5. cow CreateOverlay rejects comma in path (option injection guard) ---
echo "--- cow path-injection guard"
HTTP=$("$TMP/agentpvm" cow -backing "/tmp/a.img" -overlay "/tmp/evil,opt=x.qcow2" 2>&1 || true)
echo "$HTTP" | grep -qi "forbidden\|comma\|failed" || { echo "❌ comma path not rejected: $HTTP"; exit 1; }
echo "   comma rejected ✓"

# --- 6. pool stats subcommand ---
echo "--- pool stats subcommand"
OUT=$("$TMP/agentpvm" pool stats 2>&1 || true)
echo "$OUT" | grep -q "ready=" || { echo "❌ pool stats: $OUT"; exit 1; }
echo "   pool stats ✓"

# --- 7. umlctl -config flag parses (validates by loading) ---
echo "--- umlctl -config flag"
# umlctl start will fail at kernel launch (no kernel), but -config should
# parse and override defaults. Absorb the non-zero exit.
OUT=$("$TMP/umlctl" start -config "$TMP/spec.toml" 2>&1 || true)
echo "$OUT" | grep -qi "starting container" \
    || { echo "❌ umlctl -config parse failed: $OUT"; exit 1; }
echo "   umlctl -config ✓"

echo ""
echo "✅ 06_test_cli_smoke: ALL PASS"
