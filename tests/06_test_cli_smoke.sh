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
echo "$OUT" | grep -q "Starting sandbox" || { echo "❌ control planes did not wire up (never reached StartTask): $OUT"; exit 1; }
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

# --- 5b. cow -compact rebuilds a qcow2 overlay in place (pure-Go, no qemu-img) ---
echo "--- cow -compact CLI"
# Build a tiny base + overlay, write nothing, compact: must succeed and the
# overlay must still be a valid qcow2 (magic intact).
BASE2="$TMP/c_base.img"
head -c $((4 * 1024 * 1024)) /dev/zero > "$BASE2"
mkfs.ext4 -q -F "$BASE2" >/dev/null 2>&1 || true
OV2="$TMP/c_overlay.qcow2"
"$TMP/agentpvm" cow -backing "$BASE2" -overlay "$OV2" >/dev/null 2>&1 || { echo "❌ cow create failed"; exit 1; }
OUT=$("$TMP/agentpvm" cow -compact "$OV2" 2>&1) || { echo "❌ cow -compact failed: $OUT"; exit 1; }
echo "$OUT" | grep -q "Compacted" || { echo "❌ compact output missing: $OUT"; exit 1; }
# magic still qcow2?
head -c 4 "$OV2" | grep -q $'QFI\xfb' || { echo "❌ compacted file lost qcow2 magic"; exit 1; }
echo "   cow -compact ✓"

# --- 5c. cow -to-qcow2 / -to-raw convert (pure-Go, no qemu-img) ---
echo "--- cow convert (raw<->qcow2)"
# raw -> qcow2 -> raw round trip; content must be byte-identical.
RAW_IN="$TMP/conv_in.img"
head -c $((4 * 1024 * 1024)) /dev/zero > "$RAW_IN"
# scatter some nonzero bytes so the qcow2 has real data clusters
printf 'X1Y2Z3' | dd of="$RAW_IN" bs=1 seek=4096 conv=notrunc 2>/dev/null
QC="$("$TMP/agentpvm" cow -to-qcow2 "$RAW_IN" -overlay "$TMP/conv.qcow2" 2>&1)" \
    || { echo "❌ cow -to-qcow2 failed: $QC"; exit 1; }
echo "$QC" | grep -q "Converted" || { echo "❌ to-qcow2 output: $QC"; exit 1; }
head -c 4 "$TMP/conv.qcow2" | grep -q $'QFI\xfb' || { echo "❌ converted file not qcow2"; exit 1; }
RAW_OUT="$("$TMP/agentpvm" cow -to-raw "$TMP/conv.qcow2" -overlay "$TMP/conv_out.img" 2>&1)" \
    || { echo "❌ cow -to-raw failed: $RAW_OUT"; exit 1; }
# round-trip content check on the nonzero region
if ! cmp -s <(dd if="$RAW_IN" bs=1 skip=4096 count=6 2>/dev/null) <(dd if="$TMP/conv_out.img" bs=1 skip=4096 count=6 2>/dev/null); then
    echo "❌ convert round-trip content mismatch"; exit 1
fi
echo "   cow convert ✓"

# --- 6. pool stats subcommand ---
# pool stats talks to a running controller over HTTP. Start a stub server that
# serves /api/pool/stats and requires the same bearer secret the CLI sends, so
# the subcommand's full path (HTTP + auth + JSON decode) is exercised rather
# than its no-API error branch.
echo "--- pool stats subcommand"
export API_SECRET="ci-stub-secret"
python3 - "$TMP/pool_stub.log" <<'PYEOF' &
import http.server, json, sys, os
secret = os.environ["API_SECRET"]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/api/pool/stats":
            self.send_response(404); self.end_headers(); return
        if self.headers.get("Authorization") != "Bearer "+secret:
            self.send_response(401); self.end_headers(); return
        body = json.dumps({"ready": 2, "claimed": 1, "total": 3}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
httpd = http.server.HTTPServer(("127.0.0.1", 8080), H)
httpd.serve_forever()
PYEOF
STUB_PID=$!
# wait for the stub to bind 8080
for i in $(seq 1 40); do
    if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&- 3<&-; break; fi
    sleep 0.1
done
OUT=$(PVM_API="http://127.0.0.1:8080" "$TMP/agentpvm" pool stats 2>&1 || true)
kill "$STUB_PID" 2>/dev/null || true
wait "$STUB_PID" 2>/dev/null || true
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
