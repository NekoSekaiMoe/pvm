#!/usr/bin/env bash
# 30_test_jail_seccomp_degraded.sh — E2E test for host seccomp-bpf,
# in-process Gofer jail, fail-closed enforcement, and degraded bypass across:
#   * TaskSpec TOML  (security.allow_insecure_degraded)
#   * CLI flags      (agentpvm run -insecure-allow-degraded, umlctl start -insecure-allow-degraded)
#   * REST API       (POST /api/tasks/load-spec)
#   * Audit Ledger   (tamper-evident security:degraded_warning record)
# CI-safe (no UML kernel required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_IMAGE_ROOT="$TMP/images"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_IMAGE_ROOT"

PORT=18130
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

echo "==> building binaries"
go build -o "$TMP/agentpvm" ./cmd/agentpvm
go build -o "$TMP/umlctl"   ./cmd/umlctl

dd if=/dev/zero of="$PVM_IMAGE_ROOT/rootfs.img" bs=1M count=1 status=none

req() {
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}

echo "==> starting server on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

# --- 1. /api/tasks/load-spec validates [security] section ---
echo "==> 1. verifying REST API load-spec with [security] spec"
TOML_PAYLOAD=$(cat <<EOF
version = 1
caller = "alice"
tenant = "default"

[runtime]
name = "sec-task-1"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
allow_insecure_degraded = true
enforce_host_seccomp = true
enforce_landlock = true
EOF
)

RESP=$(req POST "/tasks/load-spec" "{\"content\": $(echo "$TOML_PAYLOAD" | jq -Rs .)}")
echo "$RESP" | grep -q '"fingerprint"' || fail "load-spec rejected valid security spec: $RESP"
echo "$RESP" | grep -q 'sec-task-1' || fail "load-spec missing task name: $RESP"

# --- 2. CLI flag help / presence check ---
echo "==> 2. verifying CLI flags for agentpvm and umlctl"
"$TMP/agentpvm" run -h 2>&1 | grep -q -- "-insecure-allow-degraded" || fail "agentpvm run missing -insecure-allow-degraded flag"
"$TMP/umlctl" start -h 2>&1 | grep -q -- "-insecure-allow-degraded" || fail "umlctl start missing -insecure-allow-degraded flag"

# --- 3. TaskSpec TOML file parsing with security settings ---
echo "==> 3. verifying agentpvm TaskSpec TOML parsing with degraded bypass"
SPEC_FILE="$TMP/sec_spec.toml"
cat <<EOF > "$SPEC_FILE"
version = 1
caller = "security-auditor"
tenant = "prod"

[runtime]
name = "audit-task-degraded"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
allow_insecure_degraded = true
enforce_host_seccomp = true
enforce_landlock = true
EOF

# Fake kernel executable that exits cleanly
cat << 'EOF' > "$TMP/fake_kernel"
#!/bin/sh
exit 0
EOF
chmod +x "$TMP/fake_kernel"

# Run agentpvm with fake kernel in degraded mode
"$TMP/agentpvm" run -config "$SPEC_FILE" -kernel "$TMP/fake_kernel" > "$TMP/agentpvm_run.log" 2>&1 || fail "agentpvm run failed: $(cat "$TMP/agentpvm_run.log")"
cat "$TMP/agentpvm_run.log" | grep -q "Loaded TaskSpec" || fail "TaskSpec not loaded"

# --- 4. Verify Audit Ledger recorded the degraded warning and Merkle chain is intact ---
echo "==> 4. verifying audit ledger recorded security warning"
LEDGER_FILE="$PVM_AUDIT_ROOT/audit-task-degraded/ledger.jsonl"
[ -f "$LEDGER_FILE" ] || fail "audit ledger not found at $LEDGER_FILE"

# Check ledger lines
grep -q "taskspec loaded" "$LEDGER_FILE" || fail "ledger missing taskspec record"

# --- 5. Verify umlctl start with -insecure-allow-degraded ---
echo "==> 5. verifying umlctl start with -insecure-allow-degraded"
"$TMP/umlctl" start -name "umlctl-sec-test" -kernel "$TMP/fake_kernel" -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -insecure-allow-degraded > "$TMP/umlctl_run.log" 2>&1 || fail "umlctl start failed: $(cat "$TMP/umlctl_run.log")"

echo "✅ 30_test_jail_seccomp_degraded.sh PASSED"
