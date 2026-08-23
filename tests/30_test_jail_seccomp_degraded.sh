#!/usr/bin/env bash
# 30_test_jail_seccomp_degraded.sh — E2E test for host seccomp-bpf,
# in-process Gofer jail, fail-closed enforcement, and degraded bypass across:
#   * Non-root (unprivileged) Fail-Closed and degraded bypass verification
#   * Root (privileged) process isolation & capability verification
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

# Fake kernel executable that exits cleanly
cat << 'EOF' > "$TMP/fake_kernel"
#!/bin/sh
exit 0
EOF
chmod +x "$TMP/fake_kernel"

# --- 3. Non-Root (Unprivileged) Mode Verification ---
echo "==> 3. verifying Non-Root mode: fail-closed enforcement & degraded bypass"

# 3a. Strict spec without allow_insecure_degraded -> should fail-closed if host primitives missing
SPEC_STRICT="$TMP/sec_strict.toml"
cat <<EOF > "$SPEC_STRICT"
version = 1
caller = "security-auditor"
tenant = "prod"

[runtime]
name = "audit-task-strict"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
allow_insecure_degraded = false
enforce_host_seccomp = true
enforce_landlock = true
EOF

# In unprivileged environment where landlock/mountns is not enabled, running strict must fail-closed
HOST_DEGRADED=0
if ! "$TMP/agentpvm" run -config "$SPEC_STRICT" -kernel "$TMP/fake_kernel" > "$TMP/strict_run.log" 2>&1; then
    grep -q "fail-closed" "$TMP/strict_run.log" || fail "expected fail-closed error in strict mode: $(cat "$TMP/strict_run.log")"
    HOST_DEGRADED=1
    echo "   non-root strict fail-closed verified ✓"
else
    echo "   host has full security capabilities (strict mode succeeded) ✓"
fi

# 3b. Degraded spec with allow_insecure_degraded = true
SPEC_DEGRADED="$TMP/sec_degraded.toml"
cat <<EOF > "$SPEC_DEGRADED"
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

"$TMP/agentpvm" run -config "$SPEC_DEGRADED" -kernel "$TMP/fake_kernel" > "$TMP/agentpvm_run.log" 2>&1 || fail "agentpvm run failed: $(cat "$TMP/agentpvm_run.log")"
cat "$TMP/agentpvm_run.log" | grep -q "Loaded TaskSpec" || fail "TaskSpec not loaded"

# Verify Audit Ledger recorded the security degraded warning
# The ledger dir name IS the task id (audit.Open(<root>/<task>/ledger.jsonl)),
# so this file is already task-scoped; still assert the Record fields
# explicitly: Action=security:degraded_warning on a line tied to this task.
LEDGER_FILE="$PVM_AUDIT_ROOT/audit-task-degraded/ledger.jsonl"
[ -f "$LEDGER_FILE" ] || fail "audit ledger not found at $LEDGER_FILE"
grep -q "taskspec loaded" "$LEDGER_FILE" || fail "ledger missing taskspec record"
# The degraded_warning record is only emitted when the host actually missed a
# baseline (secRep.Degraded). On a fully capable host (CI runners have
# seccomp+landlock+namespaces) the degraded spec boots with nothing bypassed,
# so the warning is correctly absent — assert it only when 3a failed closed.
if [ "$HOST_DEGRADED" -eq 1 ]; then
    grep -q '"action":"security:degraded_warning"' "$LEDGER_FILE" || fail "ledger missing security:degraded_warning record"
    grep '"action":"security:degraded_warning"' "$LEDGER_FILE" | grep -q '"task":"audit-task-degraded"' || fail "degraded_warning record not attributed to audit-task-degraded"
    echo "   degraded host: security:degraded_warning ledger record verified ✓"
else
    echo "   full-capability host: no degraded_warning expected (nothing bypassed) ✓"
fi

# Verify umlctl start with -insecure-allow-degraded
"$TMP/umlctl" start -name "umlctl-sec-test" -kernel "$TMP/fake_kernel" -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -insecure-allow-degraded > "$TMP/umlctl_run.log" 2>&1 || fail "umlctl start failed: $(cat "$TMP/umlctl_run.log")"
echo "   non-root degraded bypass & audit ledger verified ✓"

# --- 4. Root / Privileged Mode Verification ---
echo "==> 4. verifying Root / Privileged mode"
if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then
    SUDO_CMD=""
    if [ "$(id -u)" -ne 0 ]; then
        SUDO_CMD="sudo"
    fi

    echo "   running privileged jail & namespace checks under $SUDO_CMD"
    $SUDO_CMD "$TMP/agentpvm" run -config "$SPEC_DEGRADED" -kernel "$TMP/fake_kernel" > "$TMP/root_agentpvm.log" 2>&1 || fail "root agentpvm run failed: $(cat "$TMP/root_agentpvm.log")"
    $SUDO_CMD "$TMP/umlctl" start -name "umlctl-root-test" -kernel "$TMP/fake_kernel" -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -insecure-allow-degraded > "$TMP/root_umlctl.log" 2>&1 || fail "root umlctl start failed: $(cat "$TMP/root_umlctl.log")"
    # Compile the selected jail tests as the current user (running go test
    # itself under sudo would leave root-owned entries in GOCACHE/GOMODCACHE),
    # then elevate only the resulting test binary.
    JAIL_TEST_BIN="$TMP/jail.test"
    go test -c -o "$JAIL_TEST_BIN" ./internal/jail > "$TMP/root_jail_build.log" 2>&1 || fail "failed to compile jail tests: $(cat "$TMP/root_jail_build.log")"
    $SUDO_CMD "$JAIL_TEST_BIN" -test.v -test.run "TestConfigureProcessIsolation|TestLandlock|TestSeccomp" > "$TMP/root_jail_test.log" 2>&1 || fail "root jail tests failed: $(cat "$TMP/root_jail_test.log")"
    echo "   root execution & privileged isolation verified ✓"
else
    echo "   (no root/passwordless sudo in current environment; non-root paths verified) ✓"
fi

echo "✅ 30_test_jail_seccomp_degraded.sh PASSED"
