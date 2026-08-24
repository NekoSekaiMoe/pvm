#!/usr/bin/env bash
# 32_test_uml_seccomp_mode.sh — E2E for the UML seccomp fast-userspace mode
# (TaskSpec security.uml_seccomp -> runtime kernel cmdline param seccomp=,
# mainline x86_64 >= 6.16 / zalexdev aarch64):
#   * REST API       (POST /api/tasks/load-spec accepts on, rejects "maybe" with 4xx)
#   * Kernel cmdline (fake kernel dumps its argv: seccomp=on present when opted in,
#                     absent for the default off)
#   * Audit Ledger   (security:uml_seccomp record with mode+arch on opt-in)
# CI-safe (no UML kernel required): the workload is a shell-script fake
# kernel, exactly like 30_test_jail_seccomp_degraded.sh / 31_test_rootless_jail.sh.
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

PORT=18132
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

echo "==> building binaries"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

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

# --- 1. load-spec accepts uml_seccomp = "on" --------------------------------
echo "==> 1. REST load-spec accepts uml_seccomp=on"
TOML_ON=$(cat <<EOF
version = 1
caller = "alice"
tenant = "default"

[runtime]
name = "seccomp-spec-on"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
uml_seccomp = "on"
EOF
)
RESP=$(req POST "/tasks/load-spec" "{\"content\": $(echo "$TOML_ON" | jq -Rs .)}")
echo "$RESP" | grep -q '"fingerprint"' || fail "load-spec rejected uml_seccomp=on spec: $RESP"
echo "$RESP" | grep -q 'seccomp-spec-on' || fail "load-spec missing task name: $RESP"
echo "   load-spec accepted uml_seccomp=on ✓"

# --- 2. load-spec rejects an invalid value with 4xx -------------------------
echo "==> 2. REST load-spec rejects uml_seccomp=\"maybe\" with 4xx"
TOML_BAD="${TOML_ON/uml_seccomp = \"on\"/uml_seccomp = \"maybe\"}"
HTTP_CODE=$(curl -s -o "$TMP/bad_resp.json" -w "%{http_code}" -X POST "$API/tasks/load-spec" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"content\": $(echo "$TOML_BAD" | jq -Rs .)}")
case "$HTTP_CODE" in
    4*) ;;
    *) fail "expected 4xx for uml_seccomp=maybe, got HTTP $HTTP_CODE: $(cat "$TMP/bad_resp.json")" ;;
esac
grep -qi "uml_seccomp" "$TMP/bad_resp.json" || fail "rejection does not name uml_seccomp: $(cat "$TMP/bad_resp.json")"
echo "   invalid value rejected (HTTP $HTTP_CODE) ✓"

# Fake kernel: dumps its own argv to the console log so the host can assert
# exactly which kernel command-line parameters were passed.
cat <<'EOF' > "$TMP/fake_kernel"
#!/bin/sh
echo "KERNEL_ARGV: $*"
echo FAKE_KERNEL_DONE
exit 0
EOF
chmod +x "$TMP/fake_kernel"

console_log() { echo "$PVM_STATE_ROOT/$1/logs/console.log"; }

write_spec() { # <path> <task-name> <uml_seccomp value or "">
    local path=$1 name=$2 mode=$3
    cat <<EOF > "$path"
version = 1
caller = "seccomp-auditor"
tenant = "default"

[runtime]
name = "$name"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
allow_insecure_degraded = true
EOF
    if [ -n "$mode" ]; then
        echo "uml_seccomp = \"$mode\"" >> "$path"
    fi
}

# --- 3. opt-in: seccomp=on reaches the kernel cmdline + audit record --------
echo "==> 3. task start with uml_seccomp=on: cmdline arg + audit record"
SPEC_ON="$TMP/seccomp_on.toml"
write_spec "$SPEC_ON" "sec32-on" "on"
"$TMP/agentpvm" run -config "$SPEC_ON" -kernel "$TMP/fake_kernel" > "$TMP/run_on.log" 2>&1 \
    || { cat "$TMP/run_on.log"; cat "$(console_log sec32-on)" 2>/dev/null; fail "agentpvm run (on) failed"; }

LOG_ON="$(console_log sec32-on)"
[ -f "$LOG_ON" ] || fail "console log missing for sec32-on"
grep -q FAKE_KERNEL_DONE "$LOG_ON" || fail "fake kernel did not run for sec32-on: $(cat "$LOG_ON")"
grep "^KERNEL_ARGV:" "$LOG_ON" | grep -qw "seccomp=on" \
    || fail "kernel cmdline missing seccomp=on: $(grep '^KERNEL_ARGV:' "$LOG_ON")"
echo "   kernel cmdline carries seccomp=on ✓"

LEDGER_ON="$PVM_AUDIT_ROOT/sec32-on/ledger.jsonl"
[ -f "$LEDGER_ON" ] || fail "audit ledger not found at $LEDGER_ON"
grep -q '"action":"security:uml_seccomp"' "$LEDGER_ON" \
    || fail "ledger missing security:uml_seccomp record: $(cat "$LEDGER_ON")"
REC=$(grep '"action":"security:uml_seccomp"' "$LEDGER_ON")
echo "$REC" | grep -q '"task":"sec32-on"' || fail "uml_seccomp record not attributed to sec32-on: $REC"
echo "$REC" | grep -q '"mode":"on"' || fail "uml_seccomp record missing mode=on: $REC"
echo "$REC" | grep -q '"arch":"' || fail "uml_seccomp record missing arch: $REC"
echo "   security:uml_seccomp ledger record (mode+arch) verified ✓"

# --- 3b. auto: cmdline arg + fallback note in the audit record ---------------
echo "==> 3b. task start with uml_seccomp=auto: cmdline arg + fallback note"
SPEC_AUTO="$TMP/seccomp_auto.toml"
write_spec "$SPEC_AUTO" "sec32-auto" "auto"
"$TMP/agentpvm" run -config "$SPEC_AUTO" -kernel "$TMP/fake_kernel" > "$TMP/run_auto.log" 2>&1 \
    || { cat "$TMP/run_auto.log"; fail "agentpvm run (auto) failed"; }
grep "^KERNEL_ARGV:" "$(console_log sec32-auto)" | grep -qw "seccomp=auto" \
    || fail "kernel cmdline missing seccomp=auto: $(grep '^KERNEL_ARGV:' "$(console_log sec32-auto)")"
REC_AUTO=$(grep '"action":"security:uml_seccomp"' "$PVM_AUDIT_ROOT/sec32-auto/ledger.jsonl") \
    || fail "ledger missing security:uml_seccomp record for auto"
echo "$REC_AUTO" | grep -q '"mode":"auto"' || fail "auto record missing mode=auto: $REC_AUTO"
echo "$REC_AUTO" | grep -qi "fallback" || fail "auto record missing fallback note: $REC_AUTO"
echo "   seccomp=auto + fallback note verified ✓"

# --- 4. default off: NO seccomp= arg, no audit record ------------------------
echo "==> 4. default (no uml_seccomp key): no seccomp= arg, no audit record"
SPEC_OFF="$TMP/seccomp_off.toml"
write_spec "$SPEC_OFF" "sec32-off" ""
"$TMP/agentpvm" run -config "$SPEC_OFF" -kernel "$TMP/fake_kernel" > "$TMP/run_off.log" 2>&1 \
    || { cat "$TMP/run_off.log"; fail "agentpvm run (default off) failed"; }
LOG_OFF="$(console_log sec32-off)"
grep -q FAKE_KERNEL_DONE "$LOG_OFF" || fail "fake kernel did not run for sec32-off: $(cat "$LOG_OFF")"
if grep "^KERNEL_ARGV:" "$LOG_OFF" | grep -q "seccomp="; then
    fail "default spec must NOT pass seccomp= to the kernel: $(grep '^KERNEL_ARGV:' "$LOG_OFF")"
fi
if grep -q "security:uml_seccomp" "$PVM_AUDIT_ROOT/sec32-off/ledger.jsonl" 2>/dev/null; then
    fail "default off must not write a security:uml_seccomp record"
fi
echo "   default off: no seccomp= arg, no audit record ✓"

echo "✅ 32_test_uml_seccomp_mode.sh PASSED"
