#!/usr/bin/env bash
# 35_test_tc_ebpf_dataplane.sh — E2E for P1-A (network data plane
# consolidation): StartTask now wires the per-task eBPF egress enforcement
# itself — guest IP from the bridge-subnet IPAM (handed to the guest as
# pvm_ip=), single cilium/ebpf loader, whitelist map pinned per task at
# /sys/fs/bpf/pvm/<taskID>/whitelist_map.
#
#   Leg 1 (CI-safe, no root): a network-enabled task on a fake kernel
#     PROCEEDS without root — the TC filter attach failure degrades with an
#     audit security:degraded_warning (the L7 proxy stays the enforcement
#     point) — and pvm_ip=<allocated> is present in the kernel argv.
#   Leg 2 (CI-safe): `agentpvm network whitelist add <task_id> <ip>` writes
#     through the per-task pinned-map path and fails gracefully (typed
#     pinned-map error) when no map is pinned; path-unsafe task ids and bad
#     IPs are rejected before touching bpffs.
#   Leg 3 (CI-safe): spec surface — network.dataplane rejects unknown
#     values at load; dataplane="tc" without a bridge boots a fake kernel
#     with the FIXED contract pvm_ip=169.254.68.6 / egress_proxy=
#     169.254.68.5:<port> even when the attach itself degrades (no root),
#     with an audit security:degraded_warning naming the tc dataplane.
#   Leg 4 (CI-safe, non-root only): tc + bridge configured -> attach failure
#     falls back to the classic bridge plane (IPAM pvm_ip + loopback
#     egress_proxy + BOTH degraded warnings recorded).
#   Leg 5 (CI-safe): GET /api/network/dataplane{,/:task} — auth, posture
#     keys, 400/404 shapes.
#   Leg 6 (root + bpffs + iproute2 + /dev/net/tun; SKIP otherwise): real
#     clsact attach — the map is pinned while the task runs, the whitelist
#     CLI updates the live map, and teardown removes the pins.
#   Leg 7 (same root guards): real tc dataplane attach — pvm-gw carries
#     169.254.68.5/32, egress_sessions + the SHARED whitelist_map pin under
#     /sys/fs/bpf/pvm/<taskID>/, the fixed argv contract holds on a real
#     attach, the whitelist CLI drives the live tc-plane map, and teardown
#     removes the pins.
#
# Fake-kernel argv-dump technique from 31_test_rootless_jail.sh: the
# "kernel" is a shell script; everything after argv[0] is the UML command
# line buildTaskArgs/StartTask produced.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_IMAGE_ROOT="$TMP/images"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_IMAGE_ROOT"
# Rootless jail binds traverse these paths from inside a user namespace.
chmod 0755 "$TMP" "$PVM_IMAGE_ROOT"

fail() { echo "❌ $1"; exit 1; }

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

dd if=/dev/zero of="$PVM_IMAGE_ROOT/rootfs.img" bs=1M count=1 status=none

# Fake kernel: dumps its argv (the UML command line) into the console log.
cat <<'EOF' > "$TMP/fake_kernel"
#!/bin/sh
echo "KARGV:$*"
sleep 3
echo FAKE_KERNEL_DONE
EOF
chmod +x "$TMP/fake_kernel"

console_log() { echo "$PVM_STATE_ROOT/$1/logs/console.log"; }
ledger_file() { echo "$PVM_AUDIT_ROOT/$1/ledger.jsonl"; }

make_spec() { # <path> <task-name> <tap>
    cat <<EOF > "$1"
version = 1
caller = "tc35-test"
tenant = "default"

[runtime]
name = "$2"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[network]
enabled = true
bridge = "br_tc35"
gateway_ip = "10.0.0.1/24"
tap = "$3"

[security]
allow_insecure_degraded = true
EOF
}

# --- 1. degraded leg (CI-safe): no root, task proceeds ----------------------
echo "==> 1. degraded attach: task proceeds, pvm_ip in argv, audit warning"
make_spec "$TMP/degraded.toml" tc35-task tap_tc35
"$TMP/agentpvm" run -config "$TMP/degraded.toml" -kernel "$TMP/fake_kernel" > "$TMP/run1.log" 2>&1 \
    || { cat "$TMP/run1.log"; cat "$(console_log tc35-task)" 2>/dev/null; fail "degraded agentpvm run failed"; }

LOG1="$(console_log tc35-task)"
[ -f "$LOG1" ] || fail "console log missing for tc35-task"
grep -q FAKE_KERNEL_DONE "$LOG1" || fail "fake kernel did not complete: $(cat "$LOG1")"
# The IPAM hands out the first free address from offset .100 and StartTask
# injects it exactly like egress_proxy=.
grep -q "pvm_ip=10.0.0.100" "$LOG1" || fail "pvm_ip=10.0.0.100 missing from kernel argv: $(grep KARGV "$LOG1")"
grep -q "vec0:transport=" "$LOG1" || fail "vec0 transport arg missing: $(grep KARGV "$LOG1")"
echo "   pvm_ip=10.0.0.100 + vec0 transport in fake-kernel argv ✓"

LEDGER1="$(ledger_file tc35-task)"
[ -f "$LEDGER1" ] || fail "audit ledger missing: $LEDGER1"
if [ "$(id -u)" -ne 0 ]; then
    # Without root the TC attach MUST fail and MUST be audit-recorded — a
    # silent downgrade would be a security hole.
    grep '"action":"security:degraded_warning"' "$LEDGER1" | grep -q "tc egress filter attach failed" \
        || fail "no degraded_warning for the tc filter attach: $(cat "$LEDGER1")"
    echo "   security:degraded_warning for tc filter attach in ledger ✓"
else
    # Running as real root the attach may have succeeded; then teardown must
    # have removed the pin instead of a degraded row being written.
    if grep '"action":"security:degraded_warning"' "$LEDGER1" | grep -q "tc egress filter attach failed"; then
        echo "   degraded row present (attach failed even as root: restricted bpffs/kernel) ✓"
    else
        [ ! -e /sys/fs/bpf/pvm/tc35-task ] || fail "pin dir leaked for tc35-task after task exit"
        echo "   real attach as root; pins cleaned on exit ✓"
    fi
fi

# --- 2. whitelist CLI per-task path (CI-safe) --------------------------------
echo "==> 2. whitelist CLI: per-task pinned-map path + input validation"
WL_OUT=$("$TMP/agentpvm" network whitelist add tc35-task 203.0.113.10 2>&1) || true
echo "$WL_OUT"
case "$WL_OUT" in
    *"Whitelist Error:"*"pinned map"*)
        echo "   graceful pinned-map failure (no live task) ✓" ;;
    *"Whitelist updated: task tc35-task"*)
        # A capable root host may STILL have the map pinned if a concurrent
        # leg-3 task reused the id — not the case here, so treat as success.
        echo "   whitelist update succeeded (pinned map present) ✓" ;;
    *)
        fail "whitelist CLI output unexpected: $WL_OUT" ;;
esac
WL_BAD=$("$TMP/agentpvm" network whitelist add '../escape' 203.0.113.10 2>&1) || true
echo "$WL_BAD"
case "$WL_BAD" in
    *"invalid task id"*) echo "   path-unsafe task id rejected ✓" ;;
    *) fail "task id traversal not rejected: $WL_BAD" ;;
esac
WL_BADIP=$("$TMP/agentpvm" network whitelist add tc35-task not-an-ip 2>&1) || true
case "$WL_BADIP" in
    *"invalid whitelist IP"*) echo "   bad IP rejected before bpffs ✓" ;;
    *) fail "bad IP not rejected: $WL_BADIP" ;;
esac

# --- 3. spec dataplane surface (CI-safe) -------------------------------------
echo "==> 3. spec dataplane field: validation + fixed tc contract (degraded)"

# 3a. Unknown dataplane values are config errors and must name the field.
# make_spec_tc emits a tc spec without bridge/gateway_ip (the fixed
# link-local contract replaces them).
make_spec_tc() { # <path> <task-name> <tap> [extra-network-lines...]
    cat <<EOF > "$1"
version = 1
caller = "tc35-test"
tenant = "default"

[runtime]
name = "$2"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[network]
enabled = true
tap = "$3"
dataplane = "tc"
${4:-}

[security]
allow_insecure_degraded = true
EOF
}
make_spec_tc "$TMP/bogus_dp.toml" tc35b-task tap_tc35b
sed -i 's/^dataplane = "tc"$/dataplane = "ebpf-only"/' "$TMP/bogus_dp.toml"
if "$TMP/agentpvm" run -config "$TMP/bogus_dp.toml" -kernel "$TMP/fake_kernel" > "$TMP/run_bogus.log" 2>&1; then
    fail "dataplane=ebpf-only accepted by agentpvm run"
fi
grep -q 'dataplane' "$TMP/run_bogus.log" || fail "rejection does not name the dataplane field: $(cat "$TMP/run_bogus.log")"
echo "   dataplane=ebpf-only rejected with the field name in the error ✓"

# 3b. tc mode WITHOUT a bridge: the fixed link-local contract is injected
# even when the dataplane attach itself degrades (non-root), and the classic
# IPAM address must NOT leak into argv.
make_spec_tc "$TMP/tc.toml" tc35t-task tap_tc35t
"$TMP/agentpvm" run -config "$TMP/tc.toml" -kernel "$TMP/fake_kernel" > "$TMP/run_tc.log" 2>&1 \
    || { cat "$TMP/run_tc.log"; fail "tc-dataplane agentpvm run failed"; }
LOGT="$(console_log tc35t-task)"
[ -f "$LOGT" ] || fail "console log missing for tc35t-task"
grep -q FAKE_KERNEL_DONE "$LOGT" || fail "tc fake kernel did not complete: $(cat "$LOGT")"
grep -q "pvm_ip=169.254.68.6" "$LOGT" || fail "fixed pvm_ip=169.254.68.6 missing: $(grep KARGV "$LOGT")"
grep -qE "egress_proxy=169\.254\.68\.5:[0-9]+" "$LOGT" \
    || fail "fixed egress_proxy=169.254.68.5:<port> missing: $(grep KARGV "$LOGT")"
if grep -q "pvm_ip=10.0.0" "$LOGT"; then
    fail "bridge-mode IPAM address leaked into the tc dataplane argv"
fi
echo "   fixed pvm_ip=169.254.68.6 + egress_proxy=169.254.68.5:<port> in argv ✓"
LEDGERT="$(ledger_file tc35t-task)"
[ -f "$LEDGERT" ] || fail "audit ledger missing: $LEDGERT"
if [ "$(id -u)" -ne 0 ]; then
    # Non-root: pvm-gw setup and/or the clsact attach MUST fail and MUST be
    # audit-recorded — silent downgrade would be a security hole.
    grep '"action":"security:degraded_warning"' "$LEDGERT" | grep -q "tc dataplane" \
        || fail "no degraded_warning naming the tc dataplane: $(cat "$LEDGERT")"
    echo "   security:degraded_warning for tc dataplane in ledger ✓"
else
    # Root: attach may have succeeded for real; then the pins must be gone.
    if grep '"action":"security:degraded_warning"' "$LEDGERT" | grep -q "tc dataplane"; then
        echo "   degraded row present (attach failed even as root) ✓"
    else
        [ ! -e /sys/fs/bpf/pvm/tc35t-task ] || fail "pin dir leaked for tc35t-task after task exit"
        echo "   real attach as root; pins cleaned on exit ✓"
    fi
fi

# --- 4. tc + bridge fallback composition (CI-safe, non-root only) -----------
echo "==> 4. tc attach failure + bridge configured -> classic plane fallback"
if [ "$(id -u)" -eq 0 ]; then
    echo "   (root: attach would succeed, fallback untestable here; skipped) ✓"
else
    make_spec_tc "$TMP/tc_fallback.toml" tc35f-task tap_tc35f 'bridge = "br_tc35f"
gateway_ip = "10.0.0.1/24"'
    "$TMP/agentpvm" run -config "$TMP/tc_fallback.toml" -kernel "$TMP/fake_kernel" > "$TMP/run_f.log" 2>&1 \
        || { cat "$TMP/run_f.log"; fail "tc-fallback agentpvm run failed"; }
    LOGF="$(console_log tc35f-task)"
    grep -q FAKE_KERNEL_DONE "$LOGF" || fail "fallback fake kernel incomplete: $(cat "$LOGF" 2>/dev/null)"
    # The classic plane took over: IPAM address + the REAL (loopback)
    # listener address, not the fixed tc injection.
    grep -q "pvm_ip=10.0.0.100" "$LOGF" || fail "fallback did not restore the IPAM pvm_ip: $(grep KARGV "$LOGF")"
    grep -qE "egress_proxy=127\.0\.0\.1:[0-9]+" "$LOGF" \
        || fail "fallback did not restore the raw egress_proxy: $(grep KARGV "$LOGF")"
    LEDGERF="$(ledger_file tc35f-task)"
    # BOTH downgrades must be evidenced: the tc dataplane attach AND the
    # classic filter attach.
    grep '"action":"security:degraded_warning"' "$LEDGERF" | grep -q "tc dataplane" \
        || fail "fallback lost the tc-dataplane degraded row: $(cat "$LEDGERF")"
    grep '"action":"security:degraded_warning"' "$LEDGERF" | grep -q "tc egress filter attach failed" \
        || fail "fallback lost the classic-filter degraded row: $(cat "$LEDGERF")"
    echo "   fallback: IPAM pvm_ip + raw egress_proxy + both degraded rows ✓"
fi

# --- 5. REST dataplane endpoint (CI-safe) ------------------------------------
echo "==> 5. GET /api/network/dataplane{,/:task} posture"
PORT=18086
API="http://127.0.0.1:$PORT/api"
export API_SECRET="secret"
AUTH="Authorization: Bearer secret"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
code=$(curl -s -o /dev/null -w '%{http_code}' "$API/network/dataplane")
{ [ "$code" = 400 ] || [ "$code" = 401 ]; } || { kill "$SRV" 2>/dev/null; fail "unauthenticated /network/dataplane: want 400/401 (echo KeyAuth), got $code"; }
body=$(curl -sf -H "$AUTH" "$API/network/dataplane") || { kill "$SRV" 2>/dev/null; fail "GET /network/dataplane failed: $(cat "$TMP/server.log")"; }
echo "$body" | grep -q '"mode_default":"bridge"' || { kill "$SRV" 2>/dev/null; fail "mode_default missing: $body"; }
echo "$body" | grep -q '"gw_device"' || { kill "$SRV" 2>/dev/null; fail "gw_device missing: $body"; }
echo "$body" | grep -q '"tasks"' || { kill "$SRV" 2>/dev/null; fail "tasks missing: $body"; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "$API/network/dataplane/nosuchtask")
[ "$code" = 404 ] || { kill "$SRV" 2>/dev/null; fail "unknown task: want 404, got $code"; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "$API/network/dataplane/bad..id")
[ "$code" = 400 ] || { kill "$SRV" 2>/dev/null; fail "bad task id: want 400, got $code"; }
kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
echo "   401 without auth; 200 with mode_default/gw_device/tasks; 404/400 shapes ✓"

# --- 6. real attach leg (root + bpffs + iproute2 + tun) ----------------------
echo "==> 6. real clsact attach (root-guarded)"
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "   (no root/passwordless sudo; privileged leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then SUDO_CMD="sudo -E"; fi  # -E: keep PVM_*_ROOT env
# Same guard as 31_test_rootless_jail.sh: the jail needs the legacy
# mount/ipc/uts namespace set even in degraded mode; kernels built without
# e.g. CONFIG_IPC_NS fail the whole launch with EINVAL, which is an
# environment gap, not a dataplane regression.
if ! $SUDO_CMD unshare -m -i -u true 2>/dev/null; then
    echo "   (host kernel cannot clone the mount/ipc/uts namespace set; privileged leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
if ! command -v ip >/dev/null || ! command -v tc >/dev/null || [ ! -e /dev/net/tun ]; then
    echo "   (iproute2/tc or /dev/net/tun missing; privileged leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
# bpffs must be mounted and writable for the pin step.
if ! $SUDO_CMD mountpoint -q /sys/fs/bpf 2>/dev/null; then
    $SUDO_CMD mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi
if ! $SUDO_CMD test -w /sys/fs/bpf 2>/dev/null; then
    echo "   (bpffs not writable at /sys/fs/bpf; privileged leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
# Preflight clsact support before asserting anything (container kernels may
# lack it); clean up the probe qdisc immediately.
if ! $SUDO_CMD tc qdisc add dev lo clsact 2>/dev/null; then
    echo "   (kernel lacks clsact qdisc support; privileged leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
$SUDO_CMD tc qdisc del dev lo clsact 2>/dev/null || true

TAP="tap_tc35r"
TASK="tc35r-task"
TAP_CREATED=0
cleanup() {
    if [ "$TAP_CREATED" = 1 ]; then
        $SUDO_CMD ip tuntap del "$TAP" mode tap 2>/dev/null || true
    fi
    $SUDO_CMD rm -rf /sys/fs/bpf/pvm/"$TASK" "$TMP" /tmp/pvm-jails/tc35r-* 2>/dev/null || true
}
trap cleanup EXIT
if $SUDO_CMD ip link show "$TAP" >/dev/null 2>&1; then
    fail "tap $TAP already exists and was NOT created by this test; remove it manually first"
fi
$SUDO_CMD ip tuntap add "$TAP" mode tap || fail "ip tuntap add $TAP failed"
TAP_CREATED=1
$SUDO_CMD ip link set "$TAP" up || fail "ip link set $TAP up failed"

make_spec "$TMP/root.toml" "$TASK" "$TAP"
PIN="/sys/fs/bpf/pvm/$TASK/whitelist_map"
$SUDO_CMD "$TMP/agentpvm" run -config "$TMP/root.toml" -kernel "$TMP/fake_kernel" > "$TMP/run3.log" 2>&1 &
RUN_PID=$!
found=""
for _ in $(seq 1 80); do
    if $SUDO_CMD test -e "$PIN"; then found=1; break; fi
    if ! kill -0 "$RUN_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
if [ -z "$found" ]; then
    cat "$TMP/run3.log"
    fail "whitelist map never pinned at $PIN (run still up: $(kill -0 "$RUN_PID" 2>/dev/null && echo yes || echo no))"
fi
echo "   map pinned at $PIN while task runs ✓"

# The whitelist CLI (separate process) reaches the SAME live map through the
# pinned path — the registry fallback only works in-process.
WL3=$($SUDO_CMD "$TMP/agentpvm" network whitelist add "$TASK" 203.0.113.10 2>&1) || true
echo "$WL3"
case "$WL3" in
    *"Whitelist updated: task $TASK"*) echo "   live per-task whitelist update ✓" ;;
    *) fail "whitelist add against live task failed: $WL3" ;;
esac

wait "$RUN_PID" || { cat "$TMP/run3.log"; fail "root agentpvm run failed"; }
LOG3="$(console_log "$TASK")"
grep -q FAKE_KERNEL_DONE "$LOG3" || fail "root fake kernel incomplete: $(cat "$LOG3" 2>/dev/null)"
grep -q "pvm_ip=10.0.0.100" "$LOG3" || fail "pvm_ip missing in root leg: $(grep KARGV "$LOG3" 2>/dev/null)"
# Teardown: pins removed with the task.
if $SUDO_CMD test -e "/sys/fs/bpf/pvm/$TASK"; then
    fail "pin dir /sys/fs/bpf/pvm/$TASK leaked after task exit"
fi
echo "   pins removed on task exit ✓"
# And the ledger must NOT carry a tc-filter degraded row for this task.
LEDGER3="$(ledger_file "$TASK")"
if [ -f "$LEDGER3" ] && grep '"action":"security:degraded_warning"' "$LEDGER3" | grep -q "tc egress filter attach failed"; then
    fail "root leg attached for real but still recorded a tc-filter degraded warning"
fi
echo "   no degraded row for the successful attach ✓"

$SUDO_CMD ip tuntap del "$TAP" mode tap 2>/dev/null || true
TAP_CREATED=0

# --- 7. real tc dataplane attach (same root guards as leg 6) ----------------
echo "==> 7. real tc dataplane attach: pvm-gw + session map + fixed argv"
TAP2="tap_tc35d"
TASK2="tc35d-task"
TAP2_CREATED=0
GW_OWNED=0
cleanup7() {
    if [ "$TAP2_CREATED" = 1 ]; then
        $SUDO_CMD ip tuntap del "$TAP2" mode tap 2>/dev/null || true
    fi
    # pvm-gw is a SHARED device that survives tasks by design; remove only
    # the instance this suite created so reruns stay hermetic.
    if [ "$GW_OWNED" = 1 ]; then
        $SUDO_CMD ip link del pvm-gw 2>/dev/null || true
    fi
    $SUDO_CMD rm -rf /sys/fs/bpf/pvm/"$TASK2" /tmp/pvm-jails/tc35d-* 2>/dev/null || true
    cleanup
}
trap cleanup7 EXIT

# Preflight dummy-device support (pvm-gw IS a dummy device) and a default
# route (the dataplane SNATs out the host NIC); container kernels without
# either cannot exercise the attach.
if ! $SUDO_CMD ip link add pvmgw_probe type dummy 2>/dev/null; then
    echo "   (kernel lacks dummy device support; tc dataplane leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
$SUDO_CMD ip link del pvmgw_probe 2>/dev/null || true
if [ -z "$($SUDO_CMD ip route show default 2>/dev/null)" ]; then
    echo "   (no default route on this host; tc dataplane leg skipped) ✓"
    echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
    exit 0
fi
if ! $SUDO_CMD ip link show pvm-gw >/dev/null 2>&1; then
    GW_OWNED=1 # not pre-existing: the run below creates it, we remove it
fi
if $SUDO_CMD ip link show "$TAP2" >/dev/null 2>&1; then
    fail "tap $TAP2 already exists and was NOT created by this test; remove it manually first"
fi
$SUDO_CMD ip tuntap add "$TAP2" mode tap || fail "ip tuntap add $TAP2 failed"
TAP2_CREATED=1
$SUDO_CMD ip link set "$TAP2" up || fail "ip link set $TAP2 up failed"

make_spec_tc "$TMP/tc_root.toml" "$TASK2" "$TAP2"
PIN2="/sys/fs/bpf/pvm/$TASK2"
$SUDO_CMD "$TMP/agentpvm" run -config "$TMP/tc_root.toml" -kernel "$TMP/fake_kernel" > "$TMP/run7.log" 2>&1 &
RUN_PID=$!
found=""
for _ in $(seq 1 80); do
    if $SUDO_CMD test -e "$PIN2/egress_sessions"; then found=1; break; fi
    if ! kill -0 "$RUN_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
if [ -z "$found" ]; then
    # A restricted kernel may still refuse the attach; that is legal ONLY
    # with an audit row (evidence-based skip, mirroring leg 1's contract).
    if grep '"action":"security:degraded_warning"' "$(ledger_file "$TASK2")" 2>/dev/null | grep -q "tc dataplane"; then
        echo "   (tc dataplane attach degraded despite preflight; audit row present) ✓"
        wait "$RUN_PID" 2>/dev/null || true
        echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
        exit 0
    fi
    cat "$TMP/run7.log"
    fail "egress_sessions never pinned at $PIN2 (run still up: $(kill -0 "$RUN_PID" 2>/dev/null && echo yes || echo no))"
fi
echo "   egress_sessions pinned at $PIN2 while task runs ✓"
$SUDO_CMD ip -o -4 addr show dev pvm-gw | grep -q "169\.254\.68\.5/32" \
    || fail "pvm-gw does not carry 169.254.68.5/32: $($SUDO_CMD ip addr show pvm-gw)"
echo "   pvm-gw carries 169.254.68.5/32 ✓"
# The tc plane pins the SHARED whitelist map at the SAME standard path the
# P1-A filter uses, so the whitelist CLI and dnslearn work unchanged.
$SUDO_CMD test -e "$PIN2/whitelist_map" || fail "shared whitelist_map not pinned at $PIN2"
echo "   shared whitelist_map pinned at the standard per-task path ✓"
WL7=$($SUDO_CMD "$TMP/agentpvm" network whitelist add "$TASK2" 203.0.113.11 2>&1) || true
echo "$WL7"
case "$WL7" in
    *"Whitelist updated: task $TASK2"*) echo "   live tc-plane whitelist update ✓" ;;
    *) fail "whitelist add against live tc task failed: $WL7" ;;
esac

wait "$RUN_PID" || { cat "$TMP/run7.log"; fail "root tc-dataplane run failed"; }
LOG7="$(console_log "$TASK2")"
grep -q FAKE_KERNEL_DONE "$LOG7" || fail "tc root fake kernel incomplete: $(cat "$LOG7" 2>/dev/null)"
grep -q "pvm_ip=169.254.68.6" "$LOG7" || fail "fixed pvm_ip missing on real attach: $(grep KARGV "$LOG7" 2>/dev/null)"
grep -qE "egress_proxy=169\.254\.68\.5:[0-9]+" "$LOG7" \
    || fail "fixed egress_proxy missing on real attach: $(grep KARGV "$LOG7" 2>/dev/null)"
echo "   fixed pvm_ip/egress_proxy argv contract on a REAL attach ✓"
if $SUDO_CMD test -e "$PIN2"; then
    fail "pin dir $PIN2 leaked after task exit"
fi
echo "   pins removed on task exit ✓"
LEDGER7="$(ledger_file "$TASK2")"
if [ -f "$LEDGER7" ] && grep '"action":"security:degraded_warning"' "$LEDGER7" | grep -q "tc dataplane"; then
    fail "root leg attached for real but still recorded a tc-dataplane degraded warning"
fi
echo "   no tc-dataplane degraded row for the successful attach ✓"

$SUDO_CMD ip tuntap del "$TAP2" mode tap 2>/dev/null || true
TAP2_CREATED=0
if [ "$GW_OWNED" = 1 ]; then
    $SUDO_CMD ip link del pvm-gw 2>/dev/null || true
    GW_OWNED=0
fi

echo "✅ 35_test_tc_ebpf_dataplane.sh PASSED"
