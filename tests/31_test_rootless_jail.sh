#!/usr/bin/env bash
# 31_test_rootless_jail.sh — E2E for the rootless jail (TODO.md "[P1] Jail
# rootless 化"):
#   * NEWUSER+NEWPID monitor: workload runs as pid 1 of its own pidns, gets a
#     private /proc, and cannot signal host pids (asserted from INSIDE the
#     jailed workload via console-log markers)
#   * uidalloc table lifecycle: allocate on start (base 100000), release on
#     stop ($PVM_STATE_ROOT/uidmap.json)
#   * tap fd transport: rootless launches use vec0:transport=fd and do NOT
#     bind /dev/net/tun into the jail
#   * degraded fallback: without usable userns a privileged launch fails
#     closed naming the "user-namespace" layer, and -insecure-allow-degraded
#     selects the legacy mountns-only jail
# CI-safe (no UML kernel required): the workload is a shell-script fake
# kernel, exactly like 30_test_jail_seccomp_degraded.sh.
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
# The rootless jail helper bind-mounts host paths (ubd image) from INSIDE the
# user namespace: every ancestor of a bind source must be traversable by the
# container's mapped uid. mktemp dirs are 0700 — open traversal up.
chmod 0755 "$TMP" "$PVM_IMAGE_ROOT"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi
if [ -n "${UMLCTL_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/umlctl ($UMLCTL_BIN)"
    cp "$UMLCTL_BIN" "$TMP/umlctl"
else
    echo "==> building $TMP/umlctl"
    go build -o "$TMP/umlctl" ./cmd/umlctl
fi

dd if=/dev/zero of="$PVM_IMAGE_ROOT/rootfs.img" bs=1M count=1 status=none

# Host capability detection: the whole suite branches on whether this host
# can actually create user namespaces (CI runners can; nested containers and
# user.max_user_namespaces=0 hosts cannot).
HAS_USERNS=0
if [ -e /proc/self/ns/user ] && unshare -rm true 2>/dev/null; then
    HAS_USERNS=1
fi
echo "==> host userns available: $HAS_USERNS (euid=$(id -u))"

# Fake kernel: emits console markers from INSIDE the jail. The kill/proc
# probes run BEFORE any child is spawned, so in-namespace pid 2 does not
# exist (ESRCH) — and on the host pid 2 is kthreadd (EPERM: CAP_KILL is
# dropped from the bounding set even in the legacy jail). The trailing sleep
# keeps the process alive long enough for uidmap.json polling.
cat <<'EOF' > "$TMP/fake_kernel"
#!/bin/sh
echo "NS_PID=$$"
if [ -d /proc/self ]; then echo PROC_PRESENT; else echo PROC_ABSENT; fi
kill -TERM 2 2>/dev/null || echo KILL_HOST_PID2_DENIED
if [ -e /dev/net/tun ]; then echo TUN_VISIBLE; else echo TUN_ABSENT; fi
sleep 3
echo FAKE_KERNEL_DONE
EOF
chmod +x "$TMP/fake_kernel"

console_log() { echo "$PVM_STATE_ROOT/$1/logs/console.log"; }

# dump_run <task-id>: full failure diagnostics — manager stdout/stderr plus
# the in-jail console log (jail helper errors go there, not to the manager's
# own log).
dump_run() {
    local id=$1
    echo "----- console log ($id) -----"
    cat "$(console_log "$id")" 2>/dev/null || echo "(no console log)"
}

# assert_markers <task-id> <userns-expected 0|1>
assert_markers() {
    local id=$1 want_ns=$2 log
    log="$(console_log "$id")"
    [ -f "$log" ] || fail "console log missing for $id: $log"
    grep -q FAKE_KERNEL_DONE "$log" || fail "fake kernel did not run to completion for $id: $(cat "$log")"
    grep -q KILL_HOST_PID2_DENIED "$log" || fail "$id: jailed workload could signal host pid 2 (or kill never ran): $(cat "$log")"
    if [ "$want_ns" -eq 1 ]; then
        grep -q "NS_PID=1" "$log" || fail "$id: workload is not pid 1 — CLONE_NEWPID missing: $(cat "$log")"
        grep -q PROC_PRESENT "$log" || fail "$id: private /proc not mounted under NEWPID: $(cat "$log")"
    fi
}

SPEC="$TMP/rootless.toml"
cat <<EOF > "$SPEC"
version = 1
caller = "rootless-test"
tenant = "default"

[runtime]
name = "rl31-task"

[workspace]
base_image = "$PVM_IMAGE_ROOT/rootfs.img"
init = "/init.sh"

[security]
allow_insecure_degraded = true
EOF

# --- 1. agentpvm run: jailed fake kernel, markers from inside ---------------
echo "==> 1. agentpvm run with fake kernel"
"$TMP/agentpvm" run -config "$SPEC" -kernel "$TMP/fake_kernel" > "$TMP/run1.log" 2>&1 \
    || { cat "$TMP/run1.log"; dump_run rl31-task; fail "agentpvm run failed"; }
assert_markers rl31-task "$HAS_USERNS"
echo "   fake kernel markers verified (userns=$HAS_USERNS) ✓"

# Everything below needs root (uid allocation + tap attach are privileged)
# AND a kernel that can actually clone the legacy namespace set — e.g.
# Android kernels build without CONFIG_IPC_NS, so even the pre-existing
# NEWNS|NEWIPC|NEWUTS jail fails EINVAL there; skip the privileged legs on
# such hosts (they exercise the same code paths CI covers on normal Linux).
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "   (no root/passwordless sudo; privileged legs skipped) ✓"
    echo "✅ 31_test_rootless_jail.sh PASSED"
    exit 0
fi
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then SUDO_CMD="sudo -E"; fi  # -E: keep PVM_*_ROOT env across privilege elevation
# Elevated cleanup: sections below run umlctl/agentpvm under sudo, leaving
# root-owned 0700 dirs under $TMP that an unprivileged rm -rf cannot enter;
# the default jail root (/tmp/pvm-jails/<task>) lives OUTSIDE $TMP. TAP is
# registered by section 4 once the interface actually exists.
TAP=""
TAP_CREATED=0
cleanup() {
    if [ "$TAP_CREATED" = 1 ]; then
        $SUDO_CMD ip tuntap del "$TAP" mode tap 2>/dev/null || true
    fi
    $SUDO_CMD rm -rf "$TMP" /tmp/pvm-jails/rl31-* 2>/dev/null || true
}
trap cleanup EXIT
if ! $SUDO_CMD unshare -m -i -u true 2>/dev/null; then
    echo "   (host kernel cannot clone the mount/ipc/uts namespace set; privileged legs skipped) ✓"
    echo "✅ 31_test_rootless_jail.sh PASSED"
    exit 0
fi

# --- 2. uidalloc table lifecycle (root) --------------------------------------
echo "==> 2. uidalloc allocation on start, release on stop"
UIDMAP="$PVM_STATE_ROOT/uidmap.json"
$SUDO_CMD "$TMP/umlctl" start -name "rl31-uid" -kernel "$TMP/fake_kernel" \
    -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -insecure-allow-degraded > "$TMP/uid_run.log" 2>&1 &
RUN_PID=$!
found=""
for _ in $(seq 1 40); do
    if [ -f "$UIDMAP" ] && grep -q '"rl31-uid"' "$UIDMAP"; then found=1; break; fi
    sleep 0.25
done
[ -n "$found" ] || fail "uidmap.json never showed an allocation for rl31-uid (log: $(cat "$TMP/uid_run.log"))"
grep -Eq '"rl31-uid":\s*100000\b' "$UIDMAP" || fail "rl31-uid base is not the first slot (100000): $(cat "$UIDMAP")"
echo "   allocated base 100000 while running ✓"
wait "$RUN_PID" || fail "umlctl start rl31-uid failed: $(cat "$TMP/uid_run.log")"
if [ -f "$UIDMAP" ] && grep -q '"rl31-uid"' "$UIDMAP"; then
    fail "uid range for rl31-uid was not released on stop: $(cat "$UIDMAP")"
fi
echo "   released on stop ✓"
assert_markers rl31-uid "$HAS_USERNS"

# --- 3. user-namespace security baseline (root) -------------------------------
echo "==> 3. user-namespace baseline: fail-closed vs full boundary"
SPEC_STRICT="$TMP/strict.toml"
sed 's/allow_insecure_degraded = true/allow_insecure_degraded = false/; s/rl31-task/rl31-strict/' "$SPEC" > "$SPEC_STRICT"
if [ "$HAS_USERNS" -eq 1 ]; then
    # Full boundary: strict spec must boot WITHOUT any degraded bypass.
    $SUDO_CMD "$TMP/agentpvm" run -config "$SPEC_STRICT" -kernel "$TMP/fake_kernel" > "$TMP/strict.log" 2>&1 \
        || { cat "$TMP/strict.log"; dump_run rl31-strict; fail "strict run failed on a userns-capable host"; }
    assert_markers rl31-strict 1
    echo "   strict spec boots under NEWUSER+NEWPID, no bypass ✓"
else
    # No userns: strict must fail closed and name the user-namespace layer.
    if $SUDO_CMD "$TMP/agentpvm" run -config "$SPEC_STRICT" -kernel "$TMP/fake_kernel" > "$TMP/strict.log" 2>&1; then
        fail "strict spec booted on a host WITHOUT user namespaces"
    fi
    grep -q "user-namespace" "$TMP/strict.log" || fail "fail-closed error does not name the user-namespace layer: $(cat "$TMP/strict.log")"
    echo "   fail-closed naming user-namespace layer ✓"
fi

# --- 4. tap fd transport (root + /dev/net/tun + userns) ------------------------
echo "==> 4. tap fd transport (vec0:transport=fd)"
if [ "$HAS_USERNS" -eq 1 ] && [ -e /dev/net/tun ] && command -v ip >/dev/null; then
    TAP="tap_rl31"
    # Own what we clean up: refuse to touch a pre-existing interface (a
    # leaked one from an earlier run must be removed by hand), and only
    # register cleanup once OUR create actually succeeds.
    if $SUDO_CMD ip link show "$TAP" >/dev/null 2>&1; then
        fail "tap $TAP already exists and was NOT created by this test; remove it manually first"
    fi
    $SUDO_CMD ip tuntap add "$TAP" mode tap || fail "ip tuntap add $TAP failed"
    TAP_CREATED=1
    $SUDO_CMD ip link set "$TAP" up || fail "ip link set $TAP up failed"
    $SUDO_CMD "$TMP/umlctl" start -name "rl31-tap" -kernel "$TMP/fake_kernel" \
        -rootfs "$PVM_IMAGE_ROOT/rootfs.img" -tap "$TAP" > "$TMP/tap_run.log" 2>&1 \
        || { cat "$TMP/tap_run.log"; dump_run rl31-tap; fail "rootless tap run failed"; }
    TAP_LOG="$(console_log rl31-tap)"
    grep -q FAKE_KERNEL_DONE "$TAP_LOG" || fail "tap run: fake kernel incomplete: $(cat "$TAP_LOG")"
    # fd transport: /dev/net/tun must NOT be bound into the jail anymore.
    grep -q TUN_ABSENT "$TAP_LOG" || fail "fd transport must not expose /dev/net/tun in the jail: $(cat "$TAP_LOG")"
    grep -q "NS_PID=1" "$TAP_LOG" || fail "tap run: not pidns init: $(cat "$TAP_LOG")"
    $SUDO_CMD ip tuntap del "$TAP" mode tap 2>/dev/null || true
    TAP_CREATED=0
    echo "   tap attached host-side, fd inherited, no /dev/net/tun in jail ✓"
else
    echo "   (skipped: needs userns + /dev/net/tun + iproute2) ✓"
fi

echo "✅ 31_test_rootless_jail.sh PASSED"
