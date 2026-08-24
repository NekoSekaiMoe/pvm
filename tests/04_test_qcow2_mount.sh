#!/bin/bash
set -eo pipefail
# Alpine 架构名与 uname -m 一致（x86_64/aarch64），riscv64 等未来再议
ALPINE_ARCH=$(uname -m)

echo "========== Test 04: qcow2 CoW + vhost-user-blk boot (vec0 networking) =========="

# This test proves the FULL vhost path end-to-end:
#   pure-Go CoW overlay (internal/cow) -> pure-Go vhost-user-blk server
#   (internal/vhost/vu) -> UML virtio_uml -> virtio_blk (/dev/vda)
#   -> ext4 root mount -> init runs -> vec0 network up -> gateway reachable.
# Set PVM_VHOST_BACKEND=qemu to A/B against qemu-storage-daemon.
#
# History: the previous version created a 10MB empty ext4 (no /sbin/init) and
# only asserted that the vhost-blk.sock file existed. The guest kernel actually
# PANICKED ("No working init found") and died with SIGABRT — UML's panic path
# calls os_dump_core() -> uml_abort() -> kill(SIGABRT), which Go reports as
# "signal: aborted (core dumped)". The test still printed green checkmarks
# because the stale socket file outlives the dead qemu-storage-daemon. Never
# assert on file existence; assert on console.log boot markers.

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "agentpvm"
else
    echo "==> building agentpvm"
    go build -o "agentpvm" ./cmd/agentpvm
fi
if [ -n "${UMLCTL_BIN:-}" ]; then
    echo "==> using prebuilt bin/umlctl ($UMLCTL_BIN)"
    cp "$UMLCTL_BIN" "bin/umlctl"
else
    echo "==> building bin/umlctl"
    go build -o "bin/umlctl" ./cmd/umlctl
fi

# The vhost backend is pure Go by default (internal/vhost/vu + internal/cow).
# qemu-img is only used to build a qcow2 LAYERED base (qcow2-over-qcow2
# coverage); without it we boot the raw ext4 base directly, which still
# exercises the full qcow2 overlay + vhost-user path.
if command -v qemu-img &> /dev/null; then
    HAVE_QEMU_IMG=1
else
    echo "qemu-img not found; will boot the RAW base (qcow2 overlay on raw)."
    HAVE_QEMU_IMG=0
fi
if [ ! -x ./bin/linux ]; then
    echo "./bin/linux (UML kernel) not found, skipping boot test."
    exit 0
fi

# Base images must live inside a TRUSTED image root: StartTask validates
# workspace.base_image with validateRootfsContained (containerImageRoots),
# which only accepts /var/lib/uml-container/images, $PVM_IMAGE_ROOT, the CoW
# root and the state root. A repo-cwd path — even absolute — is rejected
# ("outside the trusted image roots") before UML ever boots.
IMG_DIR=/var/lib/uml-container/images
# Isolate this run's images in a per-run subdirectory of the trusted root:
# concurrent runs (or leftovers of a crashed one) must not overwrite or
# delete each other's files. cleanup below removes ONLY this directory.
RUN_DIR="$IMG_DIR/cow-test-$(date +%s)-$$-$RANDOM"
IMG_NAME="$RUN_DIR/cow_rootfs.img"
QCOW_NAME="$RUN_DIR/cow_rootfs.qcow2"
NAME="test-cow"
TAP="tap_cow"
BRIDGE="pvm_br_cow"
MNT="mnt_cow"
CONSOLE_LOG=/var/lib/uml-container/containers/$NAME/logs/console.log

# shellcheck disable=SC2329  # invoked by `trap cleanup EXIT` below; 0.11.0 intermittently misses it
cleanup() {
    # agentpvm and qemu-storage-daemon both carry "test-cow" in their argv
    # (task name / socket path), so this reaps both. UML's own argv contains
    # the socket path too, so it is covered as well.
    sudo pkill -f "$NAME" 2>/dev/null || true
    sudo ./bin/umlctl network rm "$BRIDGE" >/dev/null 2>&1 || true
    sudo ip link delete "$TAP" 2>/dev/null || true
    sudo umount "$MNT" 2>/dev/null || true
    rm -rf "$MNT"
    sudo rm -rf "$RUN_DIR"
}
trap cleanup EXIT

# ---- 1) Build a REAL rootfs (alpine + init), not a bare mkfs image ----
echo "Creating alpine rootfs (under trusted image root $IMG_DIR)..."
sudo mkdir -p "$RUN_DIR"
sudo dd if=/dev/zero of="$IMG_NAME" bs=1M count=200 > /dev/null 2>&1
sudo mkfs.ext4 -q -F "$IMG_NAME"

if [ ! -f "alpine.tar.gz" ]; then
# shellcheck disable=SC2086  # ALPINE_ARCH is a uname -m arch word (x86_64/aarch64), never globs/splits
    EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
    wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/${EDGE_TAR}" -O alpine.tar.gz
fi

mkdir -p "$MNT"
sudo mount -o loop "$IMG_NAME" "$MNT"
sudo tar -xzf alpine.tar.gz -C "$MNT"/

# Init: bring up vec0, verify we booted from virtio-blk (vda), verify the
# gateway is reachable, then print the success marker and power off.
cat << 'EOF' | sudo tee "$MNT"/init.sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -o remount,rw / 2>/dev/null || true
# vec0 is the only UML net transport in Linux >= 6.16 (legacy eth0=tuntap
# was removed). PVM passes vec0:transport=tap,ifname=<tap> on the cmdline.
# Guest address follows the P1-A contract: the host IPAM allocator injects
# pvm_ip=<addr> on the kernel cmdline and it arrives here as an init env
# var; the per-task eBPF egress filter exempts exactly that address (plus
# the gateway), so a hardcoded IP different from pvm_ip would have its
# replies dropped by the SSRF floor (10/8) — observed as 100% ping loss.
IP="${pvm_ip:-10.0.0.2}"
GW="${GW:-10.0.0.1}"
ip link set vec0 up || true
ip addr add "$IP/24" dev vec0 || true
ip route add default via "$GW" || true

echo "--- /proc/partitions (root must be vda via vhost-user-blk) ---"
cat /proc/partitions
mount | grep ' / ' || true
echo "--- vec0 (pvm_ip=$IP gw=$GW) ---"
ip addr show vec0 2>&1 || echo "(vec0 missing in guest)"
ping -c 2 -W 3 "$GW" 2>&1 || echo "ping gw FAILED rc=$?"

# Success gate: root on a virtio-blk partition AND vec0 up AND gateway alive.
if grep -Eq 'vda[0-9]?' /proc/partitions \
   && ip link show vec0 >/dev/null 2>&1 \
   && ping -c 1 -W 3 "$GW" >/dev/null 2>&1; then
    echo "VHOST_COW_SUCCESS"
fi

echo "INIT_DONE rc=$?"
busybox poweroff -f
EOF
sudo chmod +x "$MNT"/init.sh
sudo umount "$MNT"

# ---- 2) Base image: qcow2 (layered) when qemu-img is around, raw otherwise.
# ----    Either way agentpvm builds a per-task pure-Go qcow2 CoW overlay. ----
if [ "$HAVE_QEMU_IMG" = "1" ]; then
    echo "Converting raw ext4 base to qcow2..."
    sudo qemu-img convert -p -O qcow2 "$IMG_NAME" "$QCOW_NAME" > /dev/null
    BASE="$QCOW_NAME"   # absolute AND inside the trusted image root (see IMG_DIR above)
else
    BASE="$IMG_NAME"
fi

# ---- 3) Host networking (same proven pattern as scripts/test_pkg_install.sh,
# ----    distinct names so the two suites never collide) ----
echo "===== HOST NETWORK SETUP ====="
sudo ip tuntap add "$TAP" mode tap 2>&1 || echo "[net] $TAP already exists"
sudo ip link set "$TAP" up 2>&1 || echo "[net] WARN: $TAP up failed"
sudo ./bin/umlctl network create "$BRIDGE" 2>&1 || echo "[net] WARN: $BRIDGE create returned non-zero (may already exist)"
sudo ip link set "$TAP" master "$BRIDGE" 2>&1 || echo "[net] ERROR: could not master $TAP onto $BRIDGE"

if ! sudo ip link show "$BRIDGE" >/dev/null 2>&1; then
    echo "[net] FATAL: $BRIDGE does not exist after setup; aborting before guest boot."
    exit 1
fi
if ! sudo bridge link 2>/dev/null | grep -q "$TAP"; then
    echo "[net] FATAL: $TAP is not attached to $BRIDGE; guest would have no L2 path. Aborting."
    exit 1
fi

# ---- 4) Launch on the vhost path. The guest powers itself off after init;
# ----    timeout is only a hang guard, the real gate is the console marker. ----
sudo rm -f "$CONSOLE_LOG"
echo "Launching agentpvm (base -> per-task pure-Go CoW overlay via internal/vhost/vu, vec0 net)..."
timeout 180 sudo ./agentpvm run -name "$NAME" \
    -rootfs "$BASE" -kernel ./bin/linux -init /init.sh \
    -net-tap "$TAP" || true

# ---- 5) Assertions: boot markers in console.log, not file existence ----
# NOTE: there is deliberately NO vhost-blk.sock existence check here. The
# socket file means nothing either way: a stale one outlives a crashed boot
# (false pass), and StartTask now unlinks it on clean teardown (false fail).
# The only truthful signal is what the guest printed.
echo "============================================================"
PASS=1

if sudo grep -q "VHOST_COW_SUCCESS" "$CONSOLE_LOG" 2>/dev/null; then
    echo "✅ Guest booted from vhost-user-blk qcow2 CoW (root=vda) with working vec0."
else
    echo "❌ VHOST_COW_SUCCESS NOT observed in console.log"
    PASS=0
fi

if sudo grep -q "Kernel panic" "$CONSOLE_LOG" 2>/dev/null; then
    echo "❌ Guest kernel PANICKED (this is what Go reports as 'signal: aborted (core dumped)':"
    echo "   UML panic -> os_dump_core() -> uml_abort() -> SIGABRT)."
    PASS=0
fi

if [ "$PASS" -eq 1 ]; then
    echo "✅ qcow2 CoW vhost boot verified."
    exit 0
fi

# ---- Failure diagnostics: everything needed to locate the broken layer ----
echo ""
echo "--- DIAG: UML kernel command line (which block/net transports were passed) ---"
sudo grep -E "Kernel command line:" "$CONSOLE_LOG" 2>/dev/null | tail -1 || echo "   (no 'Kernel command line' line — UML did not finish early boot)"
echo ""
echo "--- DIAG: virtio_uml / virtio_blk init ---"
sudo grep -Ei "virtio-uml|virtio_uml|virtio_blk|\bvda\b|vhost" "$CONSOLE_LOG" 2>/dev/null | head -20 || echo "   (no virtio lines — probe may never have run)"
echo ""
echo "--- DIAG: panic / VFS / failure markers ---"
sudo grep -E "Kernel panic|VFS:|end Kernel panic|No working init|FAILED|not syncing" "$CONSOLE_LOG" 2>/dev/null | head -30 || echo "   (none)"
echo ""
echo "--- DIAG: last 30 lines of console.log ---"
sudo tail -30 "$CONSOLE_LOG" 2>/dev/null || echo "   (no console.log at all — agentpvm likely crashed before boot)"
exit 1
