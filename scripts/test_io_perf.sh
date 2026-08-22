#!/bin/bash
set -eo pipefail
# Alpine 架构名与 uname -m 一致（x86_64/aarch64），riscv64 等未来再议
ALPINE_ARCH=$(uname -m)

echo "========== I/O Performance Test (vhost-user-blk: Go + qemu backends) =========="

# Build the agentpvm and umlctl
go build -o agentpvm cmd/agentpvm/main.go
go build -o bin/umlctl ./cmd/umlctl

if [ ! -f "bin/linux" ]; then
    echo "UML kernel (bin/linux) not found. Please run scripts/build_kernel.sh first."
    exit 1
fi

# Block backends under test:
#   1. the pure-Go vhost-user-blk server (internal/vhost/vu + internal/cow) —
#      the DEFAULT, no qemu binaries needed (production path for the agent
#      sandbox, exercised here in addition to tests/04).
#   2. the qemu-storage-daemon backend (PVM_VHOST_BACKEND=qemu) — the optional
#      fallback, skipped cleanly if the daemon is not installed.
#
# The raw ext4 image is converted to qcow2 ONCE via the pure-Go converter
# (agentpvm cow -to-qcow2) so NO qemu-img binary is required to build the base.

if qemu-img --help >/dev/null 2>&1 && qemu-img --help | grep -q "io_uring"; then
    echo "AIO Backend: io_uring supported and will be used by qemu-storage-daemon where applicable."
else
    echo "AIO Backend: io_uring not supported (or qemu-img missing); qemu-storage-daemon will fallback to threads."
fi

IMG_NAME="perf_rootfs.img"
echo "Creating ${IMG_NAME} (300MB)..."
dd if=/dev/zero of=${IMG_NAME} bs=1M count=300 >/dev/null 2>&1
mkfs.ext4 -q -F ${IMG_NAME}

# Check if alpine minirootfs exists, otherwise download
if [ ! -f "alpine.tar.gz" ]; then
    echo "Downloading Alpine Edge minirootfs..."
# shellcheck disable=SC2086  # ALPINE_ARCH is a uname -m arch word (x86_64/aarch64), never globs/splits
    EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
    wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/${EDGE_TAR}" -O alpine.tar.gz
fi

echo "Mounting and extracting..."
mkdir -p mnt
sudo mount -o loop ${IMG_NAME} mnt
trap 'sudo umount mnt 2>/dev/null || true' EXIT
sudo tar -xzf alpine.tar.gz -C mnt/

echo "Creating performance init script..."
cat << 'EOF' | sudo tee mnt/init.sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
# UML mounts root read-only by default; the kernel cmdline `rw=1` is treated as
# an unknown parameter and ignored. Remount read-write so dd can write its log
# and /test_write.dat (same pattern as test_pkg_install.sh).
mount -o remount,rw / 2>/dev/null || true
echo "=============================="
echo " Starting IO Performance Test "
echo "=============================="

# Do a large write to measure sequential write performance
echo "Running sequential write test (100MB)..."
if dd if=/dev/zero of=/test_write.dat bs=1M count=100 oflag=direct > /tmp/dd_write.log 2>&1; then
    grep -E "copied|records" /tmp/dd_write.log
else
    cat /tmp/dd_write.log
    exit 1
fi

echo "Running sequential read test (100MB)..."
if dd if=/test_write.dat of=/dev/null bs=1M count=100 iflag=direct > /tmp/dd_read.log 2>&1; then
    grep -E "copied|records" /tmp/dd_read.log
else
    cat /tmp/dd_read.log
    exit 1
fi

echo "=============================="
echo " PERF_TEST_COMPLETED "
echo "=============================="
poweroff -f
EOF
sudo chmod +x mnt/init.sh

trap - EXIT
sudo umount mnt

# The agent path is qcow2-only (the vhost backends serve the overlay via
# vhost-user-blk; ubd cannot read qcow2). Convert the raw ext4 image to qcow2
# ONCE using the pure-Go converter (no qemu-img dependency). Falls back to
# qemu-img if the agentpvm binary somehow lacks the converter.
# Absolute path: validateRootfs (trusted-root validation) rejects relative paths.
BASE_QCOW2="$(pwd)/perf_rootfs.qcow2"
rm -f "${BASE_QCOW2}"
if ./agentpvm cow -to-qcow2 "${IMG_NAME}" -overlay "${BASE_QCOW2}" 2>/dev/null; then
    echo "Built qcow2 base via pure-Go converter."
elif command -v qemu-img >/dev/null 2>&1; then
    echo "Pure-Go converter unavailable; falling back to qemu-img convert."
    qemu-img convert -p -O qcow2 "${IMG_NAME}" "${BASE_QCOW2}" >/dev/null
else
    echo "FATAL: cannot build qcow2 base (no pure-Go converter and no qemu-img)."
    exit 1
fi

# run_one <name> <backend_label> <env...> <agentpvm_log> <console_log>
# Runs one UML guest under a vhost-user-blk backend, bounded by timeout, and
# returns 0 only if PERF_TEST_COMPLETED appears in the console log. It never
# exits the script itself; the caller decides the overall result.
#
# The default backend is the pure-Go vhost-user-blk server (internal/vhost/vu
# + internal/cow) — NO qemu binaries needed. Setting PVM_VHOST_BACKEND=qemu in
# the environment selects the qemu-storage-daemon subprocess backend instead
# (the optional fallback, useful for A/B testing against the reference).
run_one() {
    local name="$1"
    local label="$2"
    local ap_log="$3"
    local console_log="$4"
    shift 4
    local env=("$@")

    echo "---- running ${label} backend: $name ----"
    sudo rm -f "/var/lib/uml-container/containers/${name}/vhost-blk.sock" "$console_log" "$ap_log"

    # `timeout` bounds the whole run; agentpvm's own exit (poweroff on success
    # or crash on failure) ends it early. -debug yields the full vhost protocol
    # log to the agentpvm log on failure. PVM_VHOST_BACKEND in env selects the
    # backend (default Go server; =qemu selects qemu-storage-daemon).
    # shellcheck disable=SC2024  # ap_log sits in the repo cwd, written by the invoking user, not root
    sudo env "${env[@]}" timeout 120 ./agentpvm run -name "$name" -rootfs "${BASE_QCOW2}" \
        -kernel ./bin/linux -init /init.sh -debug \
        > "$ap_log" 2>&1 || true

    # Ensure no lingering UML process keeps the socket/logs open for the next run.
    sudo pkill -f "agentpvm run -name $name" 2>/dev/null || true

    if sudo grep -q "PERF_TEST_COMPLETED" "$console_log" 2>/dev/null; then
        echo "✅ $name ($label): I/O perf completed."
        return 0
    fi
    echo "❌ $name ($label): I/O perf failed (no PERF_TEST_COMPLETED)."
    echo "----- $name console.log -----"
    sudo cat "$console_log" 2>/dev/null || echo "(no console.log)"
    echo "----- $name $ap_log -----"
    cat "$ap_log" 2>/dev/null || true
    return 1
}

# This suite runs BOTH vhost-user-blk backends:
#   1. the pure-Go server (internal/vhost/vu + internal/cow) — the DEFAULT,
#      no qemu binaries needed. This is the path used in production by the
#      agent sandbox, so it must be exercised here, not only in tests/04.
#   2. the qemu-storage-daemon backend (PVM_VHOST_BACKEND=qemu) — the optional
#      fallback, skipped cleanly if the daemon is not installed.
# A failure of EITHER backend fails the suite.

HAVE_QSD=0
if command -v qemu-storage-daemon &> /dev/null; then
    HAVE_QSD=1
fi

RC=0

# --- 1. pure-Go vhost-user-blk backend (default) ---
AP_LOG_GO=agentpvm.go.log
CONSOLE_LOG_GO=/var/lib/uml-container/containers/perf-test-go/logs/console.log
run_one "perf-test-go" "go-vhost-blk" "$AP_LOG_GO" "$CONSOLE_LOG_GO" || RC=1

# --- 2. qemu-storage-daemon backend (fallback) ---
if [ "$HAVE_QSD" -eq 1 ]; then
    AP_LOG_QEMU=agentpvm.qemu.log
    CONSOLE_LOG_QEMU=/var/lib/uml-container/containers/perf-test-qemu/logs/console.log
    run_one "perf-test-qemu" "qemu-storage-daemon" "$AP_LOG_QEMU" "$CONSOLE_LOG_QEMU" PVM_VHOST_BACKEND=qemu || RC=1
else
    echo "Skipping qemu-storage-daemon backend: qemu-storage-daemon is not installed."
fi

if [ $RC -eq 0 ]; then
    echo "✅ I/O Performance Test completed successfully (all backends)!"
    exit 0
fi
echo "❌ I/O Performance Test failed (one or more backends)."
exit 1
