#!/bin/bash
set -eo pipefail

echo "========== I/O Performance Test (virtio-blk) =========="

# Build the agentpvm and umlctl
go build -o agentpvm cmd/agentpvm/main.go
go build -o bin/umlctl ./cmd/umlctl

if [ ! -f "bin/linux" ]; then
    echo "UML kernel (bin/linux) not found. Please run scripts/build_kernel.sh first."
    exit 1
fi

# Two backends are exercised, in this order:
#   1. qemu-storage-daemon (-native-vhost=false): the mature reference
#      vhost-user-blk implementation. Run first so a native-backend hang does
#      not gate the baseline measurement; if this stage fails, the test bails
#      immediately because even the reference path is broken.
#   2. native Go backend (-native-vhost=true): the experimental backend whose
#      virtqueue IO path uses synchronous pread/pwrite (see internal/vhost/
#      virtqueue.go). Run last so a regression here is reported without
#      blocking the qemu stage's result.
if qemu-img --help | grep -q "io_uring"; then
    echo "AIO Backend: io_uring supported and will be used by qemu-storage-daemon where applicable."
else
    echo "AIO Backend: io_uring not supported, qemu-storage-daemon will fallback to threads."
fi

IMG_NAME="perf_rootfs.img"
echo "Creating ${IMG_NAME} (300MB)..."
dd if=/dev/zero of=${IMG_NAME} bs=1M count=300 >/dev/null 2>&1
mkfs.ext4 -q ${IMG_NAME}

# Check if alpine minirootfs exists, otherwise download
if [ ! -f "alpine.tar.gz" ]; then
    echo "Downloading Alpine Edge minirootfs..."
    EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
    wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/${EDGE_TAR}" -O alpine.tar.gz
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

# run_one <name> <native_flag> <agentpvm_log> <console_log>
# Runs one UML guest under the chosen backend, bounded by timeout, and returns
# 0 only if PERF_TEST_COMPLETED appears in the console log. It never exits the
# script itself; the caller decides the overall result so both backends get a
# chance to run.
run_one() {
    local name="$1"
    local native_flag="$2"
    local ap_log="$3"
    local console_log="$4"

    echo "---- running backend: $name ($native_flag) ----"
    sudo rm -f "/var/lib/uml-container/containers/${name}/vhost-blk.sock" "$console_log" "$ap_log"

    # `timeout` bounds the whole run; agentpvm's own exit (poweroff on success
    # or crash on failure) ends it early. -debug yields the full vhost protocol
    # log to the agentpvm log on failure.
    sudo timeout 120 ./agentpvm run -name "$name" -rootfs "${IMG_NAME}" \
        -kernel ./bin/linux -init /init.sh -vhost=true $native_flag -debug \
        > "$ap_log" 2>&1 || true

    # Ensure no lingering UML process keeps the socket/logs open for the next run.
    sudo pkill -f "agentpvm run -name $name" 2>/dev/null || true

    if sudo grep -q "PERF_TEST_COMPLETED" "$console_log" 2>/dev/null; then
        echo "✅ $name: I/O perf completed."
        return 0
    fi
    echo "❌ $name: I/O perf failed (no PERF_TEST_COMPLETED)."
    echo "----- $name console.log -----"
    sudo cat "$console_log" 2>/dev/null || echo "(no console.log)"
    echo "----- $name $ap_log -----"
    cat "$ap_log" 2>/dev/null || true
    return 1
}

OVERALL=0

# 1) qemu-storage-daemon (reference). Requires the daemon; skip cleanly if absent.
QEMU_LOG=agentpvm_qemu.log
QEMU_CONSOLE=/var/lib/uml-container/containers/perf-test/logs/console.log
if ! command -v qemu-storage-daemon &> /dev/null; then
    echo "Skipping qemu-storage-daemon backend: qemu-storage-daemon is not installed."
elif ! run_one "perf-test" "-native-vhost=false" "$QEMU_LOG" "$QEMU_CONSOLE"; then
    # The reference path is the baseline; if it fails, the native stage is not
    # going to diagnose anything new, so bail out.
    echo "qemu-storage-daemon backend failed; aborting before native stage."
    exit 1
fi

# 2) native Go backend (synchronous pread/pwrite; see internal/vhost/virtqueue.go).
NATIVE_LOG=agentpvm_native.log
NATIVE_CONSOLE=/var/lib/uml-container/containers/perf-test-native/logs/console.log
if ! run_one "perf-test-native" "-native-vhost=true" "$NATIVE_LOG" "$NATIVE_CONSOLE"; then
    OVERALL=1
fi

if [ $OVERALL -eq 0 ]; then
    echo "✅ I/O Performance Test completed successfully on all backends!"
    exit 0
fi
echo "❌ I/O Performance Test failed on one or more backends."
exit 1
