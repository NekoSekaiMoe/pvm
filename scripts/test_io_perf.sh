#!/bin/bash
set -eo pipefail

echo "========== I/O Performance Test (virtio-blk via qemu-storage-daemon) =========="

# Build the agentpvm and umlctl
go build -o agentpvm cmd/agentpvm/main.go
go build -o bin/umlctl ./cmd/umlctl

if [ ! -f "bin/linux" ]; then
    echo "UML kernel (bin/linux) not found. Please run scripts/build_kernel.sh first."
    exit 1
fi

# Block backend: qemu-storage-daemon is the sole vhost-user-blk backend
# (the experimental native Go backend was removed). The daemon is required.

if qemu-img --help | grep -q "io_uring"; then
    echo "AIO Backend: io_uring supported and will be used by qemu-storage-daemon where applicable."
else
    echo "AIO Backend: io_uring not supported, qemu-storage-daemon will fallback to threads."
fi

IMG_NAME="perf_rootfs.img"
echo "Creating ${IMG_NAME} (300MB)..."
dd if=/dev/zero of=${IMG_NAME} bs=1M count=300 >/dev/null 2>&1
mkfs.ext4 -q -F ${IMG_NAME}

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

# run_one <name> <agentpvm_log> <console_log>
# Runs one UML guest under the qemu-storage-daemon vhost-user-blk backend,
# bounded by timeout, and returns 0 only if PERF_TEST_COMPLETED appears in
# the console log. It never exits the script itself; the caller decides the
# overall result.
run_one() {
    local name="$1"
    local ap_log="$2"
    local console_log="$3"

    echo "---- running qemu-storage-daemon backend: $name ----"
    sudo rm -f "/var/lib/uml-container/containers/${name}/vhost-blk.sock" "$console_log" "$ap_log"

    # `timeout` bounds the whole run; agentpvm's own exit (poweroff on success
    # or crash on failure) ends it early. -debug yields the full vhost protocol
    # log to the agentpvm log on failure.
    sudo timeout 120 ./agentpvm run -name "$name" -rootfs "${IMG_NAME}" \
        -kernel ./bin/linux -init /init.sh -vhost=true -debug \
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

# qemu-storage-daemon is the sole vhost-user-blk backend (the experimental
# native Go backend was removed). Skip cleanly if the daemon is not installed.
if ! command -v qemu-storage-daemon &> /dev/null; then
    echo "Skipping I/O performance test: qemu-storage-daemon is not installed."
    exit 0
fi

AP_LOG=agentpvm.log
CONSOLE_LOG=/var/lib/uml-container/containers/perf-test/logs/console.log
if run_one "perf-test" "$AP_LOG" "$CONSOLE_LOG"; then
    echo "✅ I/O Performance Test completed successfully!"
    exit 0
fi
echo "❌ I/O Performance Test failed."
exit 1
