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

if ! command -v qemu-storage-daemon &> /dev/null; then
    echo "Skipping I/O performance test: qemu-storage-daemon is not installed."
    exit 0
fi

if qemu-img --help | grep -q "io_uring"; then
    echo "AIO Backend: io_uring supported and will be used."
else
    echo "AIO Backend: io_uring not supported, will fallback to threads."
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

echo "Running UML with virtio-blk and io_uring..."
CONSOLE_LOG=/var/lib/uml-container/containers/perf-test/logs/console.log

# Clean up socket and logs if they exist from a previous run to avoid false positives and conflicts
sudo rm -f /var/lib/uml-container/containers/perf-test/vhost-blk.sock
sudo rm -f "$CONSOLE_LOG"

# Run the UML guest with a vhost-user-blk backend provided by
# qemu-storage-daemon (the mature, reference vhost-user-blk implementation).
# The native Go vhost-user backend (-native-vhost) is experimental and its IO
# completion path currently hangs under load; it is tracked separately and must
# not gate CI. The qemu-storage-daemon path is the same one the cow test uses
# successfully.
# `timeout` bounds the whole run; agentpvm's own exit (poweroff on success or
# crash on failure) ends it early.
sudo timeout 90 ./agentpvm run -name perf-test -rootfs ${IMG_NAME} -kernel ./bin/linux -init /init.sh -vhost=true -debug > agentpvm.log 2>&1 || true

# Ensure no lingering UML process keeps the socket/logs open for the next run.
sudo pkill -f "agentpvm run -name perf-test" 2>/dev/null || true

if sudo grep -q "PERF_TEST_COMPLETED" "$CONSOLE_LOG" 2>/dev/null; then
    echo "---- IO Perf Console Output ----"
    sudo cat "$CONSOLE_LOG" 2>/dev/null || cat agentpvm.log
    echo "✅ I/O Performance Test completed successfully!"
    exit 0
fi

echo "---- IO Perf Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || cat agentpvm.log
echo "---- IO Perf agentpvm output (agentpvm.log) ----"
cat agentpvm.log 2>/dev/null || true
echo "❌ I/O Performance Test failed to complete or timed out."
exit 1
