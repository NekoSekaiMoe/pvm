#!/bin/bash
set -eo pipefail

echo "========== I/O Performance Test (virtio-blk + io_uring) =========="

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
dd if=/dev/zero of=/test_write.dat bs=1M count=100 oflag=direct 2>&1 | grep -E "copied|records"

echo "Running sequential read test (100MB)..."
dd if=/test_write.dat of=/dev/null bs=1M count=100 iflag=direct 2>&1 | grep -E "copied|records"

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

sudo ./agentpvm run -name perf-test -rootfs ${IMG_NAME} -kernel ./bin/linux -init /init.sh -vhost=true -native-vhost=true > agentpvm.log 2>&1 || true

echo "Waiting for container to finish (up to 30s)..."
for i in {1..30}; do
    if sudo grep -q "PERF_TEST_COMPLETED" "$CONSOLE_LOG" 2>/dev/null; then
        echo "---- IO Perf Console Output ----"
        sudo cat "$CONSOLE_LOG" 2>/dev/null || cat agentpvm.log
        echo "✅ I/O Performance Test completed successfully!"
        exit 0
    fi
    sleep 1
done

echo "---- IO Perf Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || cat agentpvm.log
echo "❌ I/O Performance Test failed to complete or timed out."
exit 1
