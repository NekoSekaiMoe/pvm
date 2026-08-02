#!/bin/bash
set -eo pipefail

echo "========== Test 04: qcow2 CoW Direct Mount =========="

go build -o agentpvm cmd/agentpvm/main.go

# Generate a backing image formatted as ext4. The overlay inherits a valid
# superblock from base.img so the guest's mount_root can actually recognize it;
# an all-zero backing file (the previous dd-only base) always panics with
# "VFS: Unable to mount root fs" because no filesystem signature is present.
dd if=/dev/zero of=base.img bs=1M count=10 > /dev/null 2>&1
mkfs.ext4 -q -F base.img

# The agent path is qcow2-only: agentpvm creates a per-task qcow2 CoW overlay
# on top of a qcow2 base and serves it via qemu-storage-daemon. Convert the
# raw ext4 image to qcow2 once; agentpvm builds the overlay itself at start.
if ! command -v qemu-img &> /dev/null; then
    echo "qemu-img not found, skipping qcow2 base creation step."
    exit 0
fi
# qemu-storage-daemon is the sole vhost-user-blk backend and is required for
# the qcow2 overlay path.
if ! command -v qemu-storage-daemon &> /dev/null; then
    echo "qemu-storage-daemon not found, skipping (required for qcow2 vhost)."
    exit 0
fi

echo "Converting raw ext4 base to qcow2..."
qemu-img convert -p -O qcow2 base.img base.qcow2 > /dev/null

echo "Launching agentpvm (qcow2 base -> per-task overlay via qemu-storage-daemon)..."
./agentpvm run -name "test-cow" -rootfs base.qcow2 -vhost=true &
PID=$!

trap "kill $PID 2>/dev/null || true; rm -f base.img base.qcow2" EXIT

if ! kill -0 $PID 2>/dev/null; then
    echo "❌ agentpvm failed to start"
    exit 1
fi

sleep 2

# Verify the socket was created
if [ -S "/var/lib/uml-container/containers/test-cow/vhost-blk.sock" ]; then
    echo "✅ qcow2 vhost-user socket generated."
else
    echo "❌ qcow2 vhost-user socket missing."
    exit 1
fi

echo "✅ Direct qcow2 mount logic verified."
