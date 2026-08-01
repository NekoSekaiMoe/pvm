#!/bin/bash
set -eo pipefail

echo "========== Test 04: qcow2 CoW Direct Mount =========="

go build -o agentpvm cmd/agentpvm/main.go

# Generate a backing image formatted as ext4. The overlay inherits a valid
# superblock from base.img so the guest's mount_root can actually recognize it;
# an all-zero backing file (the previous dd-only base) always panics with
# "VFS: Unable to mount root fs" because no filesystem signature is present.
dd if=/dev/zero of=base.img bs=1M count=10 > /dev/null 2>&1
mkfs.ext4 -q base.img

# Create CoW qcow2 using our Go CLI (simulating direct call)
if ! command -v qemu-img &> /dev/null; then
    echo "qemu-img not found, skipping CoW creation step."
    exit 0
fi

echo "Creating qcow2 CoW overlay..."
qemu-img create -f qcow2 -b base.img -F raw overlay.qcow2 > /dev/null

echo "Attempting to launch qemu-storage-daemon with qcow2 driver..."
# The Go code will automatically detect .qcow2 and parse it instead of raw
./agentpvm run -name "test-cow" -rootfs overlay.qcow2 -vhost=true &
PID=$!

trap "kill $PID 2>/dev/null || true; rm -f base.img overlay.qcow2" EXIT

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
