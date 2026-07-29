#!/bin/bash
set -ex

KERNEL_VERSION="6.6.9"
KERNEL_TAR="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TAR}"

echo "Downloading Linux kernel ${KERNEL_VERSION}..."
wget -q "${KERNEL_URL}"
tar -xf "${KERNEL_TAR}"
cd "linux-${KERNEL_VERSION}"

echo "Configuring UML Kernel..."
make ARCH=um defconfig

# Enable required features according to plan.md
./scripts/config --enable CONFIG_NAMESPACES
./scripts/config --enable CONFIG_PID_NS
./scripts/config --enable CONFIG_NET_NS
./scripts/config --enable CONFIG_CGROUPS
./scripts/config --enable CONFIG_CGROUP_FREEZER
./scripts/config --enable CONFIG_CGROUP_SCHED
./scripts/config --enable CONFIG_DEVTMPFS
./scripts/config --enable CONFIG_DEVTMPFS_MOUNT
./scripts/config --enable CONFIG_UNIX
./scripts/config --enable CONFIG_EXT4_FS
./scripts/config --enable CONFIG_OVERLAY_FS

# Enable virtio-uml
./scripts/config --enable CONFIG_VIRTIO_UML
./scripts/config --enable CONFIG_VIRTIO_BLK
./scripts/config --enable CONFIG_VIRTIO_NET
./scripts/config --enable CONFIG_VIRTIO_CONSOLE

make ARCH=um olddefconfig

echo "Building UML Kernel (this will take a while)..."
make ARCH=um -j$(nproc)

echo "Copying kernel binary to bin/..."
mkdir -p ../bin
cp linux ../bin/linux

echo "Kernel build complete!"
