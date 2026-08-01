#!/bin/bash
set -ex

KERNEL_VERSION="6.18.36"
KERNEL_TAR="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TAR}"

echo "Downloading Linux kernel ${KERNEL_VERSION}..."
wget -q "${KERNEL_URL}"
tar -xf "${KERNEL_TAR}"
cd "linux-${KERNEL_VERSION}"

# UML 6.6.9 在支持大 XSAVE 扩展（AMX/AVX-512）的 host（如 GitHub Actions 的
# Xeon runner）上，init 启动后立即 SIGSEGV:
#   userspace - ptrace set fp regs failed, errno = 14
#   Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
#
# 根因：arch/x86/um/os-Linux/registers.c 的 have_xstate_support 路径用编译时
# 固定大小的 FP_SIZE buffer 走 PTRACE_SETREGSET(NT_X86_XSTATE)。当 host 内核
# 要求的 xstate size > FP_SIZE（AMX 就是这种情况），内核返回 EFAULT。上游修复
# （2024-10 [PATCH v5] um: switch to regset API and depend on XSTATE）让 UML
# 运行时发现 host xstate size，但未进 6.6.9。
#
# 规避：强制 have_xstate_support=0，让 UML 回退到 PTRACE_GETFPREGS/SETFPREGS
# （老 fxsave，512 字节固定，所有 x86_64 host 都支持）。代价：guest 内不暴露
# AVX/AMX 等扩展；alpine busybox/dd 等常规负载用不到，不影响正确性。
echo "Patching arch/x86/um/os-Linux/registers.c to disable xstate path (AMX/AVX EFAULT workaround)..."
if grep -q 'have_xstate_support = 1' arch/x86/um/os-Linux/registers.c; then
    sed -i 's/\(.*have_xstate_support = 1.*\)/\/* AMX xstate EFAULT workaround: force fxsave path *\/ \/*\1*\//' arch/x86/um/os-Linux/registers.c
    grep -n 'AMM xstate EFAULT workaround\|have_xstate_support' arch/x86/um/os-Linux/registers.c || true
else
    echo "Warning: have_xstate_support assignment not found; patch skipped (kernel source layout changed?)."
fi

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
