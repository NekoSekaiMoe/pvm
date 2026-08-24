#!/bin/bash
set -ex

# Architecture-adaptive UML kernel build. Intended to run in CI — building a
# kernel on a laptop is painfully slow, do not run locally unless you must.
#
#   x86_64 : mainline Linux ${KERNEL_VERSION} + xstate workaround (AMX hosts)
#   aarch64: zalexdev/linux-um-arm64 @ ${ZALEXDEV_REV} (ARCH=um SUBARCH=arm64;
#            not yet mainline — see docs; revision is PINNED, a drifted remote
#            fails the build instead of silently changing the kernel)
ARCH=$(uname -m)
KERNEL_VERSION="6.18.36"
KERNEL_TAR="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TAR}"
ZALEXDEV_REPO="https://github.com/zalexdev/linux-um-arm64"
ZALEXDEV_REV="8897487c52233cd00cf2850008ca068892f1ae91"

case "$ARCH" in
  x86_64)
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
    MAKE_ARGS=(ARCH=um)
    ;;
  aarch64)
    echo "Cloning zalexdev/linux-um-arm64 @ ${ZALEXDEV_REV}..."
    command -v git >/dev/null || { echo "FATAL: git required for aarch64 kernel source"; exit 1; }
    git clone --depth 1 --single-branch --branch um-arm64 "${ZALEXDEV_REPO}" linux-um-arm64
    cd linux-um-arm64
    ACTUAL_REV=$(git rev-parse HEAD)
    if [ "$ACTUAL_REV" != "${ZALEXDEV_REV}" ]; then
        echo "FATAL: upstream um-arm64 HEAD drifted: got ${ACTUAL_REV}, pinned ${ZALEXDEV_REV}"
        echo "       (re-pin after reviewing the new commits, then update bin/linux in CI caches)"
        exit 1
    fi
    # The port needs clang (LLVM=1 maps SUBARCH=arm64 to a aarch64 target);
    # upstream defconfig for SUBARCH=arm64 enables SECCOMP userspace mode.
    command -v clang >/dev/null || { echo "FATAL: clang required for aarch64 UML build (LLVM=1)"; exit 1; }
    MAKE_ARGS=(ARCH=um SUBARCH=arm64 LLVM=1 CC=clang LD=ld.lld)
    # The port's stub_exe link rule (arch/um/kernel/skas/Makefile) drives the
    # linker through $(CC) and only carries --target from CLANG_FLAGS, so
    # LD=ld.lld never applies there. clang then falls back to its default
    # GNU cross linker (aarch64-linux-gnu-ld; binutils 2.42 on
    # ubuntu-24.04-arm), which rejects the lld-only --no-rosegment flag:
    #   STUB_EXE arch/um/kernel/skas/stub_exe.dbg
    #   aarch64-linux-gnu-ld: unrecognized option '--no-rosegment'
    # Force lld for that link (mirrors what kbuild itself does for host tools
    # under LLVM=1: Makefile adds -fuse-ld=lld to KBUILD_HOSTLDFLAGS). Upstream
    # mainline does not pass --no-rosegment at all, so guard the patch: apply
    # only while the flag is present and lld is not already forced.
    STUB_MK=arch/um/kernel/skas/Makefile
    if grep -q '^STUB_EXE_LDFLAGS = .*--no-rosegment' "${STUB_MK}" && \
       ! grep -q '^STUB_EXE_LDFLAGS = .*fuse-ld=lld' "${STUB_MK}"; then
        sed -i 's/^STUB_EXE_LDFLAGS = /STUB_EXE_LDFLAGS = -fuse-ld=lld /' "${STUB_MK}"
        echo "Patched ${STUB_MK}: stub_exe link now forces ld.lld (--no-rosegment is lld-only)."
    fi
    ;;
  *)
    echo "FATAL: unsupported host architecture '${ARCH}' (supported: x86_64, aarch64)"
    exit 1
    ;;
esac

echo "Configuring UML Kernel..."
make "${MAKE_ARGS[@]}" defconfig

# Enable required features according to plan.md
./scripts/config --enable CONFIG_NAMESPACES
./scripts/config --enable CONFIG_PID_NS
./scripts/config --enable CONFIG_NET_NS
./scripts/config --enable CONFIG_CGROUPS
./scripts/config --enable CONFIG_CGROUP_FREEZER
./scripts/config --enable CONFIG_CGROUP_SCHED
# Memory controller (cgroup v2 memory.max / OOM enforcement in guest) and
# PIDs controller (pids.max fork-bomb protection). Both default n; enable so
# TaskSpec resource limits are really enforced inside the UML guest.
./scripts/config --enable CONFIG_MEMCG
./scripts/config --enable CONFIG_CGROUP_PIDS
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

# UML networking. Since Linux 6.16 (commit e619e18 "um: Remove legacy network
# transport infrastructure") the ONLY in-tree UML net transport is the vector
# driver — CONFIG_UML_NET, CONFIG_UML_NET_TUNTAP and the other legacy
# symbols no longer exist, so 'eth0=tuntap,<tap>' is reported as an unknown
# command-line parameter and the guest gets no NIC. Enable the vector driver;
# PVM emits 'vec0:transport=tap,ifname=<tap>,depth=128,gro=1' for it. The
# generic TUN module is needed on the host side too.
./scripts/config --enable CONFIG_UML_NET_VECTOR
./scripts/config --enable CONFIG_TUN

# Statically link the UML kernel (bin/linux is a host userspace binary).
#
# 症状：在 seccomp 受限的 host 上（旧 Docker/libseccomp 默认 profile、gVisor、
# 沙箱化 CI runner），动态链接的 bin/linux 连 loader 都起不来：
#   ./bin/linux: error while loading shared libraries: libc.so.6:
#   cannot stat shared object: Operation not permitted
# 根因：glibc >= 2.33 的 ld.so 装载共享库时优先走 statx()；上述环境的
# seccomp profile 对未知 syscall 返回 EPERM（而非 ENOSYS），glibc 不 fallback，
# stat libc.so.6 直接失败，UML 代码还没开始跑就退出。
#
# 规避：CONFIG_STATIC_LINK=y 产出全静态 ELF，根本不经过动态 loader，对这类
# host 免疫（STATIC_LINK 的设计场景本来就是 chroot/受限环境）。
#
# 冲突：CONFIG_UML_NET_VECTOR `select MAY_HAVE_RUNTIME_DEPS`，而 STATIC_LINK
# depends on !MAY_HAVE_RUNTIME_DEPS。runtime deps 仅指 vector 的 UDP 类
# transport 在 arch/um/drivers/vector_user.c 里用 getaddrinfo()（NSS 需要
# 动态加载）；PVM 只用 vec0:transport=tap（直接 open /dev/net/tun，无 NSS），
# 因此可以安全地摘掉这个 select。守卫式 patch：上游若已移除该 select 则跳过。
# 注意：grep BRE 里 '\t' 是字面量 t（GNU grep 3.12），匹配 tab 必须用
# [[:space:]] 或 $'\t'。
DRIVERS_KCONFIG=arch/um/drivers/Kconfig
if grep -q '^[[:space:]]*select MAY_HAVE_RUNTIME_DEPS' "${DRIVERS_KCONFIG}"; then
    sed -i '/^[[:space:]]*select MAY_HAVE_RUNTIME_DEPS/d' "${DRIVERS_KCONFIG}"
    echo "Patched ${DRIVERS_KCONFIG}: dropped 'select MAY_HAVE_RUNTIME_DEPS' from UML_NET_VECTOR (PVM uses tap transport only; enables CONFIG_STATIC_LINK)."
else
    echo "NOTE: 'select MAY_HAVE_RUNTIME_DEPS' not found in ${DRIVERS_KCONFIG}; patch skipped (already removed upstream?)."
fi
./scripts/config --enable CONFIG_STATIC_LINK

make "${MAKE_ARGS[@]}" olddefconfig

# olddefconfig silently DROPS symbols it doesn't know (e.g. renamed options:
# CONFIG_MEMCG's v1 listing moved behind CONFIG_MEMCG_V1, off by default,
# since 6.12) or whose dependencies are unmet. Fail loudly instead of
# discovering a missing controller from a guest panic in CI.
echo "Verifying required symbols survived olddefconfig..."
missing=0
for sym in CONFIG_NAMESPACES CONFIG_PID_NS CONFIG_NET_NS \
           CONFIG_CGROUPS CONFIG_CGROUP_FREEZER CONFIG_CGROUP_SCHED \
           CONFIG_MEMCG CONFIG_CGROUP_PIDS \
           CONFIG_DEVTMPFS CONFIG_DEVTMPFS_MOUNT \
           CONFIG_UNIX CONFIG_EXT4_FS CONFIG_OVERLAY_FS \
           CONFIG_VIRTIO_UML CONFIG_VIRTIO_BLK CONFIG_VIRTIO_NET CONFIG_VIRTIO_CONSOLE \
           CONFIG_UML_NET_VECTOR CONFIG_TUN \
           CONFIG_STATIC_LINK; do
    if ! grep -q "^${sym}=y" .config; then
        echo "FATAL: ${sym} missing from .config (renamed symbol or unmet dependency)"
        missing=1
    fi
done
# CONFIG_MEMCG_V1 intentionally left off: tests use v2-native detection
# (cgroup.controllers), and 6.18 defaults it to n.
# aarch64 extra: the zalexdev arm64 port tree has a CONFIG_UML_SECCOMP
# Kconfig symbol and its defconfig enables it — verify, and note it in the
# build log for visibility. Mainline x86_64 has NO such Kconfig symbol: the
# seccomp userspace mode there is selected purely at runtime via the kernel
# command-line parameter `seccomp=on|auto|off` (parsed in
# arch/um/os-Linux/start_up.c, default off) since Linux 6.16, so no rebuild
# is needed for x86_64. Both arches share the same `seccomp=` cmdline
# (see spec security.uml_seccomp).
if [ "$ARCH" = "aarch64" ]; then
    if ! grep -q "^CONFIG_UML_SECCOMP=y" .config; then
        echo "NOTE: CONFIG_UML_SECCOMP not set on aarch64 (zalexdev tree defconfig change?); ptrace userspace mode will be used"
    else
        echo "aarch64: CONFIG_UML_SECCOMP=y (fast userspace mode available via runtime param seccomp=on)"
    fi
fi
[ "$missing" -eq 0 ] || exit 1

echo "Building UML Kernel (this will take a while)..."
make "${MAKE_ARGS[@]}" -j$(nproc)

# Fail loudly if the binary is not actually static — a dynamic bin/linux is
# exactly what breaks on seccomp-restricted hosts (libc.so.6 stat EPERM).
if ! file linux | grep -q 'statically linked'; then
    echo "FATAL: linux binary is not statically linked (STATIC_LINK silently dropped?):"
    file linux
    exit 1
fi

echo "Copying kernel binary to bin/..."
mkdir -p ../bin
cp linux ../bin/linux

echo "Kernel build complete!"
