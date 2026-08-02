#!/bin/bash
set -ex
echo "Testing Package Installation inside Sandbox..."

# Make sure agentpvm and umlctl are built
go build -o agentpvm ./cmd/agentpvm
go build -o bin/umlctl ./cmd/umlctl

IMG_NAME="pkg_rootfs.img"
echo "Creating and extracting minirootfs..."
dd if=/dev/zero of=${IMG_NAME} bs=1M count=200 >/dev/null 2>&1
mkfs.ext4 -q ${IMG_NAME}

if [ ! -f "alpine.tar.gz" ]; then
    EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
    wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/${EDGE_TAR}" -O alpine.tar.gz
fi

mkdir -p mnt_pkg
sudo mount -o loop ${IMG_NAME} mnt_pkg
trap 'sudo umount mnt_pkg 2>/dev/null || true' EXIT
sudo tar -xzf alpine.tar.gz -C mnt_pkg/

# Set up an init script that configures network via vec0 (NAT) and installs python3
cat << 'EOF' | sudo tee mnt_pkg/init.sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
# 以读写重挂载，确保能写 resolv.conf / apk 缓存等。
mount -o remount,rw / 2>/dev/null || true
# Assuming vec0 is set up by pvm (UML vector transport; legacy eth0=tuntap
# was removed in Linux 6.16).
ip link set vec0 up || true
ip addr add 10.0.0.2/24 dev vec0 || true
ip route add default via 10.0.0.1 || true
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# ---- 诊断：确认 PATH、apk 与 musl 动态链接器是否存在 ----
echo "PATH=$PATH"
command -v apk || echo "command -v apk: NOT FOUND in PATH"
ls -la /sbin/apk 2>/dev/null || echo "/sbin/apk: missing"
ls -la /lib/ld-musl-x86_64.so.1 2>/dev/null || echo "/lib/ld-musl-x86_64.so.1: missing"
mount | grep ' / ' || true
# ----------------------------------------------------------------

echo "Attempting to install fastfetch..."
# 诊断阶段：不加 timeout，直接跑裸 apk，定位 “apk: No such file or directory”
# 的真实层级。在每个关键点打 marker。失败后显式 poweroff，避免 init 退出后
# UML 内核挂起被误测为超时。

# 1) 裸 apk——看 execve 本身返回什么
/sbin/apk --version 2>&1
 echo "APK_VERSION rc=$?"

# 2) 绕过内核 PT_INTERP，显式用 musl ldso 启动 apk
/lib/ld-musl-x86_64.so.1 /sbin/apk --version 2>&1
 echo "LDSO_APK rc=$?"

# 3) busybox 子命令——确认是否所有动态 ELF 都同样失败
busybox true 2>&1
 echo "BUSYBOX_TRUE rc=$?"

# 3.5) 网络诊断：打印未过滤的接口/路由表，定位 "Network unreachable"
# 到底是 eth0 根本不存在、还是存在但没拿到 IP/路由。之前的 grep 过滤会
# 吞掉 "Device not found" 这类错误，让诊断尖细号丢失。
echo "--- guest net diag (full, unfiltered) ---"
echo "### ip addr show"
ip addr show 2>&1
echo "### ip route show"
ip route show 2>&1
echo "### ip link show vec0"
ip link show vec0 2>&1 || echo "(vec0 does not exist in the guest)"
echo "### ping gateway 10.0.0.1"
ping -c 2 -W 3 10.0.0.1 2>&1 || echo "ping gw FAILED rc=$?"
echo "### nslookup dl-cdn.alpinelinux.org 8.8.8.8"
nslookup dl-cdn.alpinelinux.org 8.8.8.8 2>&1 || echo "nslookup FAILED rc=$?"
echo "### TCP 443 egress probe (authoritative — this is the transport apk actually uses)"
wget -q -T 5 -O /dev/null https://dl-cdn.alpinelinux.org/ && echo "TCP 443 egress OK" || echo "TCP 443 egress FAILED rc=$?"
echo "### ping 8.8.8.8 (informational ONLY — ICMP echo is dropped by the Azure fabric on"
echo "### GitHub-hosted runners, so this fails even when TCP/UDP egress works; not a PVM bug)"
ping -c 2 -W 3 8.8.8.8 2>&1 || echo "(ICMP echo unreachable — expected on Azure CI; rely on the TCP probe + apk instead)"
echo "--- end guest net diag ---"

# 4) 真正的安装步骤（保留成功标记）；apk 是动态 ELF，如果上面失败了这里也会失败
apk update \
  && apk add fastfetch \
  && fastfetch \
  && echo "PKG_INSTALL_SUCCESS"

echo "INIT_DONE rc=$?"
# 显式 halt，避免 init 退出后 UML 内核挂起。
busybox poweroff -f

EOF
sudo chmod +x mnt_pkg/init.sh

trap - EXIT
sudo umount mnt_pkg

# Block backend: use the ubd path (raw base mounted directly, no qcow2 CoW).
# This is the verified-working configuration for networking: vec0 (the only
# UML net transport left in Linux >= 6.16) over the ubd block backend.
# vec0 is transport-independent — it works identically over the vhost
# (virtio_uml / vhost-user-blk) block backend, which tests/04_test_qcow2_mount.sh
# proves end-to-end (guest boots from /dev/vda and reaches the gateway).
BASE_IMG="${IMG_NAME}"   # raw ext4 image, mounted directly via ubd0

# Setup Host Networking. Do NOT swallow these errors silently: a missing
# bridge or a tap that never got mastered leaves the guest with no route,
# which presents as a vague "Network unreachable" deep in apk. Each step logs
# its outcome so a CI failure points at the broken layer.
echo "===== HOST NETWORK SETUP ====="
sudo ip tuntap add tap_pkg mode tap 2>&1 || echo "[net] tap_pkg already exists or failed to add"
sudo ip link set tap_pkg up 2>&1 || echo "[net] WARN: tap_pkg up failed"
sudo ./bin/umlctl network create pvm_br0 2>&1 || echo "[net] WARN: pvm_br0 create returned non-zero (may already exist)"
sudo ip link set tap_pkg master pvm_br0 2>&1 || echo "[net] ERROR: could not master tap_pkg onto pvm_br0 (bridge missing?)"

# Fail fast if the bridge or the tap-mastering actually failed: there is no
# point booting a guest that cannot reach the gateway. These checks turn the
# silent ||true failures above into an explicit, diagnosable exit.
if ! sudo ip link show pvm_br0 >/dev/null 2>&1; then
    echo "[net] FATAL: pvm_br0 does not exist after setup; aborting before guest boot."
    exit 1
fi
if ! sudo bridge link 2>/dev/null | grep -q tap_pkg; then
    echo "[net] FATAL: tap_pkg is not attached to pvm_br0; guest would have no L2 path. Aborting."
    exit 1
fi

# ---- 诊断：dump host 侧网络状态，定位 DNS 失败是 host 还是 guest 侧问题 ----
echo "===== HOST NETWORK STATE ====="
echo "--- ip link show ---"; sudo ip link show 2>&1 | grep -E 'pvm_br0|tap_pkg|^[0-9]'
echo "--- ip addr show pvm_br0 ---"; sudo ip addr show pvm_br0 2>&1
echo "--- bridge link (tap on bridge?) ---"; sudo bridge link 2>&1 || true
echo "--- iptables -t nat -S (MASQUERADE?) ---"; sudo iptables -t nat -S 2>&1 | grep -i masq || echo "(no MASQUERADE rules)"
echo "--- sysctl net.ipv4.ip_forward ---"; sysctl net.ipv4.ip_forward 2>&1
echo "--- default route on host ---"; sudo ip route show default 2>&1
echo "--- can host resolve? ---"; getent hosts dl-cdn.alpinelinux.org 2>&1 || echo "(host DNS also failing)"
echo "==============================="
# --------------------------------------------------------------------------------

# Run the container
CONSOLE_LOG=/var/lib/uml-container/containers/pkg-test/logs/console.log
sudo rm -f "$CONSOLE_LOG"

# Using tap=tap_pkg for network
# 后台运行 agentpvm，同时轮询成功标记；不再先同步等待再轮询。
# 容器一打出 PKG_INSTALL_SUCCESS 就立即成功退出；agentpvm 提前崩溃也会被
# 后台等待器感知；超时则由内层 timeout 兜底。
sudo ./agentpvm run -name pkg-test \
    -rootfs ${BASE_IMG} -kernel ./bin/linux -init /init.sh \
    -vhost=false -net-tap tap_pkg
PVM_PID=$!

cleanup() {
    # agentpvm 仍在运行则终止它（其子进程 UML 会被一并回收）。
    kill "$PVM_PID" 2>/dev/null || true
    wait "$PVM_PID" 2>/dev/null || true
    # 兜底：杀掉残留的、以本容器名为参数的 UML 内核进程。
    sudo pkill -f "agentpvm run -name pkg-test" 2>/dev/null || true
    sudo ./bin/umlctl network rm pvm_br0 || true
    sudo ip link delete tap_pkg || true
}
trap cleanup EXIT

STATUS_FILE=pkg_exit_status
rm -f "$STATUS_FILE"
# 后台等待器：agentpvm 退出后把状态落到文件，供主轮询循环感知。
# 不用 wait $PVM_PID，因为 sudo/timeout 链可能让 $PVM_PID 不再是本 shell 的
# 直接子进程（上一轮 CI 日志报 “pid is not a child of this shell”）。
# 改用 pgrep -f 按命令行匹配存活状态，与 pid 亲缘关系无关，也不会被 sudo
# 提前返回误导。
(
    while pgrep -f "agentpvm run -name pkg-test" >/dev/null 2>&1; do
        sleep 1
    done
    wait "$PVM_PID" 2>/dev/null
    echo $? > "$STATUS_FILE"
) &

echo "---- agentpvm output (pkg_agentpvm.log) ----"
cat pkg_agentpvm.log 2>/dev/null || echo "(no pkg_agentpvm.log)"
echo "---- Pkg Test Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || echo "(no console.log)"

# ---- Result assertion ----
# The run succeeds ONLY if the guest printed PKG_INSTALL_SUCCESS. Everything
# else (guest booted but vec0 missing, apk failed, console.log empty, timeout)
# is a failure. Earlier versions of this script just `cat`-ed the log and
# exited 0 unconditionally, so a totally broken run (no networking, no apk)
# reported SUCCESS and CI stayed green. This block makes the outcome explicit
# and loud.
echo "============================================================"
if sudo grep -q "PKG_INSTALL_SUCCESS" "$CONSOLE_LOG" 2>/dev/null; then
    echo "✅ pkg-test PASS: PKG_INSTALL_SUCCESS observed in console.log"
    exit 0
fi
echo "❌ pkg-test FAIL: PKG_INSTALL_SUCCESS NOT observed in console.log"
echo ""
echo "--- DIAG: UML kernel command line (proves which block/net transports were passed) ---"
sudo grep -E "Kernel command line:" "$CONSOLE_LOG" 2>/dev/null | tail -1 || echo "   (no 'Kernel command line' line — UML did not finish early boot)"
echo ""
echo "--- DIAG: UML network driver init (vec/eth registration, or why it failed) ---"
sudo grep -Ei "eth0|vec[0-9]|netdevice|tun/tap|tuntap|network device|choosing a random ethernet|uml_net|netfront|virtio.*net" "$CONSOLE_LOG" 2>/dev/null | head -20 || echo "   (no UML net-driver lines — kernel may predate net init, or net transport never parsed)"
echo ""
echo "--- DIAG: guest-side failure markers ---"
sudo grep -E "PING |FAILED|Network unreachable|INIT_DONE|PKG_INSTALL_SUCCESS|No such|not found|panic" "$CONSOLE_LOG" 2>/dev/null | tail -20 || echo "   (no console.log at all — agentpvm likely crashed before boot)"
exit 1
