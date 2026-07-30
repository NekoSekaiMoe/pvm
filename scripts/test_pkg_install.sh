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

# Set up an init script that configures network via eth0 (NAT) and installs python3
cat << 'EOF' | sudo tee mnt_pkg/init.sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
# 以读写重挂载，确保能写 resolv.conf / apk 缓存等。
mount -o remount,rw / 2>/dev/null || true
# Assuming eth0 is set up by pvm
ip link set eth0 up || true
ip addr add 10.0.0.2/24 dev eth0 || true
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

# Setup Host Networking
sudo ip tuntap add tap_pkg mode tap || true
sudo ip link set tap_pkg up || true
sudo ./bin/umlctl network create pvm_br0 || true
sudo ip link set tap_pkg master pvm_br0 || true

# Run the container
CONSOLE_LOG=/var/lib/uml-container/containers/pkg-test/logs/console.log
sudo rm -f "$CONSOLE_LOG"

# Using tap=tap_pkg for network
# 后台运行 agentpvm，同时轮询成功标记；不再先同步等待再轮询。
# 容器一打出 PKG_INSTALL_SUCCESS 就立即成功退出；agentpvm 提前崩溃也会被
# 后台等待器感知；超时则由内层 timeout 兜底。
sudo timeout 180 ./agentpvm run -name pkg-test \
    -rootfs ${IMG_NAME} -kernel ./bin/linux -init /init.sh \
    -vhost=false -net-tap tap_pkg > pkg_agentpvm.log 2>&1 &
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

echo "Waiting for container to finish (up to 180s)..."
RESULT=timeout
for _ in $(seq 1 180); do
    if sudo grep -q "PKG_INSTALL_SUCCESS" "$CONSOLE_LOG" 2>/dev/null; then
        RESULT=success
        break
    fi
    if [ -f "$STATUS_FILE" ]; then
        RESULT=exited
        break
    fi
    sleep 1
done

echo "---- agentpvm output (pkg_agentpvm.log) ----"
cat pkg_agentpvm.log 2>/dev/null || echo "(no pkg_agentpvm.log)"
echo "---- Pkg Test Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || echo "(no console.log)"

case "$RESULT" in
    success)
        echo "✅ Package installation test passed."
        exit 0
        ;;
    exited)
        echo "❌ Container exited before producing PKG_INSTALL_SUCCESS (status: $(cat "$STATUS_FILE" 2>/dev/null))."
        exit 1
        ;;
    *)
        echo "❌ Package installation test timed out after 180s."
        exit 1
        ;;
esac
