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
# Assuming eth0 is set up by pvm
ip link set eth0 up || true
ip addr add 10.0.0.2/24 dev eth0 || true
ip route add default via 10.0.0.1 || true
echo "nameserver 8.8.8.8" > /etc/resolv.conf

echo "Attempting to install python3..."
apk update && apk add python3 && echo "PKG_INSTALL_SUCCESS"

poweroff -f
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
sudo ./agentpvm run -name pkg-test -rootfs ${IMG_NAME} -kernel ./bin/linux -init /init.sh -vhost=false -tap tap_pkg > pkg_agentpvm.log 2>&1 || true

echo "Waiting for container to finish (up to 30s)..."
for i in {1..30}; do
    if sudo grep -q "PKG_INSTALL_SUCCESS" "$CONSOLE_LOG" 2>/dev/null; then
        echo "✅ Package installation test passed."
        sudo ./bin/umlctl network rm pvm_br0 || true
        sudo ip link delete tap_pkg || true
        exit 0
    fi
    sleep 1
done

echo "---- Pkg Test Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || cat pkg_agentpvm.log
echo "❌ Package installation test failed or timed out."
sudo ./bin/umlctl network rm pvm_br0 || true
sudo ip link delete tap_pkg || true
exit 1
