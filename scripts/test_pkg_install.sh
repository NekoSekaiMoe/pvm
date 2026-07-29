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
# Assuming eth0 is set up by pvm, we can just bring it up
ip link set eth0 up || true
udhcpc -i eth0 || true

echo "Attempting to install python3..."
apk update && apk add python3 && echo "PKG_INSTALL_SUCCESS"

poweroff -f
EOF
sudo chmod +x mnt_pkg/init.sh

trap - EXIT
sudo umount mnt_pkg

# Run the container
CONSOLE_LOG=/var/lib/uml-container/containers/pkg-test/logs/console.log
sudo rm -f "$CONSOLE_LOG"

# Using tap=pvm_tap0 for network if NAT is configured that way
sudo ./agentpvm run -name pkg-test -rootfs ${IMG_NAME} -kernel ./bin/linux -init /init.sh -vhost=false > pkg_agentpvm.log 2>&1 || true

echo "---- Pkg Test Console Output ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || cat pkg_agentpvm.log

if sudo grep -q "PKG_INSTALL_SUCCESS" "$CONSOLE_LOG" 2>/dev/null; then
    echo "✅ Package installation test passed."
else
    echo "❌ Package installation test failed."
    exit 1
fi
