#!/bin/bash
set -ex
# Alpine 架构名与 uname -m 一致（x86_64/aarch64），riscv64 等未来再议
ALPINE_ARCH=$(uname -m)

echo "Building binary..."
go build -o bin/umlctl ./cmd/umlctl

echo "Creating rootfs.img..."
dd if=/dev/zero of=rootfs.img bs=1M count=100
mkfs.ext4 rootfs.img

echo "Downloading Alpine Edge minirootfs..."
EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/$ALPINE_ARCH/${EDGE_TAR}" -O alpine.tar.gz

echo "Mounting and extracting..."
mkdir -p mnt
sudo mount -o loop rootfs.img mnt
sudo tar -xzf alpine.tar.gz -C mnt/

echo "Creating an init script..."
cat << 'EOF' | sudo tee mnt/init.sh
#!/bin/sh
echo "=============================="
echo " HELLO_FROM_UML_CONTAINER"
echo "=============================="
# Power off the UML kernel
poweroff -f
EOF
sudo chmod +x mnt/init.sh

sudo umount mnt

echo "Running UML with custom compiled linux kernel..."
# umlctl's own stdout/stderr (status line, warnings) goes to uml.log.
# The UML kernel console is tee'd to a separate file by internal/log.SetupConsoleLog
# at <RootDir>/<id>/logs/console.log (RootDir defaults to /var/lib/uml-container/containers).
UMLCTL_LOG=uml.log
CONSOLE_LOG=/var/lib/uml-container/containers/integration-test/logs/console.log

# fb4ed76a hardened validateRootfs: the rootfs is interpolated into the UML
# kernel cmdline (ubd0=...) and must be absolute — resolve against the cwd
# of this script before invoking umlctl (sudo preserves the expanded path).
sudo ./bin/umlctl start --name integration-test --kernel ./bin/linux --rootfs "$(pwd)/rootfs.img" --init /init.sh > "$UMLCTL_LOG" 2>&1 || true

echo "---- umlctl output ($UMLCTL_LOG) ----"
cat "$UMLCTL_LOG"
echo "---- UML console ($CONSOLE_LOG) ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || echo "(no console.log found)"

if grep -q "HELLO_FROM_UML_CONTAINER" "$UMLCTL_LOG" "$CONSOLE_LOG" 2>/dev/null; then
    echo "SUCCESS: UML booted and ran our init script!"
else
    echo "FAILED: Did not find expected output from UML."
    exit 1
fi
