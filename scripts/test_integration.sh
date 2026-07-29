#!/bin/bash
set -ex

echo "Building binaries..."
go build -o bin/umlctl ./cmd/umlctl
go build -o bin/umld ./cmd/umld

echo "Creating rootfs.img..."
dd if=/dev/zero of=rootfs.img bs=1M count=100
mkfs.ext4 rootfs.img

echo "Downloading Alpine Edge minirootfs..."
EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/${EDGE_TAR}" -O alpine.tar.gz

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
sudo ./bin/umlctl start --name integration-test --kernel ./bin/linux --rootfs rootfs.img --init /init.sh > uml.log 2>&1 || true

cat uml.log

if grep -q "HELLO_FROM_UML_CONTAINER" uml.log; then
    echo "SUCCESS: UML booted and ran our init script!"
else
    echo "FAILED: Did not find expected output from UML."
    exit 1
fi
