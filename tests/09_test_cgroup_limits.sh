#!/bin/bash
# Test 09: guest-side cgroup v2 resource limits (memory.max / pids.max).
#
# Verifies that the UML guest kernel (built by scripts/build_kernel.sh with
# CONFIG_MEMCG + CONFIG_CGROUP_PIDS) really enforces cgroup v2 limits INSIDE
# the guest — as opposed to the host-side cgroup the internal/cgroup manager
# wraps around the whole UML process (covered by 03 and manager tests).
#
# Requires: root (loop mount), ./bin/linux rebuilt with the new config.
set -eo pipefail

echo "========== Test 09: Guest Cgroup Limits (memory.max / pids.max) =========="

if [ ! -f ./bin/linux ]; then
    echo "❌ ./bin/linux not found — run ./scripts/build_kernel.sh first"
    exit 1
fi

go build -o bin/umlctl ./cmd/umlctl

NAME="cgroup-limit-test"
ROOTFS=rootfs-cgroup-test.img
CONSOLE_LOG=/var/lib/uml-container/containers/$NAME/logs/console.log
UMLCTL_LOG=uml-cgroup-test.log

cleanup() {
    sudo umount mnt 2>/dev/null || true
    rm -rf mnt "$ROOTFS" alpine-cgroup-test.tar.gz
}
trap cleanup EXIT

echo "Creating rootfs.img..."
dd if=/dev/zero of="$ROOTFS" bs=1M count=100 status=none
mkfs.ext4 -q "$ROOTFS"

echo "Downloading Alpine minirootfs..."
EDGE_TAR=$(curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/latest-releases.yaml | grep "file: alpine-minirootfs" | head -n 1 | awk '{print $2}')
wget -q "https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/${EDGE_TAR}" -O alpine-cgroup-test.tar.gz

mkdir -p mnt
sudo mount -o loop "$ROOTFS" mnt
sudo tar -xzf alpine-cgroup-test.tar.gz -C mnt/

# Guest-side test script, runs as PID 1 inside the UML container.
# Markers asserted from the host: MEMCG_PRESENT, PIDS_PRESENT,
# PIDS_LIMIT_ENFORCED, MEM_LIMIT_ENFORCED, CGROUP_LIMIT_TEST_DONE.
cat << 'EOF' | sudo tee mnt/init.sh
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mkdir -p /sys/fs/cgroup /dev/shm
mount -t cgroup2 none /sys/fs/cgroup || { echo "CGROUP2_MOUNT_FAILED"; poweroff -f; }
mount -t tmpfs none /dev/shm

CG=/sys/fs/cgroup

# 1. Controllers compiled in (proves CONFIG_MEMCG / CONFIG_CGROUP_PIDS).
grep -q '^memory' /proc/cgroups && echo "MEMCG_PRESENT" || echo "MEMCG_MISSING"
grep -q '^pids'   /proc/cgroups && echo "PIDS_PRESENT"  || echo "PIDS_MISSING"

echo "+memory +pids" > $CG/cgroup.subtree_control

# 2. pids.max enforcement: cap at 8 tasks, try to spawn 32 sleeps.
#    With enforcement pids.current never exceeds 8 (forks fail with EAGAIN).
mkdir $CG/pidstest
echo 8 > $CG/pidstest/pids.max
echo $$ > $CG/pidstest/cgroup.procs
i=0
while [ $i -lt 32 ]; do
    ( sleep 2 ) &
    i=$((i+1))
done
sleep 1
CUR=$(cat $CG/pidstest/pids.current)
echo "pids.current=$CUR (pids.max=8)"
[ "$CUR" -le 8 ] && echo "PIDS_LIMIT_ENFORCED" || echo "PIDS_LIMIT_NOT_ENFORCED"
wait
echo $$ > $CG/cgroup.procs

# 3. memory.max enforcement: 32M cap, then write 256M into tmpfs.
#    tmpfs pages are charged to the writer's memcg, so the dd must be
#    OOM-killed (exit 137 = 128+SIGKILL) if the controller works.
mkdir $CG/memtest
echo 32M > $CG/memtest/memory.max
sh -c 'echo $$ > /sys/fs/cgroup/memtest/cgroup.procs; exec dd if=/dev/zero of=/dev/shm/hog bs=1M count=256 2>/dev/null'
RC=$?
rm -f /dev/shm/hog
[ "$RC" -eq 137 ] && echo "MEM_LIMIT_ENFORCED rc=$RC" || echo "MEM_LIMIT_NOT_ENFORCED rc=$RC"

echo "CGROUP_LIMIT_TEST_DONE"
poweroff -f
EOF
sudo chmod +x mnt/init.sh
sudo umount mnt

echo "Booting UML with the cgroup-limit test init..."
sudo ./bin/umlctl start --name "$NAME" --kernel ./bin/linux --rootfs "$ROOTFS" --init /init.sh > "$UMLCTL_LOG" 2>&1 || true

echo "---- guest console ($CONSOLE_LOG) ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || cat "$UMLCTL_LOG"

FAILED=0
for marker in MEMCG_PRESENT PIDS_PRESENT PIDS_LIMIT_ENFORCED MEM_LIMIT_ENFORCED CGROUP_LIMIT_TEST_DONE; do
    if grep -q "$marker" "$UMLCTL_LOG" || sudo grep -q "$marker" "$CONSOLE_LOG" 2>/dev/null; then
        echo "✅ $marker"
    else
        echo "❌ missing marker: $marker"
        FAILED=1
    fi
done

if [ $FAILED -ne 0 ]; then
    echo "❌ Guest cgroup limit test FAILED"
    exit 1
fi
echo "✅ Guest cgroup limits (memory.max + pids.max) enforced inside UML"
