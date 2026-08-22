#!/bin/sh
# init-ephemeral.sh — reference guest init for ephemeral (non-persistent)
# PVM sandboxes (workspace.ephemeral = true / -ephemeral).
#
# Contract with the host side (internal/container StartTask):
#   * The root filesystem is mounted READ-ONLY (kernel cmdline "ro") and, on
#     the vhost path, served through a read-only block backend — a guest
#     `mount -o remount,rw /` fails at the device level.
#   * No qcow2 overlay exists; nothing written anywhere on the rootfs can
#     persist, and writable scratch MUST live on tmpfs (RAM).
#   * hostfs volumes (hostfs_volume=<host>:<guest>[:<mode>]) are mounted rw
#     unless the volume declared read_only=true — those writes DO reach the
#     host, by explicit user intent, and survive the sandbox.
#
# Install this script as /init.sh in the rootfs image (tests do this when
# assembling fixtures), or point workspace.init at its in-guest path.
# It consumes the standard UML init environment: unknown kernel cmdline
# key=value pairs (e.g. hostfs_volume=, egress_proxy=) arrive as init
# environment variables.

# /proc and /sys are required by most userspace tools.
mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null

# Writable scratch on tmpfs — the ONLY writable paths in an ephemeral sandbox.
# tmpfs lives in guest RAM: writes vanish when the sandbox exits (and count
# against the sandbox's memory budget, which is the intended backpressure).
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/tmp
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm

# Directories that boot-time tools expect to write into; bind tmpfs over the
# read-only originals so the rootfs stays pristine.
for d in /var/log /var/cache; do
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$d" 2>/dev/null
done

# Attach declared hostfs volumes (host passes hostfs_volume=host:guest[:mode]).
for vol in $(IFS=,; echo "${hostfs_volume:-}"); do
    host=$(echo "$vol" | cut -d: -f1)
    guest=$(echo "$vol" | cut -d: -f2)
    mode=$(echo "$vol" | cut -d: -f3)
    [ -z "$mode" ] && mode=rw
    mkdir -p "$guest" 2>/dev/null || true
    mount -t hostfs -o "$mode" none "$guest" -o "$host" 2>/dev/null || \
        echo "init-ephemeral: warning: could not mount volume $host -> $guest"
done

echo "init-ephemeral: root ro, tmpfs scratch ready" > /dev/console

# Hand off to the workload. Replace with the agent entrypoint as needed.
exec /bin/sh
