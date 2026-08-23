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
#
# A failed start must fail the script: dump umlctl's own log and exit now
# (the old '|| true' masked startup failures). The launch is also BOUNDED by
# timeout(1): if umlctl (or the UML kernel under it) hangs, timeout kills it
# after BOOT_TIMEOUT seconds so THIS script regains control and dumps every
# piece of evidence it has (uml.log, UML console.log, state.json, process
# table). Without the bound, a hang runs straight into the workflow's
# timeout-minutes CANCEL, which skips the workflow's own dump steps
# (cancel != failure) and leaves zero diagnostics behind — exactly the
# evidence-free failure seen in the 1090982 run.
# timeout(1) runs as root inside sudo so it can signal the privileged umlctl;
# -k adds a SIGKILL follow-up in case umlctl ignores the SIGTERM (rc 124 =
# timed out). BOOT_TIMEOUT must stay comfortably below the workflow step's
# timeout-minutes budget so the dumps below actually get emitted.
BOOT_TIMEOUT=480
# Canonical path of the kernel binary THIS test launches; the failure
# cleanup below compares /proc/<pid>/exe against it to verify process
# identity before killing (a cmdline substring match is spoofable by any
# process merely mentioning "bin/linux" in its argv).
KERNEL_REAL=$(realpath ./bin/linux)
set +e
sudo timeout -k 15 "${BOOT_TIMEOUT}" ./bin/umlctl start --name integration-test --kernel ./bin/linux --rootfs "$(pwd)/rootfs.img" --init /init.sh > "$UMLCTL_LOG" 2>&1
START_RC=$?
set -e
if [ "$START_RC" -ne 0 ]; then
    if [ "$START_RC" -eq 124 ] || [ "$START_RC" -eq 137 ]; then
        echo "FAILED: umlctl start still alive after ${BOOT_TIMEOUT}s — HANG, not a clean failure."
    fi
    echo "FAILED: umlctl start exited $START_RC — $UMLCTL_LOG contents:"
    cat "$UMLCTL_LOG" 2>/dev/null || echo "(no umlctl log)"
    echo "---- UML console ($CONSOLE_LOG) ----"
    sudo cat "$CONSOLE_LOG" 2>/dev/null || echo "(no console.log found)"
    echo "---- container state.json ----"
    sudo cat /var/lib/uml-container/containers/integration-test/state.json 2>/dev/null || echo "(no state.json)"
    echo "---- surviving UML/umlctl processes (STAT+WCHAN show where they are stuck) ----"
    sudo ps -eo pid,ppid,stat,wchan:32,cmd | grep -E 'bin/linux|umlctl' | grep -v grep || echo "(none)"
    # Kill leftovers (the SIGTERM above may have orphaned guest host-side
    # processes — they survive Pdeathsig, which only binds monitor->umlctl).
    # SCOPED cleanup: only the UML kernel process THIS test launched. The
    # kernel's host PID is recorded in the container's state.json ("pid"
    # field, written by internal/container Start after Launcher.Start).
    # Never pkill by the global process name "linux" — that would SIGKILL
    # unrelated UML instances from other jobs sharing this host.
    STATE_JSON=/var/lib/uml-container/containers/integration-test/state.json
    UML_PID=$(sudo grep -o '"pid"[[:space:]]*:[[:space:]]*[0-9]\+' "$STATE_JSON" 2>/dev/null | grep -o '[0-9]\+$' || true)
    if [ -n "$UML_PID" ] && [ "$UML_PID" -gt 0 ] 2>/dev/null; then
        # Guard against stale state.json / PID reuse: only kill once the
        # live process's identity is verified — never by a loose cmdline
        # substring (any process mentioning "bin/linux" in argv would
        # match). Two constrained checks, either suffices:
        #   1. canonical /proc/<pid>/exe equals THIS test's kernel binary
        #      (or the jail re-exec entry that bind-mounts it);
        #   2. a strict argv contract: argv[0] is exactly the expected
        #      kernel invocation AND argv carries THIS test's rootfs path.
        PROC_EXE=$(sudo readlink -f "/proc/$UML_PID/exe" 2>/dev/null || true)
        JAIL_ENTRY=/tmp/pvm-jails/integration-test/root/pvm/entry
        ARGV0=$(sudo sh -c 'tr "\0" "\n" < "$1" | head -n1' _ "/proc/$UML_PID/cmdline" 2>/dev/null || true)
        # Fall back to the raw path when rootfs.img is missing or realpath
        # fails: under set -e a bare failing substitution would abort the
        # script here, skipping the identity check and the kill cleanup.
        ROOTFS_REAL=$(realpath ./rootfs.img 2>/dev/null || echo "./rootfs.img")
        IS_OURS=0
        case "$PROC_EXE" in
            "$KERNEL_REAL"|"$JAIL_ENTRY") IS_OURS=1 ;;
        esac
        if [ "$IS_OURS" -eq 0 ] && [ -n "$ARGV0" ] \
            && { [ "$ARGV0" = "./bin/linux" ] || [ "$ARGV0" = "$JAIL_ENTRY" ]; } \
            && sudo grep -qazF "$ROOTFS_REAL" "/proc/$UML_PID/cmdline" 2>/dev/null; then
            IS_OURS=1
        fi
        if [ "$IS_OURS" -eq 1 ]; then
            for CHILD in $(sudo pgrep -P "$UML_PID" 2>/dev/null); do
                sudo kill -9 "$CHILD" 2>/dev/null || true
            done
            sudo kill -9 "$UML_PID" 2>/dev/null || true
            echo "killed leftover UML kernel pid $UML_PID (integration-test only)"
        else
            echo "(pid $UML_PID from state.json failed identity check (exe='${PROC_EXE:-unknown}'); skipping kill)"
        fi
    else
        echo "(no UML pid recorded in state.json; nothing to kill)"
    fi
    exit 1
fi

echo "---- umlctl output ($UMLCTL_LOG) ----"
cat "$UMLCTL_LOG" 2>/dev/null || echo "(no umlctl log)"
echo "---- UML console ($CONSOLE_LOG) ----"
sudo cat "$CONSOLE_LOG" 2>/dev/null || echo "(no console.log found)"

# console.log is root-only (0600 inside a 0700 dir — see internal/log
# SetupConsoleLog hardening), and umlctl start runs under sudo, so grep the
# console log via sudo too; a plain grep gets EACCES which 2>/dev/null hides.
if grep -q "HELLO_FROM_UML_CONTAINER" "$UMLCTL_LOG" 2>/dev/null || sudo grep -q "HELLO_FROM_UML_CONTAINER" "$CONSOLE_LOG" 2>/dev/null; then
    echo "SUCCESS: UML booted and ran our init script!"
else
    echo "FAILED: Did not find expected output from UML."
    exit 1
fi
