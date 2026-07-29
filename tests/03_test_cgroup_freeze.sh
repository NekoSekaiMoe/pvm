#!/bin/bash
set -eo pipefail

echo "========== Test 03: Cgroup Freeze/Thaw =========="

go build -o agentpvm cmd/agentpvm/main.go

# Use a throwaway cgroup root. internal/cgroup.NewManager() honours the
# PVM_CGROUP_ROOT (preferred) / CGROUP_ROOT env vars; without it the manager
# falls back to the hardcoded /sys/fs/cgroup/uml, which requires root and is
# unavailable in CI.
export PVM_CGROUP_ROOT="/tmp/cgroup-test-$$"
CGROUP_DIR="$PVM_CGROUP_ROOT/test-sandbox-123"
mkdir -p "$CGROUP_DIR"
# cgroup v2 control files are plain writable files from userspace's POV when
# they live outside /sys/fs/cgroup, so we materialise the ones the manager
# touches. cgroup.freeze is read-written by Freeze/Thaw.
: > "$CGROUP_DIR/cgroup.freeze"

trap 'rm -rf "$PVM_CGROUP_ROOT"' EXIT

freeze_val() { cat "$CGROUP_DIR/cgroup.freeze"; }

echo "Initial state: freeze=$(freeze_val)"

echo "Freezing sandbox..."
./agentpvm cgroup freeze test-sandbox-123
if [ "$(freeze_val)" != "1" ]; then
    echo "❌ Freeze did not write 1 to cgroup.freeze (got '$(freeze_val)')"
    exit 1
fi

echo "Thawing sandbox..."
./agentpvm cgroup thaw test-sandbox-123
if [ "$(freeze_val)" != "0" ]; then
    echo "❌ Thaw did not write 0 to cgroup.freeze (got '$(freeze_val)')"
    exit 1
fi

echo "✅ Cgroup freeze/thaw verified against $PVM_CGROUP_ROOT"
