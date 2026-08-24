#!/usr/bin/env bash
# Bazel sh_test wrapper for the PVM CI-safe suites.
#
# Why this exists: the suites read AGENTPVM_BIN/UMLCTL_BIN from the
# environment, but Bazel evaluates sh_test.env at ANALYSIS time — it cannot
# know the runfiles tree's absolute path, and the relative value it can
# provide (cmd/agentpvm/agentpvm) only resolves if the test's cwd happens
# to be the runfiles workspace root, which is not guaranteed (and is false
# for suites that cd elsewhere first).
#
# This wrapper runs at EXECUTION time, where TEST_SRCDIR/TEST_WORKSPACE
# name the runfiles tree, so it can absolutize the binary paths before
# handing control to the real suite.
#
# Usage: bazel_run.sh <suite.sh> [suite args...]
set -euo pipefail

SUITE="$1"; shift

# Runfiles workspace directory (e.g. $TEST_SRCDIR/_main). Older Bazel
# exports RUNFILES_DIR instead; handle both.
if [ -n "${TEST_SRCDIR:-}" ] && [ -n "${TEST_WORKSPACE:-}" ]; then
    WS="$TEST_SRCDIR/$TEST_WORKSPACE"
elif [ -n "${RUNFILES_DIR:-}" ]; then
    WS="$RUNFILES_DIR/${TEST_WORKSPACE:-_main}"
else
    echo "bazel_run.sh: not running under bazel (no TEST_SRCDIR/RUNFILES_DIR)" >&2
    exit 1
fi

# Locate a workspace file in the runfiles tree; fall back to execroot
# (BUILD_WORKSPACE_DIRECTORY is only set for `bazel run`, not `bazel test`,
# so the fallback is informational only).
find_bin() { # <runfiles-relative path>
    local rel="$1"
    if [ -x "$WS/$rel" ]; then
        printf '%s\n' "$WS/$rel"
        return 0
    fi
    return 1
}

AGENTPVM_BIN="$(find_bin cmd/agentpvm/agentpvm)" \
    || { echo "bazel_run.sh: runfiles binary not found: $WS/cmd/agentpvm/agentpvm" >&2; ls "$WS" >&2 || true; exit 1; }
UMLCTL_BIN="$(find_bin cmd/umlctl/umlctl)" \
    || { echo "bazel_run.sh: runfiles binary not found: $WS/cmd/umlctl/umlctl" >&2; exit 1; }
export AGENTPVM_BIN UMLCTL_BIN

# Suites resolve their own ROOT from $0's location; run the suite from the
# runfiles tree so workspace-relative data (uml/agentpvm.toml) resolves.
exec bash "$WS/tests/$SUITE" "$@"
