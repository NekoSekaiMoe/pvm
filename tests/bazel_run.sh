#!/usr/bin/env bash
# Bazel sh_test wrapper for the PVM CI-safe suites.
#
# Why this exists: the suites read AGENTPVM_BIN/UMLCTL_BIN from the
# environment, but sh_test.env is evaluated at ANALYSIS time — it cannot
# know the runfiles tree path — and a relative value only resolves when
# cwd IS the runfiles root, which is not guaranteed.
#
# This wrapper runs at EXECUTION time and resolves the binaries through
# the official runfiles library (rlocation), which works in BOTH runfiles
# modes: symlink trees and the manifest mode Bazel defaults to on Linux
# (where bazel-out artifacts have no symlink under $TEST_SRCDIR and plain
# path joins miss them).
#
# Usage (as sh_test src, with the suite name in args): bazel_run.sh <suite.sh>
set -euo pipefail

SUITE="${1:?suite name required}"; shift

# --- official runfiles bootstrap (manifest + symlink modes) ---
runfiles_lib=""
if [ -n "${TEST_SRCDIR:-}" ] && [ -e "$TEST_SRCDIR/../manifest_runfiles_lib.bash" ]; then
    # not a real path; fall through to the canonical locations below
    :
fi
for cand in \
    "${TEST_SRCDIR:-/nonexistent}/_main/../bazel_tools/tools/bash/runfiles/runfiles.bash" \
    "${TEST_SRCDIR:-/nonexistent}/bazel_tools/tools/bash/runfiles/runfiles.bash" \
    "${RUNFILES_DIR:-/nonexistent}/bazel_tools/tools/bash/runfiles/runfiles.bash"; do
    if [ -e "$cand" ]; then runfiles_lib="$cand"; break; fi
done
# bazel_tools is external to the workspace in bzlmod (name "bazel_tools"),
# its runfiles path prefix is _main/../bazel_tools or the workspace alias.
if [ -z "$runfiles_lib" ]; then
    # Last resort: probe rlocation via the test's own runfiles manifest.
    manifest="${RUNFILES_MANIFEST_FILE:-${TEST_SRCDIR:-}/MANIFEST}"
    [ -f "$manifest" ] || { echo "bazel_run.sh: no runfiles library and no manifest at $manifest" >&2; exit 1; }
    rloc() { # <workspace-relative path> -> absolute or empty
        local key="${TEST_WORKSPACE:-_main}/$1" line
        while IFS= read -r line; do
            case "$line" in "$key "*) printf '%s\n' "${line#* }"; return 0;; esac
        done < "$manifest"
        return 1
    }
else
    # shellcheck disable=SC1090
    source "$runfiles_lib"
    rloc() { rlocation "${TEST_WORKSPACE:-_main}/$1"; }
fi

AGENTPVM_BIN="$(rloc cmd/agentpvm/agentpvm)" || true
UMLCTL_BIN="$(rloc cmd/umlctl/umlctl)" || true
[ -n "${AGENTPVM_BIN:-}" ] && [ -x "$AGENTPVM_BIN" ] || {
    echo "bazel_run.sh: runfiles binary not found via rlocation: cmd/agentpvm/agentpvm (lib=${runfiles_lib:-manifest})" >&2
    exit 1
}
[ -n "${UMLCTL_BIN:-}" ] && [ -x "$UMLCTL_BIN" ] || {
    echo "bazel_run.sh: runfiles binary not found via rlocation: cmd/umlctl/umlctl" >&2
    exit 1
}
export AGENTPVM_BIN UMLCTL_BIN

# Resolve the suite path itself (workspace file -> runfiles) and run it
# with bash; the suite computes its own ROOT from $0, landing on the
# runfiles workspace root so workspace-relative data (uml/agentpvm.toml)
# resolves.
SUITE_PATH="$(rloc "tests/$SUITE")"
[ -n "${SUITE_PATH:-}" ] && [ -f "$SUITE_PATH" ] || {
    echo "bazel_run.sh: suite not found in runfiles: tests/$SUITE" >&2
    exit 1
}
exec bash "$SUITE_PATH" "$@"
