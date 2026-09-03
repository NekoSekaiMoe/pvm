#!/usr/bin/env bash
# check-arm64.sh — verify the tree builds natively on both endiannesses.
#
# PVM is architecture-portable by construction: the UML guest kernel is
# separately built per arch (scripts/build_kernel.sh), the jail carries
# per-arch seccomp syscall tables (seccomp_amd64.go / seccomp_arm64.go),
# and the eBPF objects are regenerated per host by bpf2go. This script
# type-checks the Go tree for BOTH amd64 and arm64 so a stray amd64-only
# path cannot land silently.
#
# Usage: ./scripts/check-arm64.sh   (from the repo root)
# Exit codes: 0 = both arches build (or explicit SKIP); 1 = failure.
# Env: PVM_GO=<path> forces the toolchain. When NO Go can be found (PATH
# plus the usual install roots) the script prints a SKIP line and exits 0:
# the dual-arch compile is still exercised for real by the ci.yml go legs
# (setup-go on amd64 AND arm64 runners), while environments that only
# build via Bazel's hermetic SDK (the bazel job never installs a system
# Go) get an explicit, greppable skip instead of a false failure.
set -euo pipefail
cd "$(dirname "$0")/.."

# A runfiles tree (Bazel symlink mode) materializes only declared data —
# no go.mod, no sources — so a real dual-arch build is impossible there.
# Distinguish that from a genuine build failure explicitly.
if [ ! -f go.mod ]; then
    echo "[arm64-check] SKIP: no go.mod next to the script (runfiles tree without sources)"
    exit 0
fi

# A plain `go build` also needs two generated inputs Bazel produces into
# its own output tree, never into the source checkout: the Nuxt static
# assets (webui/embed.go's all:.output/public embed pattern) and the
# bpf2go shims (internal/network/{bpf,tapdp}_bpfel.go — gitignored by
# design; `go generate ./...` materializes them). A fresh checkout and
# the Bazel CI job have neither, so a plain-go dual-arch build there is
# not a broken tree, it is a missing prerequisite — skip explicitly. The
# ci.yml go legs run `nuxt generate` + `go generate` before the suites,
# so the real dual-arch check still executes on amd64 and arm64.
if [ ! -d webui/.output/public ] || [ ! -f internal/network/bpf_bpfel.go ] || [ ! -f internal/network/tapdp_bpfel.go ]; then
    echo "[arm64-check] SKIP: generated inputs missing (webui/.output/public, bpf2go shims); run 'nuxt generate' + 'go generate ./...' first, or rely on the ci.yml go legs"
    exit 0
fi

# --- resolve a Go toolchain -------------------------------------------------
# Bazel sh_test actions run with a scrubbed environment (PATH cut to
# /bin:/usr/bin, HOME unset), so a bare `go` is unreachable even on images
# that ship one. Probe PATH first, then the common distro/CI roots.
GO_BIN="${PVM_GO:-}"
if [ -z "$GO_BIN" ]; then
    if command -v go >/dev/null 2>&1; then
        GO_BIN=go
    else
        for cand in \
            /usr/local/go/bin/go \
            /usr/local/bin/go \
            /usr/lib/go/bin/go \
            /usr/lib/go-*/bin/go \
            /opt/go/bin/go \
            /snap/bin/go \
            "${HOME:-/nonexistent}/sdk"/go*/bin/go; do
            if [ -x "$cand" ]; then GO_BIN="$cand"; break; fi
        done
    fi
fi
if [ -z "$GO_BIN" ]; then
    echo "[arm64-check] SKIP: no go toolchain on PATH or in the usual roots"
    exit 0
fi

# --- make `go` runnable under a scrubbed env --------------------------------
# go refuses to start when HOME/GOCACHE are undefined, and cross-builds
# need a writable module cache; point both at a scratch dir only when the
# environment does not provide them.
if [ -z "${HOME:-}" ]; then
    HOME="$(mktemp -d)"
    export HOME
fi
: "${GOCACHE:=$HOME/.cache/go-build}"
: "${GOPATH:=$HOME/go}"
export GOCACHE GOPATH
mkdir -p "$GOCACHE" "$GOPATH" 2>/dev/null || true

fail=0
# Private log dir (not fixed /tmp names: a pre-created symlink at a
# predictable path would redirect our output to an arbitrary file).
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT
for arch in amd64 arm64; do
  if GOARCH="$arch" CGO_ENABLED=0 "$GO_BIN" build ./cmd/agentpvm ./cmd/umlctl 2>"$LOG_DIR/build-$arch.log"; then
    echo "[arm64-check] GOARCH=$arch: OK"
  else
    echo "[arm64-check] GOARCH=$arch: FAILED" >&2
    sed 's/^/  | /' "$LOG_DIR/build-$arch.log" >&2
    fail=1
  fi
done
# The eBPF shims compile only on linux; vet them on the native arch too.
if ! "$GO_BIN" vet ./internal/network/ ./internal/jail/ 2>"$LOG_DIR/vet.log"; then
  echo "[arm64-check] vet FAILED" >&2
  sed 's/^/  | /' "$LOG_DIR/vet.log" >&2
  fail=1
fi
exit "$fail"
