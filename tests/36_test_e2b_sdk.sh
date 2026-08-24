#!/usr/bin/env bash
# 36_test_e2b_sdk.sh — drive PVM's /sandboxes compatibility surface with the
# REAL official E2B JS SDK (@e2b/sdk), turning the README's "E2B compatible"
# claim into an executable assertion. The SDK pins its API host to
# http://localhost:3000 when E2B_DEBUG=1, so agentpvm runs on port 3000.
#
# Covers: X-API-KEY auth, list shape, create/kill error contracts — the
# subset drivable WITHOUT a UML kernel or a guest envd daemon (see
# internal/api/e2b_compat.go for the full-lifecycle envd caveat).
# Kernel-free and CI-safe; requires node + npm and skips gracefully without
# them (or when npm cannot reach the registry).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v node >/dev/null 2>&1 || { echo "SKIP: node not installed"; exit 0; }
command -v npm  >/dev/null 2>&1 || { echo "SKIP: npm not installed";  exit 0; }

echo "==> installing @e2b/sdk (tests/e2b_sdk)"
if ! (cd tests/e2b_sdk && npm install --no-audit --no-fund --silent); then
    echo "SKIP: npm install failed (offline registry?)"
    exit 0
fi

TMP="$(mktemp -d)"
# SRV is only assigned once the server starts; under set -u an early EXIT
# (e.g. build failure) must not trip on an unbound SRV, and TMP cleanup must
# always run.
trap 'if [ -n "${SRV:-}" ]; then kill "$SRV" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"
# The server refuses to start without a secret (no default credential).
export API_SECRET="secret"

# E2B_DEBUG=1 hardcodes the SDK's API host to http://localhost:3000.
PORT=3000

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

echo "==> starting agentpvm api on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "X-API-KEY: secret" "http://127.0.0.1:$PORT/sandboxes" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

echo "==> running @e2b/sdk driver against PVM"
E2B_DEBUG=1 E2B_API_KEY=secret node tests/e2b_sdk/driver.mjs

echo "✓ e2b SDK compatibility test passed"
