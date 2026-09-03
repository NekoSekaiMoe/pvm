#!/usr/bin/env bash
# 58_test_console_sse_and_ops.sh — SSE console stream contract + the
# operator tooling selftests, wired as one suite.
# Covers: /api/tasks/:id/console/stream 404 for unknown tasks (the live
# stream itself needs a booted guest — kernel-adjacent), deploy/collect-logs.sh
# selftest (redaction bundle), scripts/bench.sh selftest (dry-run command
# generation), scripts/check-arm64.sh dual-arch build, and the OpenAPI
# structural check.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18058
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1 || fail "server failed to start: $(cat "$TMP/server.log")"

echo "--- 1. SSE stream: unknown task → 404"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "$API/tasks/ghost/console/stream")
[ "$CODE" = "404" ] || fail "SSE unknown task must 404, got $CODE"

echo "--- 2. SSE stream: known task without a console session → 404"
mkdir -p "$PVM_STATE_ROOT/sse-t"
printf '{"id":"sse-t","name":"sse-t","status":"running"}\n' > "$PVM_STATE_ROOT/sse-t/state.json"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "$API/tasks/sse-t/console/stream")
[ "$CODE" = "404" ] || fail "session-less task must 404, got $CODE"

echo "--- 3. metrics expose the new collectors (render hooks)"
BODY=$(curl -sf -H "$AUTH" "http://127.0.0.1:$PORT/metrics")
for series in pvm_tasks pvm_task_cpu_seconds_total pvm_task_memory_rss_bytes pvm_templates pvm_volumes pvm_pool_ready pvm_pool_claimed pvm_pool_total; do
    echo "$BODY" | grep -q "$series" || fail "metrics missing $series"
done

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""

echo "--- 4. collect-logs.sh selftest (redacted diagnostic bundle)"
./deploy/collect-logs.sh --selftest > "$TMP/collect.log" 2>&1 || fail "collect-logs selftest failed: $(tail -5 "$TMP/collect.log")"
grep -q "selftest: PASS" "$TMP/collect.log" || fail "collect-logs selftest did not PASS"

echo "--- 5. bench.sh selftest (dry-run command generation)"
./scripts/bench.sh --selftest > "$TMP/bench.log" 2>&1 || fail "bench selftest failed: $(tail -5 "$TMP/bench.log")"
grep -q "selftest: PASS" "$TMP/bench.log" || fail "bench selftest did not PASS"

echo "--- 6. dual-architecture build check"
./scripts/check-arm64.sh > "$TMP/arch.log" 2>&1 || fail "arm64 check failed: $(cat "$TMP/arch.log")"
if grep -q "\[arm64-check\] SKIP:" "$TMP/arch.log"; then
    # Bazel CI has no system Go (its binaries come from rules_go's
    # hermetic SDK); the dual-arch compile is covered by the ci.yml go
    # legs on amd64+arm64 runners. check-arm64.sh exits 0 with this line.
    echo "    (skipped: no go toolchain in this environment)"
else
    grep -q "GOARCH=amd64: OK" "$TMP/arch.log" || fail "amd64 build not OK"
    grep -q "GOARCH=arm64: OK" "$TMP/arch.log" || fail "arm64 build not OK"
fi

echo "--- 7. OpenAPI structural check"
bash scripts/check_openapi.sh api/openapi.yaml > "$TMP/openapi.log" 2>&1 || fail "openapi check failed: $(cat "$TMP/openapi.log")"
grep -q "openapi-check OK" "$TMP/openapi.log" || fail "openapi check did not pass"

echo "✅ 58_test_console_sse_and_ops.sh passed"
