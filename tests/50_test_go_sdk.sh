#!/usr/bin/env bash
# 50_test_go_sdk.sh — the official Go SDK builds and drives a live server:
# health/version, E2B sandbox list, template create+build-status, exec
# approval sentinel, approvals/identity/incidents/pool round trips.
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
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_TEMPLATE_ROOT"
dd if=/dev/zero of="$TMP/base.img" bs=1024 count=64 2>/dev/null

PORT=18050
export API_SECRET="secret"
export PVM_API_KEY="secret"
export PVM_API_URL="http://127.0.0.1:$PORT"
export PVM_EXEC_SIM=1

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf "$PVM_API_URL/healthz" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf "$PVM_API_URL/healthz" >/dev/null || fail "server failed to start"

echo "--- 1. SDK example program builds + runs the full surface"
cat > "$TMP/sdk_demo.go" <<'GEOF'
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	sdk "uml-container/sdk/go"
)

func main() {
	cfg := sdk.NewConfigFromEnv()
	if cfg.APIURL == "" {
		cfg.APIURL = os.Getenv("PVM_API_URL")
	}
	c := sdk.NewClient(cfg)
	ctx := context.Background()

	if err := c.Health(ctx); err != nil {
		fatal("health", err)
	}
	v, err := c.Version(ctx)
	fatal("version", err)
	fmt.Println("version:", v.Version)

	sbs, err := c.ListSandboxes(ctx)
	fatal("sandboxes", err)
	fmt.Println("sandboxes:", len(sbs))

	// Template build pipeline via SDK.
	tpl, err := c.CreateTemplate(ctx, os.Getenv("ROOTFS"), "")
	fatal("template", err)
	st, err := c.WaitForTemplateReady(ctx, tpl.TemplateID, 20*time.Second)
	fatal("wait template", err)
	fmt.Println("template:", st.Phase)

	// Exec approval sentinel via sim gateway.
	_, err = c.Exec(ctx, "t-sdk", "noop")
	if err == nil {
		fatal("exec", errors.New("no gateway: expected error"))
	}
	fmt.Println("exec (no gateway):", err)

	// Approval plane.
	list, err := c.ListApprovals(ctx, "")
	fatal("approvals", err)
	fmt.Println("approvals:", len(list))

	// Identity plane.
	tok, _, err := c.MintToken(ctx, "t-sdk", []string{"repo:read"}, "5m")
	fatal("mint", err)
	fresh, err := c.RefreshToken(ctx, tok)
	fatal("refresh", err)
	n, err := c.RevokeAllTokens(ctx, "t-sdk")
	fatal("revoke", err)
	fmt.Println("identity: mint+refresh ok, revoked", n, "fresh==old:", fresh == tok)

	// Incidents + pool.
	act, err := c.ReportIncident(ctx, "t-sdk", "low", "sdk", "test")
	fatal("incident", err)
	fmt.Println("incident action:", act)
	inc, err := c.ListIncidents(ctx)
	fatal("incidents", err)
	fmt.Println("incidents:", len(inc))
	created, err := c.WarmPool(ctx, "tpl-sdk", 1)
	fatal("warm", err)
	fmt.Println("warmed:", created)
	ps, err := c.GetPoolStats(ctx)
	fatal("pool stats", err)
	fmt.Println("pool:", ps.Ready, "/", ps.Total)

	fmt.Println("SDK_OK")
}

func fatal(stage string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "stage", stage+":", err)
		os.Exit(1)
	}
}
GEOF
(cd "$ROOT" && ROOTFS="$TMP/base.img" go run "$TMP/sdk_demo.go") > "$TMP/sdk.out" 2>&1 || { cat "$TMP/sdk.out"; fail "sdk demo run"; }
grep -q "SDK_OK" "$TMP/sdk.out" || { cat "$TMP/sdk.out"; fail "SDK_OK marker missing"; }
grep -q "template: done" "$TMP/sdk.out" || { cat "$TMP/sdk.out"; fail "template build must reach done"; }

echo "--- 2. envd client envelope codec via go test (already unit-covered; sanity)"
go test ./sdk/go/ >/dev/null || fail "sdk/go unit tests"

echo "✅ 50 go sdk suite passed"
