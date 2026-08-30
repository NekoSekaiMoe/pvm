#!/usr/bin/env bash
# 52_test_registry_policy.sh — registry allowlist fast-fail and insecure
# gating (both evaluated BEFORE any root/network work, so CI-safe).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "❌ $1"; exit 1; }

if [ -n "${UMLCTL_BIN:-}" ]; then
    cp "$UMLCTL_BIN" "$TMP/umlctl"
else
    go build -o "$TMP/umlctl" ./cmd/umlctl
fi

echo "--- 1. allowlisted registry only"
OUT=$(PVM_REGISTRY_ALLOWLIST="good.example.com" "$TMP/umlctl" image pull "evil.example.com/img:1" 2>&1 || true)
echo "$OUT" | grep -q "allowlist" || fail "non-allowlisted registry must fail with allowlist error: $OUT"
# The failure must be the allowlist fast-fail, not a permission error:
# policy checks run BEFORE the privilege check, so "requires root" here
# would mean the fast-fail never fired.
if echo "$OUT" | grep -q "requires root"; then
    fail "allowlist check must fast-fail before the root check: $OUT"
fi

echo "--- 2. explicit http:// scheme is honored (fails on network, not policy)"
OUT=$(PVM_REGISTRY_ALLOWLIST="good.example.com" "$TMP/umlctl" image pull "http://good.example.com/img:1" 2>&1 || true)
if echo "$OUT" | grep -q "allowlist"; then
    fail "http:// host on the allowlist must not be rejected by policy: $OUT"
fi
# Expect a later-stage failure (root/network/permissions) — the policy
# gate passed.
echo "$OUT" | grep -qE "requires root|crane|network|dial|no such host|unreachable|permission denied" || fail "expected a non-policy failure: $OUT"

echo "--- 3. wildcard allowlist accepts any host"
OUT=$(PVM_REGISTRY_ALLOWLIST="*" "$TMP/umlctl" image pull "any.example.org/img:1" 2>&1 || true)
echo "$OUT" | grep -q "allowlist" && fail "wildcard must not produce allowlist errors: $OUT" || true

echo "--- 4. unit matrix for the insecure transport gating"
go test ./internal/image/ -run "TestInsecureEnabled|TestRegistryHostPort|TestSchemeRewrite|TestSparse" >/dev/null || fail "image unit matrix"

echo "✅ 52 registry policy suite passed"
