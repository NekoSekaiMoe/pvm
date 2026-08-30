#!/usr/bin/env bash
# 51_test_deploy_artifacts.sh — offline validation of the deploy surface:
# install.sh syntax, compose/openapi YAML, systemd unit shape, deploy check
# script, webui i18n parity.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "❌ $1"; exit 1; }

echo "--- 1. shell scripts parse"
bash -n deploy/install.sh || fail "install.sh syntax"
for f in tests/*.sh; do bash -n "$f" || fail "$f syntax"; done

echo "--- 2. YAML artifacts parse"
python3 - <<'PYEOF' || exit 1
import yaml
for p in ("deploy/docker-compose.yml", "api/openapi.yaml"):
    with open(p) as f:
        yaml.safe_load(f)
    print(p, "OK")
PYEOF

echo "--- 3. systemd units carry the hardening contract"
for u in deploy/systemd/*.service; do
    grep -q "Type=simple" "$u" || fail "$u Type"
    grep -q "EnvironmentFile=" "$u" || fail "$u EnvironmentFile"
    grep -q "Restart=on-failure" "$u" || fail "$u Restart"
    grep -q "NoNewPrivileges=true" "$u" || fail "$u NoNewPrivileges"
done

echo "--- 4. deploy surface check script runs green"
# The Makefile (and its deploy-check target) was removed with the deploy
# restructure; scripts/check_openapi.sh is the structural check now.
bash scripts/check_openapi.sh || fail "check_openapi.sh"

echo "--- 5. webui i18n parity"
node webui/test/i18n_parity.mjs >/dev/null || fail "i18n parity"

echo "--- 6. openapi covers the new endpoints"
for route in "/api/identity" "/api/incidents" "/metrics" "/healthz" "/version" "/api/exec" "/api/templates/{id}/build" "/api/tasks/{id}/metrics" "/api/tasks/{id}/console" "/api/approvals/{id}/edit"; do
    grep -q "$route" api/openapi.yaml || fail "openapi missing $route"
done

echo "✅ 51 deploy artifacts suite passed"
