#!/usr/bin/env bash
# 31_test_jail_root_privileges.sh — Privileged test for UserNS/MountNS process isolation
# and Landlock LSM lockdown under root/sudo privileges.
# Requires: root or passwordless sudo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$(id -u)" -ne 0 ]; then
    if ! sudo -n true 2>/dev/null; then
        echo "⚠️  Skipping 31_test_jail_root_privileges.sh (requires root or passwordless sudo)"
        exit 0
    fi
    SUDO="sudo"
else
    SUDO=""
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Running privileged jail & namespace isolation tests (as root)"

# Run Go jail tests under sudo
$SUDO go test -v -run "TestConfigureProcessIsolation|TestLandlock|TestSeccomp" ./internal/jail

echo "✅ 31_test_jail_root_privileges.sh PASSED"
