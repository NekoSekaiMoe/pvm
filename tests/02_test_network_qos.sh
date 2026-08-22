#!/bin/bash
set -eo pipefail

echo "========== Test 02: Network QoS and SSRF (Dry Run) =========="

go build -o agentpvm cmd/agentpvm/main.go

# Since we might not be root in all CI environments, we just test if the CLI parses 
# the QoS and Whitelist commands correctly.

echo "Testing QoS Configuration CLI..."
# Dry-run CI has no root and no tap_test device, so the tc call is EXPECTED
# to fail at the environment level. What must NOT happen is a CLI-level
# failure (bad flags, rate rejected by the whitelist regex): capture the
# output and accept only success or the tc-level error.
QOS_OUT=$(./agentpvm network qos tap_test 10mbit 2>&1) && QOS_RC=0 || QOS_RC=$?
echo "$QOS_OUT"
case "$QOS_OUT" in
    *"failed to setup QoS"*|"")
        echo "✅ QoS CLI structure passed (tc-level failure is expected without root/tap)"
        ;;
    *)
        echo "❌ QoS CLI failed unexpectedly (rc=$QOS_RC)"
        exit 1
        ;;
esac

echo "Testing eBPF Whitelist Configuration CLI..."
# Without root / a pinned bpffs map (typical CI) the update must fail
# gracefully with a clear error; with a live map it must succeed. Either
# outcome proves the CLI parsed and dispatched the command correctly.
WL_OUT=$(./agentpvm network whitelist add api.openai.com 198.51.100.1 2>&1) || true
echo "$WL_OUT"
case "$WL_OUT" in
    *"Whitelist updated"*|*"Whitelist Error: failed to open pinned map"*)
        echo "✅ eBPF Whitelist CLI structure passed (pinned-map failure is expected without root/bpffs)"
        ;;
    *)
        echo "❌ Whitelist CLI failed unexpectedly"
        exit 1
        ;;
esac

echo "Note: Full eBPF TC attaching requires root and valid netdev, verified in Go unit tests."
