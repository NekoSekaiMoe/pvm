#!/bin/bash
set -eo pipefail

echo "========== Test 01: E2B API Simulation =========="

# Build the CLI
go build -o agentpvm cmd/agentpvm/main.go

# Start the API server in the background
./agentpvm api -port 8081 &
API_PID=$!

trap "kill $API_PID && wait $API_PID 2>/dev/null || true" EXIT

# Readiness retry loop
for i in {1..10}; do
    if curl -s -f http://127.0.0.1:8081/ > /dev/null 2>&1 || curl -s http://127.0.0.1:8081/ > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

echo "Sending execution request to E2B API (no task id -> must be rejected)..."
HTTP_STATUS=$(curl -s -o resp.json -w "%{http_code}" -X POST http://127.0.0.1:8081/api/exec \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer secret" \
  -d '{"cmd": "apk update && apk add python3"}')

echo "API Response:"
cat resp.json

# /exec is now the Tool/Policy Gateway (plan.md §6). Without a task id it must
# reject with 400 (not the old 501 mock). 403 is also acceptable if a gateway
# is registered but denies; both indicate the endpoint is live and gating.
if [ "$HTTP_STATUS" != "400" ] && [ "$HTTP_STATUS" != "403" ]; then
    echo "❌ E2B API Test Failed: HTTP status $HTTP_STATUS (expected 400 or 403)"
    exit 1
fi

echo "✅ E2B API Test Passed"
