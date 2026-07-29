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

echo "Sending execution request to E2B API..."
HTTP_STATUS=$(curl -s -o resp.json -w "%{http_code}" -X POST http://127.0.0.1:8081/exec \
  -H "Content-Type: application/json" \
  -d '{"cmd": "apk update && apk add python3"}')

echo "API Response:"
cat resp.json

if [ "$HTTP_STATUS" != "200" ]; then
    echo "❌ E2B API Test Failed: HTTP status $HTTP_STATUS"
    exit 1
fi

if ! grep -q '"exitCode"' resp.json; then
    echo "❌ E2B API Test Failed: Missing exitCode in JSON response"
    exit 1
fi

echo "✅ E2B API Test Passed"
