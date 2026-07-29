#!/bin/bash
set -eo pipefail

echo "========== Test 01: E2B API Simulation =========="

# Build the CLI
go build -o agentpvm cmd/agentpvm/main.go

# Start the API server in the background
./agentpvm api -port 8081 &
API_PID=$!

# Give it a second to start
sleep 1

echo "Sending execution request to E2B API..."
RESPONSE=$(curl -s -X POST http://127.0.0.1:8081/exec \
  -H "Content-Type: application/json" \
  -d '{"cmd": "apk update && apk add python3"}')

echo "API Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "Execution simulated for: apk update"; then
    echo "✅ E2B API Test Passed"
else
    echo "❌ E2B API Test Failed"
    kill $API_PID
    exit 1
fi

kill $API_PID
