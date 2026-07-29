#!/bin/bash
set -ex
echo "Testing Package Installation inside Sandbox..."

# Assuming agentpvm is running with NAT bridge
# We would send a command via E2B API to the sandbox
cat << 'EOF' > test_script.py
import requests

# Send an execution request to the local E2B compatible API
res = requests.post("http://127.0.0.1:8080/exec", json={"cmd": "apk update && apk add python3"})
res.raise_for_status()
print("Response from Agent Sandbox:", res.json())
EOF

python3 test_script.py
