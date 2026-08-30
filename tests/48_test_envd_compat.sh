#!/usr/bin/env bash
# 48_test_envd_compat.sh — envd-compatible data plane: 49982 version
# websocket handshake, 49983 Connect-JSON (process.Start sim, filesystem
# methods), raw /files. CI-safe (PVM_EXEC_SIM=1, custom ports).
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

PORT=18048
WSPORT=18148
ENVDPORT=18149
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"
export PVM_EXEC_SIM=1
export PVM_ENVD_ENABLED=1
export PVM_ENVD_WS_PORT=$WSPORT
export PVM_ENVD_PORT=$ENVDPORT

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
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start"

mkdir -p "$PVM_STATE_ROOT/t-envd"
cat > "$PVM_STATE_ROOT/t-envd/state.json" <<EOF
{"id":"t-envd","name":"t-envd","status":"running","pid":99999}
EOF

echo "--- 1. envd healthz answers"
curl -sf "http://127.0.0.1:$ENVDPORT/healthz" | jq -e '.service == "envd"' >/dev/null || fail "envd healthz"

echo "--- 2. filesystem.Filesystem/MakeDir + ListDir"
curl -sf -X POST "http://127.0.0.1:$ENVDPORT/filesystem.Filesystem/MakeDir" \
    -H "X-Task-Id: t-envd" -H "Content-Type: application/json" \
    -d '{"path":"work"}' | jq -e '.entry.type == "DIRECTORY"' >/dev/null || fail "MakeDir"
curl -sf -X POST "http://127.0.0.1:$ENVDPORT/filesystem.Filesystem/ListDir" \
    -H "X-Task-Id: t-envd" -H "Content-Type: application/json" \
    -d '{"path":"."}' | jq -e '.entries[0].name == "work"' >/dev/null || fail "ListDir"

echo "--- 3. raw /files write + read round trip"
curl -sf -X POST "http://127.0.0.1:$ENVDPORT/files?path=work/notes.txt&username=root" \
    -H "X-Task-Id: t-envd" -H "Content-Type: application/octet-stream" \
    --data-binary "envd-body" >/dev/null || fail "raw write"
BODY=$(curl -sf "http://127.0.0.1:$ENVDPORT/files?path=work/notes.txt&username=root" -H "X-Task-Id: t-envd")
[ "$BODY" = "envd-body" ] || fail "raw read got: $BODY"

echo "--- 4. traversal is neutralized"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$ENVDPORT/files?path=../../../etc/passwd&username=root" -H "X-Task-Id: t-envd")
[ "$CODE" = "404" ] || [ "$CODE" = "400" ] || fail "traversal must fail closed, got $CODE"

echo "--- 5. process.Process/Start streams sim output + end + EOS"
python3 - "$ENVDPORT" <<'PYEOF'
import socket, struct, sys, json
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
payload = json.dumps({"process": {"cmd": "/bin/bash", "args": ["-l", "-c", "echo envd-ok"], "envs": {}}, "stdin": False}).encode()
frame = struct.pack(">BI", 0, len(payload)) + payload
req = b"POST /process.Process/Start HTTP/1.1\r\nHost: x\r\nContent-Type: application/connect+json\r\nX-Task-Id: t-envd\r\nConnect-Protocol-Version: 1\r\nContent-Length: "
req += str(len(frame)).encode() + b"\r\n\r\n" + frame
s.sendall(req)
buf = b""
while b"\r\n\r\n" not in buf:
    buf += s.recv(4096)
head, rest = buf.split(b"\r\n\r\n", 1)
# De-chunk (Transfer-Encoding: chunked wraps the Connect frames). The
# terminating 0-chunk means the response ended: after it, do NOT recv again
# (keep-alive would block).
body = b""
response_done = False
while True:
    while b"\r\n" not in rest:
        rest += s.recv(4096)
    size_line, rest = rest.split(b"\r\n", 1)
    size = int(size_line.strip() or b"0", 16)
    if size == 0:
        response_done = True
        break
    while len(rest) < size + 2:
        rest += s.recv(4096)
    body += rest[:size]
    rest = rest[size+2:]  # chunk data + CRLF
# Parse Connect frames until EOS (or response end).
while True:
    if len(body) >= 5:
        flags = body[0]
        n = struct.unpack(">I", body[1:5])[0]
        if len(body) >= 5 + n:
            frame_payload = body[5:5+n]
            body = body[5+n:]
            if flags & 0x02:
                break
            ev = json.loads(frame_payload)
            if "event" in ev and "data" in ev["event"]:
                import base64
                out = base64.b64decode(ev["event"]["data"].get("stdout", "")).decode()
                if "simulated" in out and "envd-ok" in out:
                    print("STREAM_OK")
                    continue
            if "event" in ev and "end" in ev["event"]:
                assert ev["event"]["end"]["exitCode"] == 0, "exit code"
    if response_done or len(body) == 0:
        if response_done:
            break
    chunk = s.recv(4096)
    if not chunk:
        break
    body += chunk
PYEOF

echo "--- 6. version websocket handshake (49982-equivalent port)"
python3 - "$WSPORT" <<'PYEOF'
import socket, base64, hashlib, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
key = base64.b64encode(b"0123456789abcdef").decode()
s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
data = b""
while b"\r\n\r\n" not in data:
    data += s.recv(4096)
head = data.split(b"\r\n\r\n")[0].decode()
assert "101" in head.split("\r\n")[0], head
expect = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
assert expect in head, "bad accept key"
# First frame: version JSON.
body = data.split(b"\r\n\r\n", 1)[1]
while len(body) < 2:
    body += s.recv(4096)
opcode = body[0] & 0x0F
n = body[1] & 0x7F
while len(body) < 2 + n:
    body += s.recv(4096)
payload = body[2:2+n]
assert opcode == 1 and b"envd" in payload, (opcode, payload)
print("WS_OK")
PYEOF

echo "✅ 48 envd compat suite passed"
