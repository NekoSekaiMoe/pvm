#!/usr/bin/env bash
# 61_test_egress_real_enforcement.sh — egress 真断言伴生（对应 02/34/35 sim）。
# 不断言 CLI 形状，断言 fail-closed：
#   1. 未 allowlisted 的外连在控制面即被拒绝（非 allowlisted 不学习、不放行），且有审计行；
#   2. 无 pinned map 时 whitelist 写入必须报 typed pinned-map 错误（绝不静默放行）；
#   3. 同一 host 在 task 间隔离：A task 学到的条目在 B task 不可见。
# CI-safe：无内核、无 root、无真 DNS；用 34 同款 python3 fake upstream。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
DNS=""
trap 'if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; fi; if [ -n "$DNS" ]; then kill "$DNS" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

command -v python3 >/dev/null || { echo "SKIP: python3 not available"; exit 0; }

PORT=18061
API="http://127.0.0.1:$PORT/api"
API_SECRET="egress-real-$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

# Print the failure message in $1 to stdout and exit the script with status 1.
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

# Loopback DNS fixture: bind before publishing the chosen port to the test.
python3 - "$TMP/dns-port" <<'PYDNS' &
import socket, struct, sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    with open(sys.argv[1], "w") as ready:
        ready.write(str(sock.getsockname()[1]))
    while True:
        data, peer = sock.recvfrom(4096)
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 5  # null terminator, QTYPE, QCLASS
        header = data[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
                  + socket.inet_aton("93.184.216.34"))
        sock.sendto(header + data[12:end] + answer, peer)
PYDNS
DNS=$!
for _ in $(seq 1 40); do
    [ -s "$TMP/dns-port" ] && break
    sleep 0.05
done
[ -s "$TMP/dns-port" ] || fail "fake DNS failed to start"
UPSTREAM_PORT=$(cat "$TMP/dns-port")

echo "--- 1. 非 allowlisted 域名不学习：learned 为空且有拒绝审计"
curl -sf -X PUT "$API/egress/t-egr-a/policy" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"allow_domains":["allowed.example"],"dns_learn_enabled":true,"learn_ttl":"60s","dns_upstream":"127.0.0.1:'"$UPSTREAM_PORT"'"}' >/dev/null || fail "policy put"
LEARNED=$(curl -sf -H "$AUTH" "$API/egress/t-egr-a/learned")
echo "$LEARNED" | jq -e '.entries | length == 0' >/dev/null || fail "nothing learned yet: $LEARNED"
BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/egress/t-egr-a/allow" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"host":"evil.example","ip":"198.51.100.9"}')
case "$BAD" in 400|403|404|422) : ;; *) fail "non-allowlisted allow must be rejected, got $BAD" ;; esac
LEARNED2=$(curl -sf -H "$AUTH" "$API/egress/t-egr-a/learned")
echo "$LEARNED2" | jq -e 'any(.entries[]; .domain == "evil.example") | not' >/dev/null || fail "evil must not be learned: $LEARNED2"

echo "--- 2. 无 pinned map 时 whitelist 写入 fail-closed（typed 错误，非静默放行）"
if [ -n "${AGENTPVM_BIN:-}" ]; then cp "$AGENTPVM_BIN" "$TMP/wl"; else go build -o "$TMP/wl" ./cmd/agentpvm; fi
WL_STATUS=0
WL_OUT=$("$TMP/wl" network whitelist add t-egr-nomap 198.51.100.1 2>&1) || WL_STATUS=$?
[ "$WL_STATUS" -ne 0 ] || fail "whitelist without pinned map must exit nonzero: $WL_OUT"
echo "$WL_OUT"
case "$WL_OUT" in
    *"Whitelist Error: network: failed to open pinned map "*)
        echo "   fail-closed typed error ✓" ;;
    *) fail "whitelist without pinned map must fail closed, got: $WL_OUT" ;;
esac

echo "--- 3. task 间隔离：A 学到的 B 不可见"
curl -sf -X PUT "$API/egress/t-egr-b/policy" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"allow_domains":["allowed.example"],"dns_learn_enabled":true,"learn_ttl":"60s","dns_upstream":"127.0.0.1:'"$UPSTREAM_PORT"'"}' >/dev/null || fail "policy put b"
curl -sf -X POST "$API/egress/t-egr-a/allow" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"domain":"allowed.example"}' | jq -e '.learned > 0' >/dev/null || fail "task A must learn allowed.example"
LA=$(curl -sf -H "$AUTH" "$API/egress/t-egr-a/learned")
echo "$LA" | jq -e 'any(.entries[]; .domain == "allowed.example" and .ip == "93.184.216.34")' >/dev/null \
    || fail "allowed entry must be visible in task A: $LA"
LB=$(curl -sf -H "$AUTH" "$API/egress/t-egr-b/learned")
echo "$LB" | jq -e 'any(.entries[]; .domain == "allowed.example" and .ip == "93.184.216.34") | not' >/dev/null || fail "cross-task leak: $LB"

echo "✅ 61 egress real enforcement suite passed"
