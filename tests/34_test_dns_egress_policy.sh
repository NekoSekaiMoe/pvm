#!/usr/bin/env bash
# 34_test_dns_egress_policy.sh — E2E test for DNS-learned domain egress policy.
# Covers: (a) PUT /api/egress/:task/policy creates a control-plane learner,
# (b) DNS answers for allowlisted domains are learned (via fake upstream +
# real wire-format DNS query through the learner's UDP proxy), (c)
# non-allowlisted domains are NOT learned, (d) dns:learn / dns:expire audit
# rows, (e) TTL expiry + sweeper, (f) DELETE learned/:host, (g) per-task
# isolation, (h) validation of bad learn_ttl (API + spec load-spec).
# CI-safe: no kernel, no root, no real DNS — a python3 fake upstream answers
# on loopback. Skips gracefully without python3.
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

PORT=18097
export PVM_API="http://127.0.0.1:$PORT"
API="$PVM_API/api"
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

fail() { echo "❌ $1"; exit 1; }

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT"
"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/containers" >/dev/null || fail "server failed to start: $(cat "$TMP/server.log")"

req() { # method path [json-body]
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}

# ---- fake upstream DNS + tiny query client -------------------------------
UPSTREAM_PORT=15353
cat > "$TMP/fakedns.py" <<'PY'
import socket, struct, sys

ANSWERS = {
    b"allowed.example.com": ("93.184.216.34", 300),
    b"other.net": ("93.184.216.35", 300),
}

def qname(buf):
    out, i = b"", 12
    while buf[i] != 0:
        n = buf[i]; i += 1
        out += buf[i:i+n] + b"."; i += n
    return out[:-1], i + 5  # skip null + qtype + qclass

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data, peer = s.recvfrom(4096)
        try:
            name, end = qname(data)
            question = data[12:end]
            ip, ttl = ANSWERS.get(name, ("93.184.216.99", 60))
            hdr = struct.pack(">HHHHHH", struct.unpack(">H", data[:2])[0],
                              0x8180, 1, 1, 0, 0)
            ans = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4)
                   + socket.inet_aton(ip))
            s.sendto(hdr + question + ans, peer)
        except Exception:
            pass

def query(addr, name):
    host, port = addr.rsplit(":", 1)
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, (host, int(port)))
    s.recvfrom(4096)

if sys.argv[1] == "serve":
    serve(int(sys.argv[2]))
else:
    query(sys.argv[2], sys.argv[3])
PY

echo "==> starting fake upstream DNS on 127.0.0.1:$UPSTREAM_PORT"
python3 "$TMP/fakedns.py" serve "$UPSTREAM_PORT" &
DNS=$!
sleep 0.3

echo "--- 1. PUT policy creates control-plane learner w/ proxy addr"
RESP=$(req PUT "/egress/tk-dns-a/policy" '{
  "dns_learn_enabled": true,
  "dns_upstream": "127.0.0.1:'"$UPSTREAM_PORT"'",
  "allow_domains": ["allowed.example.com"],
  "learn_ttl": "3s"
}')
echo "$RESP" | grep -q '"dns_addr"' || fail "policy create missing dns_addr: $RESP"
DNS_ADDR=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["dns_addr"])')
[ -n "$DNS_ADDR" ] && [ "$DNS_ADDR" != "null" ] || fail "empty dns_addr: $RESP"
echo "   learner up at $DNS_ADDR ✓"

echo "--- 2. allowlisted domain is learned from the DNS wire answer"
python3 "$TMP/fakedns.py" query "$DNS_ADDR" "allowed.example.com"
sleep 0.5
LEARNED=$(req GET "/egress/tk-dns-a/learned")
echo "$LEARNED" | grep -q "93.184.216.34" || fail "expected learned IP 93.184.216.34: $LEARNED"
echo "   learned 93.184.216.34 ✓"

echo "--- 3. non-allowlisted domain resolves but is NOT learned"
python3 "$TMP/fakedns.py" query "$DNS_ADDR" "other.net"
sleep 0.5
LEARNED=$(req GET "/egress/tk-dns-a/learned")
if echo "$LEARNED" | grep -q "93.184.216.35"; then
    fail "non-allowlisted domain was learned: $LEARNED"
fi
echo "   other.net not learned ✓"

echo "--- 4. dns:learn audit row present in the per-task ledger"
LEDGER="$PVM_AUDIT_ROOT/tk-dns-a/ledger.jsonl"
[ -f "$LEDGER" ] || fail "ledger missing at $LEDGER"
grep -q '"dns:learn"' "$LEDGER" || fail "no dns:learn row: $(cat "$LEDGER")"
echo "   dns:learn recorded ✓"

echo "--- 5. TTL expiry: learn_ttl=3s entry is swept"
sleep 4
LEARNED=$(req GET "/egress/tk-dns-a/learned")
if echo "$LEARNED" | grep -q "93.184.216.34"; then
    fail "expired entry still present after learn_ttl: $LEARNED"
fi
grep -q '"dns:expire"' "$LEDGER" || fail "no dns:expire row after expiry"
echo "   entry expired + dns:expire recorded ✓"

echo "--- 6. DELETE learned/:host drops entries"
python3 "$TMP/fakedns.py" query "$DNS_ADDR" "allowed.example.com"
sleep 0.5
RESP=$(req DELETE "/egress/tk-dns-a/learned/allowed.example.com")
echo "$RESP" | grep -q '"dropped":[1-9]' || fail "expected dropped>=1: $RESP"
LEARNED=$(req GET "/egress/tk-dns-a/learned")
if echo "$LEARNED" | grep -q "93.184.216.34"; then
    fail "entry still present after DELETE: $LEARNED"
fi
echo "   DELETE dropped the entry ✓"

echo "--- 7. per-task isolation: same domain not learned for another task"
req PUT "/egress/tk-dns-b/policy" '{
  "dns_learn_enabled": true,
  "dns_upstream": "127.0.0.1:'"$UPSTREAM_PORT"'",
  "allow_domains": ["unrelated.org"],
  "learn_ttl": "30s"
}' >/dev/null
RESP=$(req PUT "/egress/tk-dns-b/policy" '{}')
DNS_ADDR_B=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["dns_addr"])')
python3 "$TMP/fakedns.py" query "$DNS_ADDR_B" "allowed.example.com"
sleep 0.5
LEARNED_B=$(req GET "/egress/tk-dns-b/learned")
if echo "$LEARNED_B" | grep -q "93.184.216.34"; then
    fail "domain leaked into tk-dns-b (not on its allowlist): $LEARNED_B"
fi
echo "   tk-dns-b unaffected ✓"

echo "--- 8. validation: bad learn_ttl rejected by API"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$API/egress/tk-dns-c/policy" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"dns_learn_enabled": true, "learn_ttl": "not-a-duration"}')
[ "$CODE" = "400" ] || fail "expected 400 for bad learn_ttl, got $CODE"
echo "   API 400 ✓"

echo "--- 9. validation: bad learn_ttl rejected by spec load-spec"
cat > "$TMP/bad.toml" <<EOF
[task]
name = "tk-dns-bad"
[network]
enabled = true
dns_learn_enabled = true
learn_ttl = "not-a-duration"
EOF
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/tasks/load-spec" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"path\": \"$TMP/bad.toml\"}")
[ "$CODE" = "400" ] || [ "$CODE" = "422" ] || fail "expected 4xx for bad spec learn_ttl, got $CODE"
echo "   load-spec 4xx ✓"

echo "--- 10. promote API: POST /egress/:task/allow learns via fake upstream"
# Point the learner's upstream already set; promote a fresh domain on a task
# whose learner exists (tk-dns-b) but allowlist lacks the domain yet.
RESP=$(req POST "/egress/tk-dns-b/allow" '{"domain": "other.net"}')
echo "$RESP" | grep -q '"added_to_allowlist":true' || fail "promote failed: $RESP"
sleep 0.5
LEARNED_B=$(req GET "/egress/tk-dns-b/learned")
echo "$LEARNED_B" | grep -q "93.184.216.35" || fail "promote did not learn other.net: $LEARNED_B"
echo "   promoted + learned ✓"

echo ""
echo "✅ 34_test_dns_egress_policy.sh: ALL PASS"
