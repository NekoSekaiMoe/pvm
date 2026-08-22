#!/usr/bin/env bash
# 25_test_e2b_api_full.sh — exhaustive route sweep: EVERY endpoint exposed by
# internal/api/e2b_server.go is hit exactly once with its best-achievable
# kernel-free outcome asserted (success path where possible, contract-correct
# error where a UML kernel / root / writable /var/lib is required).
# Does NOT require a UML kernel; safe to run in CI.
#
# Route checklist (must stay in sync with e2b_server.go):
#  [1]  GET    /api/containers
#  [2]  POST   /api/containers/start
#  [3]  GET    /api/containers/:id/logs
#  [4]  DELETE /api/containers/:id
#  [5]  POST   /api/containers/:id/snapshot
#  [6]  POST   /api/containers/:id/restore
#  [7]  POST   /api/images/pull
#  [8]  POST   /api/exec
#  [9]  GET    /api/tasks
#  [10] GET    /api/tasks/:id
#  [11] POST   /api/tasks/:id/transition
#  [12] POST   /api/tasks/:id/pause
#  [13] POST   /api/tasks/:id/resume
#  [14] POST   /api/tasks/load-spec
#  [15] GET    /api/audit/:id
#  [16] GET    /api/audit/:id/verify
#  [17] GET    /api/approvals
#  [18] POST   /api/approvals
#  [19] POST   /api/approvals/:id/decide
#  [20] GET    /api/policy/:task
#  [21] POST   /api/policy/:task
#  [22] GET    /api/pool/stats
#  [23] POST   /api/pool/warm
#  [24] POST   /api/pool/quota
#  [25] POST   /api/gate/verify
#  [26] POST   /api/volumes
#  [27] GET    /api/volumes
#  [28] GET    /api/volumes/:id
#  [29] DELETE /api/volumes/:id
#  [30] POST   /api/templates
#  [31] GET    /api/templates
#  [32] GET    /api/templates/:id
#  [33] POST   /api/templates/:id/alias
#  [34] DELETE /api/templates/:id
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_VOLUME_ROOT="$TMP/volumes"
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT"

PORT=18085
API="http://127.0.0.1:$PORT/api"
# Random per-run API secret; the server reads the SAME value from $API_SECRET.
API_SECRET=$(head -c32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
[ -n "$API_SECRET" ] || API_SECRET=$(openssl rand -hex 16 2>/dev/null || true)
[ -n "$API_SECRET" ] || API_SECRET="s$RANDOM$RANDOM$RANDOM$RANDOM"
export API_SECRET
AUTH="Authorization: Bearer $API_SECRET"

echo "==> building agentpvm"
go build -o "$TMP/agentpvm" ./cmd/agentpvm

echo "==> starting server on :$PORT"
"$TMP/agentpvm" webui --port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    if curl -sf -H "$AUTH" "$API/containers" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
# The loop alone can fall through without the server ever being ready; the
# poll's own curl doubles as the readiness probe (auth + startup combined).
curl -sf -H "$AUTH" "$API/containers" >/dev/null || {
    echo "❌ server did not become ready; $TMP/server.log contents:"
    cat "$TMP/server.log"
    exit 1
}

req() { # method path [json-body] -> body
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$API$p" -H "$AUTH"
    fi
}
code() { # method path [json-body] -> http status
    local m=$1 p=$2 b=${3:-}
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH" -H "Content-Type: application/json" -d "$b"
    else
        curl -s -o /dev/null -w "%{http_code}" -X "$m" "$API$p" -H "$AUTH"
    fi
}
assert_status() { # actual expected name
    [ "$1" = "$2" ] || { echo "❌ $3: expected $2, got $1"; exit 1; }
}
pass() { echo "   [$1] $2 ✓"; }

echo "--- [1] GET /containers"
N=$(req GET /containers | jq 'length')
[ "$N" -ge 0 ] 2>/dev/null || { echo "❌ /containers not live"; exit 1; }
pass 1 "list live"

echo "--- [2] POST /containers/start (no kernel -> honest 500 error)"
# With ./bin/linux absent the launcher fails immediately; with a kernel
# present this would boot a real box, so only assert when it cannot.
if [ ! -f ./bin/linux ]; then
    OUT=$(req POST /containers/start '{"name":"sweep-start","rootfs":"/var/lib/uml-container/images/alpine","mem":"256M"}')
    ERR=$(printf '%s' "$OUT" | jq -r 'has("error")')
    [ "$ERR" = "true" ] || { echo "❌ start: expected error json: $OUT"; exit 1; }
    pass 2 "fails fast with error json"
else
    echo "   [2] SKIP: ./bin/linux present (would boot a real container)"
fi

echo "--- [3] GET /containers/:id/logs (seeded console.log -> 200 + content)"
mkdir -p "$PVM_STATE_ROOT/sweep-log/logs"
echo "hello from console" > "$PVM_STATE_ROOT/sweep-log/logs/console.log"
BODY=$(req GET /containers/sweep-log/logs)
printf '%s' "$BODY" | grep -q "hello from console" || { echo "❌ logs content: $BODY"; exit 1; }
pass 3 "reads real console.log"

echo "--- [4] DELETE /containers/:id (seeded dir -> removed)"
mkdir -p "$PVM_STATE_ROOT/sweep-del"
assert_status "$(code DELETE /containers/sweep-del)" "200" "delete seeded"
[ ! -d "$PVM_STATE_ROOT/sweep-del" ] || { echo "❌ dir not removed"; exit 1; }
pass 4 "dir really removed"

echo "--- [5][6] snapshot/restore (unknown container -> contract error)"
HTTP=$(code POST /containers/no-such-box/snapshot)
[ "$HTTP" = "500" ] || [ "$HTTP" = "404" ] || { echo "❌ snapshot: $HTTP"; exit 1; }
HTTP=$(code POST /containers/no-such-box/restore)
[ "$HTTP" = "500" ] || [ "$HTTP" = "404" ] || { echo "❌ restore: $HTTP"; exit 1; }
pass 5 "snapshot contract error"
pass 6 "restore contract error"

echo "--- [7] POST /images/pull (registry allowlist enforced)"
OUT=$(req POST /images/pull '{"image":"evil.example.com/foo:latest"}')
printf '%s' "$OUT" | jq -re '.error' | grep -q "allowlist" || { echo "❌ allowlist: $OUT"; exit 1; }
pass 7 "off-allowlist registry rejected"

echo "--- [20][21] policy register + introspect"
HTTP=$(code GET /policy/sweep-t)
assert_status "$HTTP" "404" "policy before registration"
OUT=$(req POST /policy/sweep-t '{"Rules":[{"Name":"read_file","Action":"allow"},{"Name":"rm_rf","Action":"deny","Reason":"danger"},{"Name":"send_email","Action":"approve","Reason":"external send"}]}')
assert_status "$(printf '%s' "$OUT" | jq -r .status)" "registered" "policy registered"
NR=$(req GET /policy/sweep-t | jq 'length')
[ "$NR" -eq 4 ] || { echo "❌ expected 4 compiled rules (3 + catch-all), got $NR"; exit 1; }
HTTP=$(code POST /policy/sweep-t '{"Rules":[]}')
assert_status "$HTTP" "409" "duplicate registration without force"
pass 20 "GET rules echo"
pass 21 "register + duplicate 409"

echo "--- [8] POST /exec (allow / deny / approve / no-task)"
assert_status "$(code POST /exec '{"cmd":"ls"}')" "400" "exec without task"
HTTP=$(code POST "/exec?task=unregistered-t" '{"cmd":"ls"}')
assert_status "$HTTP" "403" "exec without gateway"
OUT=$(req POST "/exec?task=sweep-t" '{"cmd":"read_file path=/etc/hostname"}')
assert_status "$(printf '%s' "$OUT" | jq -r .ok)" "true" "allowed tool dry-run ok"
HTTP=$(code POST "/exec?task=sweep-t" '{"cmd":"rm_rf path=/"}')
assert_status "$HTTP" "403" "denied tool"
HTTP=$(code POST "/exec?task=sweep-t" '{"cmd":"send_email to=x@y.com"}')
assert_status "$HTTP" "202" "approve-gated tool -> 202"
pass 8 "allow=200 deny=403 approve=202 no-task=400"

echo "--- [9][10][11][14] tasks: list / detail / transition / load-spec"
mkdir -p "$PVM_STATE_ROOT/sweep-task"
echo '{"id":"sweep-task","name":"sweep-task","status":"pending"}' > "$PVM_STATE_ROOT/sweep-task/state.json"
CNT=$(req GET /tasks | jq '[.[] | select(.id=="sweep-task")] | length')
assert_status "$CNT" "1" "task listed"
assert_status "$(req GET /tasks/sweep-task | jq -r .status)" "pending" "detail readable"
assert_status "$(code POST /tasks/sweep-task/transition '{"to":"provisioning","actor":"controller","reason":"sweep"}')" "200" "valid transition"
TOML='version=1
caller="sweeper"
[runtime]
name="sweep-spec"
memory="256M"
[kernel]
path="./bin/linux"
'
FP=$(req POST /tasks/load-spec "{\"content\":$(printf '%s' "$TOML" | jq -Rs .)}" | jq -r .fingerprint)
[ -n "$FP" ] && [ "$FP" != "null" ] || { echo "❌ load-spec fingerprint"; exit 1; }
pass 9 "list"
pass 10 "detail"
pass 11 "transition"
pass 14 "load-spec fingerprint=$FP"

echo "--- [12][13] pause/resume (mock cgroup freeze sync)"
mkdir -p "$PVM_STATE_ROOT/sweep-pause" "$PVM_CGROUP_ROOT/sweep-pause"
echo "0" > "$PVM_CGROUP_ROOT/sweep-pause/cgroup.freeze"
cat > "$PVM_STATE_ROOT/sweep-pause/state.json" <<'EOF'
{"id":"sweep-pause","name":"sweep-pause","status":"running","pid":99997,"idle_timeout":"30m"}
EOF
assert_status "$(code POST /tasks/sweep-pause/pause)" "204" "pause"
[ "$(cat "$PVM_CGROUP_ROOT/sweep-pause/cgroup.freeze")" = "1" ] || { echo "❌ freeze not synced"; exit 1; }
assert_status "$(code POST /tasks/sweep-pause/resume)" "200" "resume"
[ "$(cat "$PVM_CGROUP_ROOT/sweep-pause/cgroup.freeze")" = "0" ] || { echo "❌ thaw not synced"; exit 1; }
pass 12 "pause 204 + freeze=1"
pass 13 "resume 200 + freeze=0"

echo "--- [15][16][25] audit read/verify + artifact gate writes records"
OUT=$(req POST /gate/verify '{"task_id":"sweep-gate","diff":"","build_log":"","claimed_ok":true}')
assert_status "$(printf '%s' "$OUT" | jq -r .passed)" "true" "clean bundle passes"
OUT=$(req POST /gate/verify '{"task_id":"sweep-gate","diff":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","build_log":"","claimed_ok":true}')
assert_status "$(printf '%s' "$OUT" | jq -r .passed)" "false" "secret bundle fails"
NAUD=$(req GET /audit/sweep-gate | jq 'length')
[ "$NAUD" -ge 2 ] || { echo "❌ expected >=2 audit records, got $NAUD"; exit 1; }
assert_status "$(req GET /audit/sweep-gate/verify | jq -r .valid)" "true" "chain valid"
pass 15 "ledger read ($NAUD records)"
pass 16 "verify valid"
pass 25 "gate pass/fail verdicts"

echo "--- [17][18][19] approvals: list / create / decide"
TID=$(req POST /approvals '{"task_id":"sweep-t","tool":"send_email","target":"prod","params":{"to":"x@y.com"},"why":"sweep"}' | jq -r .id)
[ -n "$TID" ] && [ "$TID" != "null" ] || { echo "❌ no ticket"; exit 1; }
CNT=$(req GET "/approvals?task=sweep-t" | jq 'length')
[ "$CNT" -ge 1 ] || { echo "❌ ticket not listed"; exit 1; }
assert_status "$(req POST "/approvals/$TID/decide" '{"approved":true,"by":"sweeper"}' | jq -r .state)" "approved" "decide"
HTTP=$(code POST "/approvals/$TID/decide" '{"approved":true,"by":"sweeper"}')
assert_status "$HTTP" "409" "re-decide rejected"
pass 17 "list"
pass 18 "create"
pass 19 "decide + idempotency 409"

echo "--- [22][23][24] pool: stats / warm / quota"
assert_status "$(req POST /pool/warm '{"template":{"name":"alpine","memory":"256M","cpu":1},"n":2}' | jq -r .created)" "2" "warm"
assert_status "$(req GET /pool/stats | jq -r .ready)" "2" "stats ready"
assert_status "$(code POST /pool/quota '{"tenant":"sweep-tenant","quota":{"max_concurrent":3}}')" "200" "quota set"
pass 22 "stats"
pass 23 "warm"
pass 24 "quota"

echo "--- [26]-[29] volumes: create / list / get / delete"
VID="sweep-vol"
assert_status "$(code POST /volumes "{\"name\":\"$VID\",\"driver\":\"local\"}")" "201" "volume create"
CNT=$(req GET /volumes | jq "[.[] | select(.volume_id==\"$VID\")] | length")
assert_status "$CNT" "1" "volume listed"
assert_status "$(req GET /volumes/$VID | jq -r .volume_id)" "$VID" "volume get"
assert_status "$(code DELETE /volumes/$VID)" "204" "volume delete"
assert_status "$(code GET /volumes/$VID)" "404" "volume gone"
pass 26 "create 201"
pass 27 "list"
pass 28 "get"
pass 29 "delete 204 + gone"

echo "--- [30]-[34] templates: create / list / get / alias / delete"
OUT=$(req POST /templates '{"image_ref":"docker.io/library/alpine:3.19"}')
TPL=$(printf '%s' "$OUT" | jq -r .template_id)
[ -n "$TPL" ] && [ "$TPL" != "null" ] || { echo "❌ template create: $OUT"; exit 1; }
assert_status "$(printf '%s' "$OUT" | jq -r .status)" "PENDING" "created PENDING"
CNT=$(req GET /templates | jq "[.[] | select(.template_id==\"$TPL\")] | length")
assert_status "$CNT" "1" "template listed"
assert_status "$(req GET /templates/$TPL | jq -r .template_id)" "$TPL" "template get"
# alias claims require READY (plan contract): a PENDING template must be rejected
assert_status "$(code POST /templates/$TPL/alias '{"alias":"sweep-alias"}')" "409" "alias on PENDING rejected"
# simulate image build completion on disk (same technique as tests/11)
jq '.status = "READY"' "$PVM_TEMPLATE_ROOT/$TPL/meta.json" > "$PVM_TEMPLATE_ROOT/$TPL/meta.json.tmp" \
    && mv "$PVM_TEMPLATE_ROOT/$TPL/meta.json.tmp" "$PVM_TEMPLATE_ROOT/$TPL/meta.json"
assert_status "$(code POST /templates/$TPL/alias '{"alias":"sweep-alias"}')" "200" "alias bind"
assert_status "$(req GET /templates/sweep-alias | jq -r .template_id)" "$TPL" "alias resolves"
assert_status "$(code DELETE /templates/sweep-alias)" "204" "delete via alias"
assert_status "$(code GET /templates/$TPL)" "404" "template gone"
pass 30 "create PENDING"
pass 31 "list"
pass 32 "get"
pass 33 "alias bind + resolve"
pass 34 "delete via alias + gone"

echo ""
echo "✅ 25_test_e2b_api_full: ALL 34 ROUTES SWEPT"
