#!/usr/bin/env bash
# 55_test_template_extras.sh — snapshot→template promotion, inspection and
# preview endpoints.
# Covers: from-snapshot 201 (flattened standalone raw image, provenance,
# size+sha), alias resolution, inspect refills stats, missing snapshot 404,
# preview 503 without a UML kernel.
# CI-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"' EXIT

export PVM_STATE_ROOT="$TMP/state"
export PVM_AUDIT_ROOT="$TMP/audit"
export PVM_CGROUP_ROOT="$TMP/cg"
export PVM_TEMPLATE_ROOT="$TMP/templates"
mkdir -p "$PVM_STATE_ROOT" "$PVM_AUDIT_ROOT" "$PVM_CGROUP_ROOT" "$PVM_TEMPLATE_ROOT"

PORT=18055
API="http://127.0.0.1:$PORT/api"
AUTH="Authorization: Bearer secret"
export API_SECRET="secret"

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

"$TMP/agentpvm" api -port "$PORT" &>"$TMP/server.log" &
SRV=$!
for _ in $(seq 1 40); do
    curl -sf -H "$AUTH" "$API/templates" >/dev/null 2>&1 && break
    sleep 0.25
done
curl -sf -H "$AUTH" "$API/templates" >/dev/null 2>&1 || fail "server failed to start: $(cat "$TMP/server.log")"

# Fixture: a task with one snapshot whose disk is a small RAW image plus an
# event.json pointing at it (the production layout).
SNAPDIR="$PVM_STATE_ROOT/ts-1/snapshots/snap-1710000000000000000"
mkdir -p "$SNAPDIR"
dd if=/dev/zero of="$TMP/disk.raw" bs=1024 count=256 2>/dev/null
printf 'PVM-PROBE-HEADER' | dd of="$TMP/disk.raw" bs=1 seek=1024 conv=notrunc 2>/dev/null
cp "$TMP/disk.raw" "$SNAPDIR/disk.img"
cat > "$SNAPDIR/event.json" <<EOF
{"id":"snap-1710000000000000000","task_id":"ts-1","disk_overlay":"$SNAPDIR/disk.img","memory_state":"n/a"}
EOF
cat > "$PVM_STATE_ROOT/ts-1/state.json" <<'EOF'
{"id":"ts-1","name":"ts-1","status":"running"}
EOF

echo "--- 1. promote snapshot → READY template"
OUT=$(curl -sf -X POST "$API/templates/from-snapshot" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"task":"ts-1","alias":"golden"}')
echo "$OUT" | jq -e '.status == "READY" and .kind == "template"' >/dev/null || fail "record not READY: $OUT"
echo "$OUT" | jq -e '.image_ref == "snapshot:ts-1/snap-1710000000000000000"' >/dev/null || fail "provenance wrong: $OUT"
SIZE=$(echo "$OUT" | jq -r .image_size_bytes)
[ "$SIZE" -gt 0 ] 2>/dev/null || fail "image_size_bytes missing: $OUT"
SHA=$(echo "$OUT" | jq -r .image_sha256)
[ "${#SHA}" = "64" ] || fail "image_sha256 must be a sha256 hex: $OUT"
TID=$(echo "$OUT" | jq -r .template_id)

echo "--- 2. alias resolves to the promoted template"
OUT=$(curl -sf "$API/templates/golden" -H "$AUTH")
[ "$(echo "$OUT" | jq -r .template_id)" = "$TID" ] || fail "alias lookup failed: $OUT"

echo "--- 3. inspect returns the record with stats"
OUT=$(curl -sf "$API/templates/$TID/inspect" -H "$AUTH")
[ "$(echo "$OUT" | jq -r .image_size_bytes)" = "$SIZE" ] || fail "inspect size drifted: $OUT"
[ "$(echo "$OUT" | jq -r .image_sha256)" = "$SHA" ] || fail "inspect sha drifted: $OUT"

echo "--- 4. the promoted image is a standalone RAW copy of the snapshot disk"
IMG=$(curl -sf "$API/templates/$TID/inspect" -H "$AUTH" | jq -r .image_path)
[ -f "$IMG" ] || fail "image file missing at $IMG"
cmp -s "$IMG" "$SNAPDIR/disk.img" || fail "flattened image must equal the (raw) snapshot disk"
# qcow2 magic must NOT be present.
head -c 4 "$IMG" | grep -q "QFI" && fail "promoted image must not be qcow2"

echo "--- 5. empty snapshot_id picks the newest; missing task → 404"
OUT=$(curl -sf -X POST "$API/templates/from-snapshot" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"ts-1"}')
[ "$(echo "$OUT" | jq -r .status)" = "READY" ] || fail "newest-snapshot promotion failed: $OUT"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/templates/from-snapshot" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"ghost"}')
[ "$CODE" = "404" ] || fail "missing task must 404, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/templates/from-snapshot" -H "$AUTH" -H "Content-Type: application/json" -d '{"task":"ts-1","snapshot_id":"snap-none"}')
[ "$CODE" = "404" ] || fail "missing snapshot must 404, got $CODE"

echo "--- 6. inspect unknown → 404 (and malformed ids → 400)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/templates/tpl-000000000000000000000000/inspect" -H "$AUTH")
[ "$CODE" = "404" ] || fail "inspect valid-but-unknown id must 404, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/templates/tpl-nope/inspect" -H "$AUTH")
[ "$CODE" = "400" ] || fail "inspect malformed id must 400, got $CODE"

echo "--- 7. preview without a UML kernel → 503 with a clear error"
if [ -e "./bin/linux" ]; then
    echo "    (kernel present on this host — preview would boot; skipping 503 assertion)"
else
    BODY=$(curl -s -X POST "$API/templates/$TID/preview" -H "$AUTH" -H "Content-Type: application/json" -d '{"timeout_seconds":5}')
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/templates/$TID/preview" -H "$AUTH" -H "Content-Type: application/json" -d '{"timeout_seconds":5}')
    [ "$CODE" = "503" ] || fail "preview without kernel must 503, got $CODE"
    echo "$BODY" | jq -e '.error | contains("kernel")' >/dev/null || fail "503 must name the kernel: $BODY"
fi

echo "✅ 55_test_template_extras.sh passed"
