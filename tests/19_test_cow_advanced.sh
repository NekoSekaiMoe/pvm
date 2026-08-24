#!/usr/bin/env bash
# 19_test_cow_advanced.sh — E2E test for pure-Go qcow2 CoW overlay creation, compaction, and conversion.
# Covers: Path injection defenses (commas), raw <-> qcow2 conversion round-trip,
# and in-place qcow2 compaction.
# CI-safe (no kernel required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "❌ $1"; exit 1; }

if [ -n "${AGENTPVM_BIN:-}" ]; then
    echo "==> using prebuilt $TMP/agentpvm ($AGENTPVM_BIN)"
    cp "$AGENTPVM_BIN" "$TMP/agentpvm"
else
    echo "==> building $TMP/agentpvm"
    go build -o "$TMP/agentpvm" ./cmd/agentpvm
fi

echo "--- 1. Path injection defense: comma in backing path rejected"
OUT=$("$TMP/agentpvm" cow -backing "/tmp/base,injected=1.img" -overlay "$TMP/out.qcow2" 2>&1 || true)
echo "$OUT" | grep -qi "forbidden\|comma\|failed" || fail "comma in backing path not rejected: $OUT"
echo "   comma in backing rejected ✓"

echo "--- 2. Path injection defense: comma in overlay path rejected"
OUT=$("$TMP/agentpvm" cow -backing "$TMP/base.img" -overlay "/tmp/out,injected=1.qcow2" 2>&1 || true)
echo "$OUT" | grep -qi "forbidden\|comma\|failed" || fail "comma in overlay path not rejected: $OUT"
echo "   comma in overlay rejected ✓"

echo "--- 3. Create qcow2 overlay over raw base"
BASE="$TMP/base_raw.img"
head -c $((2 * 1024 * 1024)) /dev/zero > "$BASE"
printf "HEADER_RAW_DATA" | dd of="$BASE" bs=1 seek=0 conv=notrunc 2>/dev/null
OV="$TMP/overlay.qcow2"
"$TMP/agentpvm" cow -backing "$BASE" -overlay "$OV" >/dev/null
[ -f "$OV" ] || fail "overlay was not created"
# Verify qcow2 magic QFI\xfb
head -c 4 "$OV" | grep -q $'QFI\xfb' || fail "overlay is not a valid qcow2 file"
echo "   overlay created with valid qcow2 magic ✓"

echo "--- 4. Compact qcow2 overlay in-place"
OUT=$("$TMP/agentpvm" cow -compact "$OV" 2>&1)
echo "$OUT" | grep -q "Compacted" || fail "compact output missing: $OUT"
head -c 4 "$OV" | grep -q $'QFI\xfb' || fail "compacted file lost qcow2 magic"
echo "   compact in-place verified ✓"

echo "--- 5. Convert raw -> qcow2 -> raw byte-level content round-trip"
RAW_IN="$TMP/convert_in.img"
head -c $((1024 * 1024)) /dev/zero > "$RAW_IN"
printf "PAYLOAD_BLOCK_TEST_12345" | dd of="$RAW_IN" bs=1 seek=4096 conv=notrunc 2>/dev/null

QC_CONV="$TMP/convert.qcow2"
"$TMP/agentpvm" cow -to-qcow2 "$RAW_IN" -overlay "$QC_CONV" >/dev/null
head -c 4 "$QC_CONV" | grep -q $'QFI\xfb' || fail "converted file is not qcow2"

# Negative case: converting onto the same file must fail and preserve source
OUT=$("$TMP/agentpvm" cow -to-raw "$QC_CONV" -overlay "$QC_CONV" 2>&1 || true)
echo "$OUT" | grep -qi "same file\|failed" || fail "same source and overlay path not rejected: $OUT"
head -c 4 "$QC_CONV" | grep -q $'QFI\xfb' || fail "source image corrupted by rejected conversion"
echo "   same-path conversion rejected without modifying source ✓"

RAW_OUT="$TMP/convert_out.img"
"$TMP/agentpvm" cow -to-raw "$QC_CONV" -overlay "$RAW_OUT" >/dev/null

# Compare the complete raw images byte-for-byte
if ! cmp -s "$RAW_IN" "$RAW_OUT"; then
    fail "convert round-trip content mismatch"
fi
echo "   convert raw<->qcow2 round-trip byte-identical ✓"

echo ""
echo "✅ 19_test_cow_advanced: ALL PASS"
