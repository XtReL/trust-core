#!/usr/bin/env bash
# End-to-end demo: keys -> log -> records -> full verification -> kept
# checkpoint -> single-entry proof -> tamper detection.
# Anyone can run it: this is the "someone else verified it" signal.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/trustcore$(go env GOEXE)"  # .exe on Windows, empty elsewhere
ORIGIN="trust.example.com/demo/gatekeeper"
EVENT="examples/gatekeeper-scan.event.json"

go build -o "$BIN" ./cmd/trustcore

echo "== 1. keys: log operator + attester (scanner)"
"$BIN" keygen -out "$WORK/log" -name "$ORIGIN"
"$BIN" keygen -out "$WORK/attester" >/dev/null

echo "== 2. empty log"
"$BIN" init -log "$WORK/tlog" -origin "$ORIGIN" -log-key "$WORK/log.key"

rec() { "$BIN" record -log "$WORK/tlog" -origin "$ORIGIN" -log-key "$WORK/log.key" -key "$WORK/attester.key" -event "$EVENT" >/dev/null; }

echo "== 3. two scans recorded; the client keeps this checkpoint"
rec; rec
cp "$WORK/tlog/checkpoint" "$WORK/kept-checkpoint"

echo "== 4. one more scan, then full verification against the kept checkpoint"
rec
VERIFY=( "$BIN" verify -log "$WORK/tlog" -origin "$ORIGIN" -log-pub "$WORK/log.pub" -attester-pub "$WORK/attester.pub" -previous "$WORK/kept-checkpoint" )
"${VERIFY[@]}"

echo "== 5. single-entry proof (client holds only entry 1)"
"$BIN" prove -log "$WORK/tlog" -index 1 > "$WORK/proof.json"
"$BIN" verify-entry -entry "$WORK/tlog/entries/00000000000000000001.json" -proof "$WORK/proof.json" \
  -origin "$ORIGIN" -log-pub "$WORK/log.pub" -attester-pub "$WORK/attester.pub"

echo "== 6. tamper: add one space to entry 0"
printf ' ' >> "$WORK/tlog/entries/00000000000000000000.json"
if "${VERIFY[@]}" 2>/dev/null; then
  echo "ERROR: tampering was NOT detected"; exit 1
fi
echo "tampering detected (expected)"
echo "DEMO PASSED"
