#!/usr/bin/env bash
# Q2: history rewritten (entry 0 replaced, checkpoint re-signed with the same
# operator key). Expected: missed without -previous; detected (exit 1) with
# -previous on the checkpoint kept before the rewrite; silently skipped
# (exit 0, OK) when the -previous file is empty.
# Usage: q2_rewrite.sh OBJECT_COPY_DIR
source "$(dirname "$0")/lib.sh"
setup "$1"
keygen
mklog "$W/log" 3 || { echo "ASSERT FAIL: could not build the log"; exit 1; }

mkdir -p "$W/kept"
cp "$W/log/checkpoint" "$W/kept/checkpoint"
echo; echo "checkpoint kept by the client before the rewrite:"; cat "$W/kept/checkpoint"

vrun before "$W/log" -previous "$W/kept/checkpoint"
check "before rewrite, -previous: exit 0" code_is before 0
check "before rewrite, -previous: history line" out_has before "history:   first 3 entries match the previous checkpoint"

# Operator rewrites history: entry 0 is a different attestation, entries 1..2
# are re-recorded, the checkpoint is re-signed with the same log key.
"$TC" init -log "$W/rewritten" -origin "$ORIGIN" -log-key "$W/keys/log.key" >/dev/null
"$TC" record -log "$W/rewritten" -origin "$ORIGIN" -log-key "$W/keys/log.key" -key "$W/keys/att.key" -event "$(event forged0)" >/dev/null
for i in 1 2; do
	"$TC" record -log "$W/rewritten" -origin "$ORIGIN" -log-key "$W/keys/log.key" -key "$W/keys/att.key" -event "$(event "$i")" >/dev/null
done
rm -rf "$W/log"
mv "$W/rewritten" "$W/log"
echo; echo "rewritten checkpoint now on disk:"; cat "$W/log/checkpoint"
check "rewrite changed the root" not cmp -s "$W/log/checkpoint" "$W/kept/checkpoint"
check "rewrite keeps the size at 3" [ "$(sed -n 2p "$W/log/checkpoint")" = 3 ]

vrun nopref "$W/log"
check "rewritten, no -previous: exit 0 (not detectable by design)" code_is nopref 0
check "rewritten, no -previous: OK line" out_has nopref "OK: checkpoint signature"

vrun prev "$W/log" -previous "$W/kept/checkpoint"
check "rewritten, -previous kept: exit 1" code_is prev 1
check "rewritten, -previous kept: stderr is the rewrite problem + summary" err_equals prev \
' - history was rewritten: first entries no longer match the previous checkpoint
VERIFICATION FAILED: 1 problem(s)'
check "rewritten, -previous kept: no OK line" out_lacks prev "OK:"

: >"$W/kept/empty"
echo; echo "empty previous file size: $(wc -c <"$W/kept/empty")"
vrun empty "$W/log" -previous "$W/kept/empty"
check "rewritten, -previous EMPTY file: exit 0 (check silently skipped)" code_is empty 0
check "rewritten, -previous EMPTY file: OK line printed" out_has empty "OK: checkpoint signature"
check "rewritten, -previous EMPTY file: no history line" out_lacks empty "history:"
check "rewritten, -previous EMPTY file: stderr empty (no warning)" err_equals empty ""

vrun emptyjson "$W/log" -previous "$W/kept/empty" -json
check "-json with EMPTY -previous: exit 0" code_is emptyjson 0
check "-json with EMPTY -previous: no previousSize in report" out_lacks emptyjson "previousSize"
check "-json with EMPTY -previous: ok true" out_has emptyjson '"ok": true'

vrun missing "$W/log" -previous "$W/kept/does-not-exist"
check "-previous missing file: exit 2" code_is missing 2
check "-previous missing file: error message" err_equals missing "error: open $W/kept/does-not-exist: no such file or directory"

finish
