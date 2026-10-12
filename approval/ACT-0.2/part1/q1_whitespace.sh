#!/usr/bin/env bash
# Q1: one space changed in one entry on disk. Expected: detected, exit 1,
# exactly one problem "entries on disk do not match the signed checkpoint root".
# Usage: q1_whitespace.sh OBJECT_COPY_DIR
source "$(dirname "$0")/lib.sh"
setup "$1"
keygen
mklog "$W/log" 3 || { echo "ASSERT FAIL: could not build the log"; exit 1; }

STDERR_EXPECTED=' - entries on disk do not match the signed checkpoint root (log was modified)
VERIFICATION FAILED: 1 problem(s)'
E="$W/log/entries/00000000000000000001.json"

vrun base "$W/log"
check "untouched log: exit 0" code_is base 0
check "untouched log: OK line" out_has base "OK: checkpoint signature, Merkle root and all entry signatures verified"

echo
echo "entry 1 has $(tr -cd ' ' <"$E" | wc -c) space byte(s) before the change"
cp "$E" "$W/entry1.orig"

for variant in A B; do
	cp "$W/entry1.orig" "$E"
	if [ "$variant" = A ]; then
		echo; echo "== variant A: one space inserted after the first ':' =="
		sed -i '0,/":/s//": /' "$E"
	else
		echo; echo "== variant B: one space appended at the end of the file =="
		printf ' ' >>"$E"
	fi
	echo "bytes: $(wc -c <"$W/entry1.orig") -> $(wc -c <"$E")"
	cmp -l "$W/entry1.orig" "$E" | head -3
	echo "diff of first 40 bytes:"
	head -c 40 "$W/entry1.orig"; echo
	head -c 40 "$E"; echo
	check "variant $variant: exactly one byte added" [ $(($(wc -c <"$E") - $(wc -c <"$W/entry1.orig"))) -eq 1 ]
	check "variant $variant: entry still parses as JSON" python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$E"

	vrun "q1$variant" "$W/log"
	check "variant $variant: exit code 1" code_is "q1$variant" 1
	check "variant $variant: stderr is exactly the root-mismatch problem + summary" err_equals "q1$variant" "$STDERR_EXPECTED"
	check "variant $variant: no OK line" out_lacks "q1$variant" "OK:"
	check "variant $variant: report still names the log" out_has "q1$variant" "log:       $ORIGIN"
done

finish
