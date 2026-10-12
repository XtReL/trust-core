#!/usr/bin/env bash
# Q3: exit codes when the -log directory or the -log-pub file does not exist,
# compared with the exit codes documented in README.md.
# Expected: missing -log -> 1 ("VERIFICATION FAILED: open .../checkpoint"),
# missing -log-pub -> 2 ("error: open ..."); README documents only
# 0 ok / 1 verification failed / 2 usage error.
# Usage: q3_exit_codes.sh OBJECT_COPY_DIR
source "$(dirname "$0")/lib.sh"
setup "$1"
keygen
mklog "$W/log" 1 || { echo "ASSERT FAIL: could not build the log"; exit 1; }

vrun base "$W/log"
check "existing log and keys: exit 0" code_is base 0

check "precondition: $W/nolog does not exist" [ ! -e "$W/nolog" ]
vrun nolog "$W/nolog"
check "missing -log dir: exit 1" code_is nolog 1
check "missing -log dir: reported as verification failure" err_equals nolog \
	"VERIFICATION FAILED: open $W/nolog/checkpoint: no such file or directory"

check "precondition: $W/keys/nope.pub does not exist" [ ! -e "$W/keys/nope.pub" ]
run nopub "$TC" verify -log "$W/log" -origin "$ORIGIN" -log-pub "$W/keys/nope.pub" -attester-pub "$W/keys/att.pub"
check "missing -log-pub file: exit 2" code_is nopub 2
check "missing -log-pub file: reported as error" err_equals nopub \
	"error: open $W/keys/nope.pub: no such file or directory"

# Both missing: which one wins (keys are loaded first).
run both "$TC" verify -log "$W/nolog" -origin "$ORIGIN" -log-pub "$W/keys/nope.pub" -attester-pub "$W/keys/att.pub"
check "both missing: exit 2 (key loaded first)" code_is both 2

# Usage error for reference: a required flag missing.
run usage "$TC" verify -log "$W/log" -attester-pub "$W/keys/att.pub"
check "missing required -log-pub flag: exit 2" code_is usage 2

# What README and the CLI header say.
echo
echo "README.md exit-code line:"
grep -n 'Коды выхода' "$OBJ/README.md"
echo "cmd/trustcore/main.go header:"
grep -n 'Exit codes' "$OBJ/cmd/trustcore/main.go"
check "README documents 2 as usage error only" grep -qF '`2` — ошибка использования.' "$OBJ/README.md"
check "README does not mention I/O errors" bash -c "! grep -qiE 'I/O|ввода-вывода' '$OBJ/README.md'"
check "CLI header documents 2 as usage OR I/O error" grep -qF 'Exit codes: 0 = ok, 1 = verification failed, 2 = usage or I/O error.' "$OBJ/cmd/trustcore/main.go"

# The two cases are the same kind of failure (a path given on the command
# line does not exist) but get different codes.
check "inconsistency: missing -log and missing -log-pub give different codes" \
	[ "$(cat "$W/nolog.code")" != "$(cat "$W/nopub.code")" ]

finish
