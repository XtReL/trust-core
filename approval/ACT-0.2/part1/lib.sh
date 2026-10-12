# Shared helpers for the ACT-0.2 part 1 controls. Sourced, not executed.
# Usage in a control: source lib.sh; setup "$OBJ"
# OBJ is an unpacked copy of the object (git archive), never the repo itself.
set -uo pipefail

FAILS=0

setup() {
	OBJ="$(cd "$1" && pwd)"
	W="$(mktemp -d)"
	trap 'rm -rf "$W"; echo "cleanup: removed $W (keys, logs, binary)"' EXIT
	echo "object copy: $OBJ"
	echo "work dir:    $W"
	(cd "$OBJ" && GOTOOLCHAIN=local go build -o "$W/trustcore" ./cmd/trustcore) || {
		echo "ASSERT FAIL: build failed"
		exit 1
	}
	TC="$W/trustcore"
	ORIGIN="trust.example.com/act02/control"
}

# run NAME CMD... : runs a command, keeps stdout/stderr/exit code in
# $W/NAME.{out,err,code} and prints them in full.
run() {
	local name="$1"
	shift
	echo
	echo "\$ $*"
	"$@" >"$W/$name.out" 2>"$W/$name.err"
	echo $? >"$W/$name.code"
	echo "--- stdout ---"
	cat "$W/$name.out"
	echo "--- stderr ---"
	cat "$W/$name.err"
	echo "--- exit: $(cat "$W/$name.code") ---"
}

check() { # check DESCRIPTION CONDITION-COMMAND...
	local d="$1"
	shift
	if "$@"; then
		echo "ASSERT OK:   $d"
	else
		echo "ASSERT FAIL: $d"
		FAILS=$((FAILS + 1))
	fi
}

code_is() { [ "$(cat "$W/$1.code")" = "$2" ]; }
err_equals() { [ "$(cat "$W/$1.err")" = "$2" ]; }
out_has() { grep -qF -- "$2" "$W/$1.out"; }
out_lacks() { ! grep -qF -- "$2" "$W/$1.out"; }
not() { ! "$@"; }

# event N : writes an event file whose subject commit is derived from N.
event() {
	local f="$W/event-$1.json"
	local c
	c="$(printf 'act02-%s' "$1" | sha1sum | cut -d' ' -f1)"
	sed "s/3f786850e387550fdab836ed7e6dc881de23001b/$c/" "$OBJ/examples/gatekeeper-scan.event.json" >"$f"
	echo "$f"
}

# mklog DIR N : creates a log with N entries (events 0..N-1).
mklog() {
	"$TC" init -log "$1" -origin "$ORIGIN" -log-key "$W/keys/log.key" >/dev/null || return 1
	local i
	for ((i = 0; i < $2; i++)); do
		"$TC" record -log "$1" -origin "$ORIGIN" -log-key "$W/keys/log.key" \
			-key "$W/keys/att.key" -event "$(event "${3:-}$i")" >/dev/null || return 1
	done
}

keygen() {
	mkdir -p "$W/keys"
	"$TC" keygen -out "$W/keys/log" -name "$ORIGIN"
	"$TC" keygen -out "$W/keys/att"
}

# vrun NAME LOGDIR [extra flags] : runs verify with the control's keys.
vrun() {
	local name="$1" d="$2"
	shift 2
	run "$name" "$TC" verify -log "$d" -origin "$ORIGIN" \
		-log-pub "$W/keys/log.pub" -attester-pub "$W/keys/att.pub" "$@"
}

finish() {
	echo
	if [ "$FAILS" -ne 0 ]; then
		echo "RESULT: $FAILS assertion(s) differ from the expected answer"
		exit 1
	fi
	echo "RESULT: all assertions match the expected answer"
	exit 0
}
