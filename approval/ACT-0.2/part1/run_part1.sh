#!/usr/bin/env bash
# Runs the part 1 controls against a fresh `git archive` copy of the object
# and saves the full output of each run to out/<control>.out.
# Usage: run_part1.sh [COMMIT]   (from inside a clone of XtReL/trust-core)
set -uo pipefail
COMMIT="${1:-f419b0d1693e6d3c06b7effa813239d129f31d6d}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"
COPY="$(mktemp -d)"
trap 'rm -rf "$COPY"' EXIT
TOP="$(git -C "$HERE" rev-parse --show-toplevel)"
git -C "$TOP" archive "$COMMIT" | tar -x -C "$COPY"
echo "object $COMMIT unpacked to $COPY; go: $(go version)"
rc=0
for c in q1_whitespace q2_rewrite q3_exit_codes; do
	(
		echo "# control: $c.sh"
		echo "# object:  $COMMIT"
		echo "# date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# go:      $(go version)"
		bash "$HERE/$c.sh" "$COPY"
		code=$?
		echo "# exit: $code"
		exit $code
	) >"$OUT/$c.out" 2>&1
	code=$?
	echo "$c: exit $code  ($OUT/$c.out)"
	[ $code -eq 0 ] || rc=1
done
exit $rc
