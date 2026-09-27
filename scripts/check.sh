#!/usr/bin/env bash
# Single source of truth for CI: runs exactly what .github/workflows/ci.yml
# runs (jobs "test" and "interop"), with the same commands and flags, and
# fails on the first error. Run this before every push.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== job: test =="

echo "-- gofmt --"
test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)

echo "-- vet --"
go vet ./...

echo "-- test --"
go test -race -count=1 ./...

echo "-- end-to-end demo --"
bash scripts/demo.sh

echo "== job: interop =="

# Run in a temporary copy of interop/ so "go mod tidy" cannot leave changes
# in the working copy. The copy's go.mod "replace" is repointed at this
# repo's absolute path, since the copy no longer sits next to it.
ROOT="$(pwd)"
INTEROP_TMP="$(mktemp -d)"
trap 'rm -rf "$INTEROP_TMP"' EXIT
cp -r interop "$INTEROP_TMP/interop"
sed -i.bak "s|=> \.\./|=> $ROOT|" "$INTEROP_TMP/interop/go.mod"
rm -f "$INTEROP_TMP/interop/go.mod.bak"

echo "-- reference implementations (golang.org/x/mod/sumdb) --"
(cd "$INTEROP_TMP/interop" && go mod tidy && go test -count=1 ./...)

echo "check: OK"
