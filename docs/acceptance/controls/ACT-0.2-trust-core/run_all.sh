#!/usr/bin/env bash
# Запускает все контроли акта ACT-0.2-trust-core во ВРЕМЕННОМ клоне
# репозитория (рабочая копия репозитория не затрагивается). Сеть не нужна.
# Код выхода 0 — ВСЕ ожидания акта выполнены (включая ожидания о
# наблюдаемых дефектах: после исправления кода соответствующие контроли
# покраснеют, это ожидаемо — см. README.md этой папки).
# Использование (из любого места):
#   bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
git clone --quiet "$REPO" "$W/copy" || exit 1
mkdir "$W/copy/acceptance"
for f in "$HERE"/*_test.go.txt; do cp "$f" "$W/copy/acceptance/$(basename "$f" .txt)"; done
for f in "$HERE"/c*.sh "$HERE"/e01_*.sh "$HERE"/f02_*.sh; do cp "$f" "$W/copy/acceptance/"; done
cd "$W/copy" || exit 1
echo "# коммит клона: $(git rev-parse HEAD)"
rc=0
echo "## go vet ./acceptance/"; go vet ./acceptance/ || rc=1
echo "## go test ./acceptance/ -count=1 -v (C01–C09, C13, F01–F04)"
go test ./acceptance/ -count=1 -v 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok|\s+--- )' | grep -v '=== RUN' ; [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
for s in e01_environment c10_private_keys c11_backward_compat c12_interop_blocked c14_no_deps c15_exit_codes f02_text_findings; do
  echo "## bash acceptance/$s.sh"; bash "acceptance/$s.sh" || rc=1
done
[ "$rc" -eq 0 ] && echo "RUN_ALL: все ожидания акта выполнены" || echo "RUN_ALL: есть невыполненные ожидания"
exit $rc
