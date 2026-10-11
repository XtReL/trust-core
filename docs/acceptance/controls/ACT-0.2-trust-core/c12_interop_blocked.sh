#!/usr/bin/env bash
# Контроль З12. README.md:130 — «Совместимость проверяется тестами в
# interop/: наши чекпоинты открываются эталонной реализацией Go, её заметки
# — нашей, корни и доказательства совпадают поэлементно.»
#
# Статус заявления: Н. Это НЕ проверка заявления, а фиксация причины, по
# которой его нельзя проверить в рамках правил акта: interop/ — отдельный
# модуль с внешней зависимостью golang.org/x/mod, а interop/go.sum в
# репозитории нет, поэтому «загрузка по go.sum» невозможна. Прогон
# check.sh/CI делает `go mod tidy`, то есть создаёт go.sum заново из
# сети — это изменение go.sum, при котором правило акта требует остановиться
# и спросить владельца.
#
# Скрипт утверждает наблюдаемое состояние (оно же блокирует): без сети
# и без изменения go.mod/go.sum модульные тесты interop не запускаются.
# Когда решение владельца будет принято и go.sum появится, скрипт
# покраснеет — это ожидаемо; тогда нужно запускать сами тесты interop.
# Запуск (из корня временной копии, без сети): bash acceptance/c12_interop_blocked.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }

[ ! -e interop/go.sum ]; expect "interop/go.sum отсутствует" 0 $?
if git rev-parse --git-dir >/dev/null 2>&1; then
  expect "interop/go.sum не отслеживается git" "" "$(git ls-files interop/go.sum)"
  expect "(контроль способности поиска) interop/go.mod отслеживается git" "interop/go.mod" "$(git ls-files interop/go.mod)"
fi
grep -q 'golang.org/x/mod' interop/go.mod; expect "interop/go.mod требует golang.org/x/mod" 0 $?

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp -r interop "$W/interop"
sed -i "s|=> \.\./|=> $(pwd)|" "$W/interop/go.mod"
cp "$W/interop/go.mod" "$W/go.mod.before"
out="$(cd "$W/interop" && GOPROXY=off GOFLAGS=-mod=readonly go test -count=1 ./... 2>&1)"; code=$?
[ "$code" -ne 0 ]; expect "go test interop без сети с -mod=readonly не проходит (код != 0)" 0 $?
echo "$out" | grep -q -E 'missing go.sum entry|go.sum'; expect "причина — отсутствие записей go.sum" 0 $?
cmp -s "$W/go.mod.before" "$W/interop/go.mod"; expect "go.mod во временной копии не изменён" 0 $?
echo "--- вывод go test (для протокола):"; echo "$out" | head -8

[ "$fails" -eq 0 ] && echo "C12: состояние «заблокировано» подтверждено" || { echo "C12: не выполнено ожиданий: $fails"; exit 1; }
