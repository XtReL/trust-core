#!/usr/bin/env bash
# Контроль З13. README.md:130 — «Совместимость проверяется тестами в
# `interop/`: наши чекпоинты открываются эталонной реализацией Go, её
# заметки — нашей, корни и доказательства совпадают поэлементно.»
# Способ: Прогон — запускаются тесты interop/ репозитория в ОДНОРАЗОВОЙ копии.
#
# СЕТЬ: нужна только для загрузки модулей Go (golang.org/x/mod, `go mod tidy`);
# если модули уже в кэше, сеть не используется. Репозиторий не меняется:
# interop/go.sum создаётся только в одноразовой копии.
# Если загрузка невозможна, скрипт завершается кодом 3 («Н: сеть недоступна»).
#
# Что проверяется:
#   1. `go mod tidy` в interop/ копии завершается кодом 0; печатаются sha256
#      созданного go.sum, диф interop/go.mod до/после tidy и версии модулей;
#   2. `go test -v ./...` в interop/: PASS у TestOurNoteOpensWithReference,
#      TestReferenceNoteOpensWithOurs, TestMerkleMatchesReference;
#   3. контроль способности (тесты не проходят вхолостую): в другой копии (go.mod и
#      go.sum из п.1, без сети) ломается NodeHash (префикс 0x01 → 0x02) — обязан
#      упасть TestMerkleMatchesReference; ломается хэш ключа в vkey ("\n" → "\r")
#      — обязан упасть TestOurNoteOpensWithReference.
# Запуск (из корня временной копии/клона): bash acceptance/c13_interop.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
R="$(pwd)"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }

copy_root() { mkdir -p "$1" && tar -C "$R" --exclude=.git --exclude=acceptance -cf - . | tar -C "$1" -xf -; }
copy_root "$W/main"
cd "$W/main/interop" || exit 1
[ ! -e go.sum ]; expect "в копии нет interop/go.sum до tidy (как в репозитории)" 0 $?
cp go.mod "$W/go.mod.before"
echo "# дата и время (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# GOPROXY=$(go env GOPROXY) GOSUMDB=$(go env GOSUMDB)"
echo '$ go mod tidy'
out="$(go mod tidy 2>&1)"; code=$?
echo "$out"
if [ "$code" -ne 0 ]; then
  echo "$out" | grep -q -E 'lookup disabled|dial tcp|Forbidden|403|timeout|no such host|proxyconnect' && { echo "Н: сеть недоступна для загрузки модулей Go"; exit 3; }
fi
expect "go mod tidy: код выхода" 0 "$code"
[ -e go.sum ]; expect "(контроль способности проверки наличия) после tidy interop/go.sum создан — тот же тест наличия файла его находит" 0 $?
echo "# sha256 созданного interop/go.sum:"; sha256sum go.sum
echo "# содержимое interop/go.sum (строк: $(wc -l < go.sum)):"; cat go.sum
echo "# диф interop/go.mod (до → после tidy):"; diff "$W/go.mod.before" go.mod || true
echo "# версии модулей (go list -m all):"; go list -m all 2>&1
echo '$ go test -count=1 -v ./...'
tout="$(go test -count=1 -v ./... 2>&1)"; tcode=$?
echo "$tout"
expect "go test interop: код выхода" 0 "$tcode"
for t in TestOurNoteOpensWithReference TestReferenceNoteOpensWithOurs TestMerkleMatchesReference; do
  echo "$tout" | grep -q -- "--- PASS: $t "; expect "PASS: $t" 0 $?
done

# контроль способности
mutated() { # имя файл старое новое тест
  copy_root "$W/$1"; cp "$W/main/interop/go.mod" "$W/main/interop/go.sum" "$W/$1/interop/"
  python3 -I - "$W/$1/$2" "$3" "$4" <<'EOF' || return 2
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if s.count(old) != 1: sys.exit("pattern count != 1")
open(p, "w").write(s.replace(old, new))
EOF
  (cd "$W/$1/interop" && GOFLAGS=-mod=readonly GOPROXY=off go test -count=1 -run "$5" -v ./... 2>&1)
}
mo="$(mutated m1 tlog/merkle.go 'h.Write([]byte{0x01})' 'h.Write([]byte{0x02})' TestMerkleMatchesReference)"
echo "$mo" | grep -q -- "--- FAIL: TestMerkleMatchesReference"; expect "(контроль способности) мутация NodeHash краснит TestMerkleMatchesReference" 0 $?
mo="$(mutated m2 tlog/checkpoint.go 'h.Write([]byte("\n"))' 'h.Write([]byte("\r"))' TestOurNoteOpensWithReference)"
echo "$mo" | grep -q -- "--- FAIL: TestOurNoteOpensWithReference"; expect "(контроль способности) мутация хэша ключа краснит TestOurNoteOpensWithReference" 0 $?

[ "$fails" -eq 0 ] && echo "C13: все ожидания выполнены" || { echo "C13: не выполнено ожиданий: $fails"; exit 1; }
