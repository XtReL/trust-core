#!/usr/bin/env bash
# Воспроизведение трёх первоначальных «красных» прогонов (раздел «Процесс» акта):
# для каждого показано, что причина в контроле, а не в коде репозитория.
#   (a) c15 сценарий 13 («verify-entry с чужой записью дал 0»): две записи были
#       побайтно одинаковы, поэтому «чужая» запись — те же байты; код вёл себя верно.
#   (b) c11_gitignore, функция поиска по истории (IndexError): python вызывал
#       `git show` вне клона, `git show` не находил ревизию, список строк был пуст.
#   (c) f02 F06 (подложенная строка с заглавной «Энтропия» не найдена): `grep -i`
#       для кириллицы зависит от локали; в локали C регистр не сворачивается.
# Запуск (из корня временной копии/клона): bash acceptance/p01_red_runs_repro.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
R="$(pwd)"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }
go build -o "$W/tc" ./cmd/trustcore || exit 1
T="$W/tc"; O=repro.invalid/log

echo "## (a) одинаковые события → одинаковые записи"
cd "$W"
"$T" keygen -out log >/dev/null && "$T" keygen -out att >/dev/null && "$T" init -log lg -origin $O -log-key log.key >/dev/null
for i in 1 2; do "$T" record -log lg -origin $O -log-key log.key -key att.key -event "$R/examples/gatekeeper-scan.event.json" >/dev/null; done
cmp -s lg/entries/00000000000000000000.json lg/entries/00000000000000000001.json; expect "записи 0 и 1 побайтно совпадают (Ed25519 и JSON детерминированы)" 0 $?
"$T" prove -log lg -index 1 > proof.json
"$T" verify-entry -entry lg/entries/00000000000000000000.json -proof proof.json -origin $O -log-pub log.pub -attester-pub att.pub >/dev/null; expect "verify-entry: байты записи 0 с доказательством индекса 1 принимаются (верно: тот же лист)" 0 $?
sed 's/3f786850e387550fdab836ed7e6dc881de23001b/0000000000000000000000000000000000000001/' "$R/examples/gatekeeper-scan.event.json" > ev2.json
"$T" init -log lg2 -origin $O -log-key log.key >/dev/null
"$T" record -log lg2 -origin $O -log-key log.key -key att.key -event "$R/examples/gatekeeper-scan.event.json" >/dev/null
"$T" record -log lg2 -origin $O -log-key log.key -key att.key -event ev2.json >/dev/null
"$T" prove -log lg2 -index 1 > proof2.json
"$T" verify-entry -entry lg2/entries/00000000000000000000.json -proof proof2.json -origin $O -log-pub log.pub -attester-pub att.pub >/dev/null 2>&1; expect "после замены второго события: чужая запись → код 1" 1 $?

echo "## (b) git show вне клона"
(cd "$W" && git show HEAD:README.md >/dev/null 2>&1); expect "git show из каталога вне клона не находит ревизию (код 128)" 128 $?
(cd "$R" && git show HEAD:README.md >/dev/null 2>&1); expect "(контроль способности) git show внутри клона находит ревизию" 0 $?

echo "## (c) регистр кириллицы в grep -i зависит от локали"
n_c="$(printf 'Энтропия\n' | LC_ALL=C grep -c -i 'энтроп')"
expect "LC_ALL=C: grep -i не находит «Энтропия» по шаблону «энтроп»" 0 "$n_c"
n_ex="$(printf 'Энтропия\n' | LC_ALL=C grep -c -E 'энтроп|Энтроп')"
expect "LC_ALL=C: явное перечисление регистров находит (способ, принятый в f02)" 1 "$n_ex"

[ "$fails" -eq 0 ] && echo "P01: все ожидания выполнены" || { echo "P01: не выполнено ожиданий: $fails"; exit 1; }
