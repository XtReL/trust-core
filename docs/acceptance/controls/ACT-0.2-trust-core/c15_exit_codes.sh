#!/usr/bin/env bash
# Контроль З15. README.md:45 — «Коды выхода: 0 — всё проверено, 1 — проверка
# не прошла, 2 — ошибка использования.»
# Собирает CLI из временной копии и прогоняет сценарии. Для каждого
# сценария ожидаемый код записан в таблице и проверяется (exit 1 при любом
# расхождении). Сценарии 1 и 3–4 подкладывают подмену и должны давать 1;
# 5–9 — ошибки использования, должны давать 2.
# Сценарий D1 утверждает НАБЛЮДАЕМЫЙ ДЕФЕКТ (заявление опровергнуто в этой
# части): несуществующий каталог журнала -log даёт 1 вместо 2. После
# исправления кода D1 покраснеет — это ожидаемо, ожидание тогда меняется на 2.
# Запуск (из корня временной копии): bash acceptance/c15_exit_codes.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
T="$W/trustcore"; go build -o "$T" ./cmd/trustcore || { echo "build failed"; exit 1; }
O=acceptance.invalid/log
EV=examples/gatekeeper-scan.event.json
cd "$W"
"$T" keygen -out log -name $O >/dev/null && "$T" keygen -out att >/dev/null &&
"$T" init -log lg -origin $O -log-key log.key >/dev/null &&
"$T" record -log lg -origin $O -log-key log.key -key att.key -event "$OLDPWD/$EV" >/dev/null &&
sed 's/3f786850e387550fdab836ed7e6dc881de23001b/0000000000000000000000000000000000000001/' "$OLDPWD/$EV" > ev2.json &&
"$T" record -log lg -origin $O -log-key log.key -key att.key -event ev2.json >/dev/null || { echo "setup failed"; exit 1; }
# записи 0 и 1 различаются (иначе «чужая» запись была бы побайтно той же)
cmp -s lg/entries/00000000000000000000.json lg/entries/00000000000000000001.json && { echo "setup: entries identical"; exit 1; }
cat > manifest.json <<JSON
{"base":"$O","epochs":[{"epoch":1,"log":"lg","publicKey":"log.pub","attesterKeys":["att.pub"]}]}
JSON
"$T" keygen -out other >/dev/null
cp -r lg lg-tampered && printf ' ' >> lg-tampered/entries/00000000000000000000.json
sed 's#"lg"#"lg-tampered"#' manifest.json > manifest-tampered.json
echo '{bad' > manifest-bad.json

fails=0
check() { # name expected command...
  local name="$1" want="$2"; shift 2
  "$@" >/dev/null 2>"$W/err"; local got=$?
  if [ "$got" -eq "$want" ]; then echo "ok    $name: exit $got"
  else echo "FAIL  $name: expected exit $want, got $got ($(head -c 120 "$W/err" | head -1))"; fails=$((fails+1)); fi
}
V=("$T" verify -origin $O -log-pub log.pub -attester-pub att.pub)
check "1 verify tampered log"            1 "${V[@]}" -log lg-tampered
check "2 verify honest log (baseline)"   0 "${V[@]}" -log lg
check "3 verify wrong log key"           1 "$T" verify -log lg -origin $O -log-pub other.pub -attester-pub att.pub
check "4 verify wrong origin"            1 "$T" verify -log lg -origin other.invalid/x -log-pub log.pub -attester-pub att.pub
check "5 missing required flag"          2 "$T" verify -log lg -origin $O
check "6 unknown command"                2 "$T" bogus
check "7 undefined flag"                 2 "$T" verify -bogusflag
check "8 unreadable -log-pub"            2 "$T" verify -log lg -origin $O -log-pub nope.pub -attester-pub att.pub
check "9 malformed manifest"             2 "$T" verify-chain -manifest manifest-bad.json
check "10 verify-chain honest"           0 "$T" verify-chain -manifest manifest.json
check "11 verify-chain tampered"         1 "$T" verify-chain -manifest manifest-tampered.json
"$T" prove -log lg -index 1 > proof.json
check "12 verify-entry honest"           0 "$T" verify-entry -entry lg/entries/00000000000000000001.json -proof proof.json -origin $O -log-pub log.pub -attester-pub att.pub
check "13 verify-entry wrong entry"      1 "$T" verify-entry -entry lg/entries/00000000000000000000.json -proof proof.json -origin $O -log-pub log.pub -attester-pub att.pub
# D1: наблюдаемый дефект — несуществующий каталог журнала (ошибка использования/ввода-вывода) даёт 1, а не 2.
check "D1 verify, nonexistent -log dir (observed defect: 1, README.md:45 and main.go:4 imply 2)" 1 "${V[@]}" -log does-not-exist
[ "$fails" -eq 0 ] && echo "C15: all expectations held" || { echo "C15: $fails expectation(s) failed"; exit 1; }
