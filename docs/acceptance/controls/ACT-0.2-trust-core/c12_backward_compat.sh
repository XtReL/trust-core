#!/usr/bin/env bash
# Контроль З12. docs/adr/0002-key-rotation.md:75-77 — «Существующий журнал =
# эпоха 1; verify.Log, trustcore verify и формат на диске не меняются.»
# (+ CLAUDE.md: журналы прежних версий проверяются новой версией — это
# правило, а не доказательство; доказательством служит прогон ниже.)
#
# Берёт из истории git коммит v0.1.0 (15fc79a; соответствие тегу v0.1.0
# наблюдалось через git ls-remote, см. шапку акта), собирает из него
# СТАРЫЙ бинарник, создаёт им журнал и проверяет этот журнал НОВЫМ.
#   1. старый журнал: new verify (с -previous), verify-chain (эпоха 1),
#      prove + verify-entry — все должны давать 0;
#   2. формат на диске: тот же набор ключей и событий, записанный НОВЫМ
#      бинарником, должен дать побайтно тот же каталог журнала (Ed25519 и
#      JSON детерминированы) — diff -r без расхождений;
#   3. закоммиченная фикстура testdata/v0.1.0-log проверяется новым
#      бинарником (3 записи, ключ журнала = ключ аттестатора);
#   4. контроль способности: подмена в старом журнале → новый verify даёт 1.
# Требуется git-клон (нужна история): запуск из корня временного клона:
#   bash acceptance/c12_backward_compat.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
OLD_REV="${OLD_REV:-15fc79afef0e8768cd37830bb29f10bd9054b5ce}"
git cat-file -e "$OLD_REV^{commit}" 2>/dev/null || { echo "нет коммита $OLD_REV в истории (нужен git clone, не архив)"; exit 1; }
R="$(pwd)"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
expect() { # name want got
  if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi
}
rc() { "$@" >/dev/null 2>&1; echo $?; }

mkdir "$W/old" && git archive "$OLD_REV" | tar -x -C "$W/old"
[ ! -d "$W/old/rotate" ] && [ ! -f "$W/old/verify/chain.go" ]; expect "старое дерево — до ротации (нет rotate/ и verify/chain.go)" 0 $?
(cd "$W/old" && go build -o "$W/trustcore-old" ./cmd/trustcore) || { echo "не собрался старый бинарник"; exit 1; }
(cd "$R" && go build -o "$W/trustcore-new" ./cmd/trustcore) || { echo "не собрался новый бинарник"; exit 1; }
OLD="$W/trustcore-old"; NEW="$W/trustcore-new"
expect "старый бинарник не знает rotate (подтверждает, что это старая версия)" 2 "$(rc "$OLD" rotate)"

O=github.com/example/compat/v1
EV1="$R/examples/gatekeeper-scan.event.json"
sed 's/3f786850e387550fdab836ed7e6dc881de23001b/0000000000000000000000000000000000000001/' "$EV1" > "$W/ev2.json"
cd "$W"
"$OLD" keygen -out log -name $O >/dev/null && "$OLD" keygen -out att >/dev/null || exit 1
"$OLD" init -log lg-old -origin $O -log-key log.key >/dev/null || exit 1
for e in "$EV1" "$W/ev2.json"; do "$OLD" record -log lg-old -origin $O -log-key log.key -key att.key -event "$e" >/dev/null || exit 1; done
cp lg-old/checkpoint kept-checkpoint
"$OLD" record -log lg-old -origin $O -log-key log.key -key att.key -event "$EV1" >/dev/null || exit 1
"$OLD" verify -log lg-old -origin $O -log-pub log.pub -attester-pub att.pub >/dev/null; expect "старый verify принимает старый журнал" 0 $?

# 1. новый бинарник проверяет старый журнал
expect "новый verify -previous: старый журнал" 0 "$(rc "$NEW" verify -log lg-old -origin $O -log-pub log.pub -attester-pub att.pub -previous kept-checkpoint)"
cat > manifest.json <<JSON
{"base":"$O","epochs":[{"epoch":1,"log":"lg-old","publicKey":"log.pub","attesterKeys":["att.pub"],"lastKnownCheckpoint":"kept-checkpoint"}]}
JSON
expect "новый verify-chain: старый журнал как эпоха 1" 0 "$(rc "$NEW" verify-chain -manifest manifest.json)"
"$OLD" prove -log lg-old -index 1 > proof.json
expect "новый verify-entry: доказательство старого prove" 0 "$(rc "$NEW" verify-entry -entry lg-old/entries/00000000000000000001.json -proof proof.json -origin $O -log-pub log.pub -attester-pub att.pub)"

# 2. побайтная стабильность формата на диске
"$NEW" init -log lg-new -origin $O -log-key log.key >/dev/null || exit 1
for e in "$EV1" "$W/ev2.json" "$EV1"; do "$NEW" record -log lg-new -origin $O -log-key log.key -key att.key -event "$e" >/dev/null || exit 1; done
diff -r -x '.tmp-*' -x .lock lg-old lg-new >/dev/null; expect "тот же ввод, старый и новый record: каталог журнала побайтно совпадает" 0 $?
[ -n "$(ls lg-new/entries)" ]; expect "(контроль способности diff: каталог не пуст)" 0 $?
mkdir lg-diff && cp -r lg-new/. lg-diff/ && printf ' ' >> lg-diff/entries/00000000000000000000.json
diff -r -x '.tmp-*' -x .lock lg-old lg-diff >/dev/null; expect "(контроль способности diff: подмена одного пробела видна)" 1 $?

# 3. закоммиченная фикстура
FX="$R/testdata/v0.1.0-log"
FO=github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1
out="$("$NEW" verify -log "$FX/log" -origin $FO -log-pub "$FX/log.pub" -attester-pub "$FX/log.pub" 2>&1)"; code=$?
expect "новый verify: фикстура testdata/v0.1.0-log" 0 "$code"
echo "$out" | grep -q '^size:      3$'; expect "фикстура: размер 3" 0 $?
expect "новый verify-chain: фикстура" 0 "$(rc "$NEW" verify-chain -manifest "$FX/manifest.json")"

# 4. контроль способности самой проверки
printf ' ' >> lg-old/entries/00000000000000000000.json
expect "(контроль способности) подмена в старом журнале → новый verify даёт 1" 1 "$(rc "$NEW" verify -log lg-old -origin $O -log-pub log.pub -attester-pub att.pub)"

[ "$fails" -eq 0 ] && echo "C12: все ожидания выполнены" || { echo "C12: не выполнено ожиданий: $fails"; exit 1; }
