#!/usr/bin/env bash
# Контроль З10. README.md:122 — «Приватные ключи (*.key) исключены через
# .gitignore и создаются с правами 0600. Никогда не коммитьте их».
# Проверяет три вещи, каждую с подложенным положительным случаем:
#   1. keygen создаёт *.key с правами 600 (в том числе при umask 000);
#   2. .gitignore игнорирует *.key (git check-ignore); подложенный
#      не-ключевой файл (*.pem) НЕ игнорируется — поиск способен отвечать «нет»;
#   3. в репозитории (все коммиты всех веток) нет приватных ключей:
#      (а) нет файлов *.key, (б) нет заголовка PEM PRIVATE KEY, (в) нет
#      тела ключа Ed25519 PKCS#8 (21-символьный base64-префикс DER; сам префикс в этом
#      файле разбит на части, чтобы скрипт не находил сам себя в истории).
#      Подложено: во временном клоне закоммитирован сгенерированный
#      одноразовый ключ в файл leaked.txt — тот же поиск обязан его найти.
# Секреты не выводятся: только rev:путь:строка, длина и энтропия
# (бит/символ) совпавшего токена.
# Нужен git-клон. Запуск из корня временного клона:
#   bash acceptance/c10_private_keys.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
R="$(pwd)"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }

go build -o "$W/tc" ./cmd/trustcore || exit 1

# 1. права на файл ключа
for um in 000 022; do
  (umask $um; mkdir -p "$W/k$um" && cd "$W/k$um" && "$W/tc" keygen -out k >/dev/null)
  expect "права k.key при umask $um" 600 "$(stat -c %a "$W/k$um/k.key")"
done
(cd "$W/k000" && "$W/tc" keygen -out k >/dev/null 2>&1); expect "keygen не перезаписывает существующий ключ (код != 0)" 0 $([ $? -ne 0 ]; echo $?)

# 2. .gitignore
git check-ignore -q -- keys/log.key; expect ".gitignore игнорирует keys/log.key" 0 $?
git check-ignore -q -- keys/log.pem; expect "(контроль способности) .gitignore НЕ игнорирует keys/log.pem" 1 $?

# 3. поиск приватных ключей по всей истории
scan() { # каталог-клон; печатает только rev:путь:строка, длину и энтропию
  ( cd "$1" && { git rev-list --all | while read -r rev; do
      git grep -I -n -o -E -e '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' -e 'MC4CAQAw''BQYDK2Vw''BCIEI' "$rev" -- 2>/dev/null
    done
    git log --all --name-only --format= | grep -E '\.key$' | sort -u | sed 's/^/FILE:/'; } |
  python3 -I -c '
import math, re, subprocess, sys
seen = {}
for raw in sys.stdin.read().splitlines():
    if raw.startswith("FILE:"):
        key = ("file", raw[5:], 0, 0, 0.0); seen.setdefault(key, [raw[5:], 0])
        continue
    head, line, match = raw.rsplit(":", 2)
    rev, path = head.split(":", 1)
    blob = subprocess.run(["git", "show", rev + ":" + path], capture_output=True, text=True).stdout.splitlines()
    n = int(line)
    if match.startswith("-----BEGIN"):
        body = ""
        for l in blob[n:]:
            if l.startswith("-----END"): break
            body += l.strip()
        kind = "header"
    else:
        m = re.search(r"MC4CAQAw" r"BQYDK2Vw" r"BCIEI" r"[A-Za-z0-9+/=]*", blob[n - 1])
        body = m.group(0) if m else ""
        kind = "body-prefix"
    ent = 0.0
    if body:
        ent = -sum((body.count(c) / len(body)) * math.log2(body.count(c) / len(body)) for c in set(body))
    k = (kind, path, n, len(body), round(ent, 2))
    if k not in seen: seen[k] = [rev[:7], 0]
    seen[k][1] += 1
for k, (rev, cnt) in sorted(seen.items()):
    if k[0] == "file": print("hit kind=tracked-*.key path=%s" % k[1])
    else: print("hit kind=%s %s:%s:%d len=%d entropy=%.2f bits/char (revs=%d)" % (k[0], rev, k[1], k[2], k[3], k[4], cnt))
' )
}
real="$(scan "$R")"
expect "в реальной истории нет приватных ключей и файлов *.key (число находок)" 0 "$(printf '%s' "$real" | grep -c '^hit')"

git clone --quiet "$R" "$W/planted" || exit 1
( cd "$W/k000" && cp k.key "$W/planted/leaked.txt" )
( cd "$W/planted" && git add leaked.txt && git -c user.name=acc -c user.email=acc@example.invalid commit -q -m "planted one-off test key" )
hits="$(scan "$W/planted")"
echo "--- подложенный случай (только путь:строка, длина, энтропия):"; echo "$hits"
expect "(контроль способности) тот же поиск находит подложенный заголовок PEM" 1 "$(printf '%s\n' "$hits" | grep -c 'kind=header .*leaked.txt:1 ')"
expect "(контроль способности) тот же поиск находит подложенное тело ключа" 1 "$(printf '%s\n' "$hits" | grep -c 'kind=body-prefix')"
( cd "$W/planted" && git mv leaked.txt planted.key 2>/dev/null; git -c user.name=acc -c user.email=acc@example.invalid commit -q -am "rename to .key" 2>/dev/null; true )
expect "(контроль способности) отслеживаемый/исторический *.key находится" 1 "$(scan "$W/planted" | grep -c 'kind=tracked-\*\.key')"

[ "$fails" -eq 0 ] && echo "C10: все ожидания выполнены" || { echo "C10: не выполнено ожиданий: $fails"; exit 1; }
