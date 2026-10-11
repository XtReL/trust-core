#!/usr/bin/env bash
# Контроль окружения акта (шапка, «Окружение»): подтверждает утверждения
# «автозагрузок toolchain: 0» и «загрузок модулей Go: 0».
#   1. go.mod и interop/go.mod: директива go не выше установленного toolchain,
#      директивы toolchain нет — при GOTOOLCHAIN=auto загрузка не потребовалась бы;
#   2. подложено: копия с `go 1.99` при GOTOOLCHAIN=local — та же команда
#      `go list` обязана сообщить, что нужен более новый toolchain (то есть
#      требование к toolchain обнаруживается, а не «молча 0»);
#   3. нет каталога toolchain в кэше модулей, и в кэше нет файлов модулей
#      (файлы *.lock, создаваемые заблокированной попыткой, не считаются);
#      подложено: файл во временном кэше тот же поиск находит.
# Сеть не нужна. Запуск (из корня временной копии): bash acceptance/e01_environment.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS="${GOFLAGS:--mod=readonly}"
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }

have="$(GOTOOLCHAIN=local go env GOVERSION | sed 's/^go//')"
for f in go.mod interop/go.mod; do
  want="$(awk '/^go /{print $2}' "$f")"
  [ -n "$want" ] && [ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" = "$want" ]; expect "$f: go '$want' <= установленного $have" 0 $?
  expect "$f: директивы toolchain нет (число строк)" 0 "$(grep -c -E '^toolchain ' "$f")"
done

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir "$W/plant" && printf 'module example.com/plant\n\ngo 1.99\n' > "$W/plant/go.mod" && printf 'package plant\n' > "$W/plant/p.go"
out="$(cd "$W/plant" && GOTOOLCHAIN=local go list ./... 2>&1)"
echo "$out" | grep -q -E 'requires go >= 1\.99'; expect "(контроль способности) требование go 1.99 при GOTOOLCHAIN=local обнаружено" 0 $?

cache="$(GOTOOLCHAIN=local go env GOMODCACHE)"
mods() { find "$1" -type f ! -name '*.lock' 2>/dev/null | wc -l | tr -d ' '; }
expect "файлов модулей в кэше $cache (без *.lock)" 0 "$(mods "$cache")"
expect "каталогов golang.org/toolchain* в кэше" 0 "$(find "$cache" -maxdepth 2 -name 'toolchain*' 2>/dev/null | wc -l | tr -d ' ')"
mkdir -p "$W/fakecache/golang.org/x/mod@v0.0.0" && : > "$W/fakecache/golang.org/x/mod@v0.0.0/go.mod"
expect "(контроль способности) подложенный файл модуля тем же поиском найден" 1 "$(mods "$W/fakecache")"

[ "$fails" -eq 0 ] && echo "E01: все ожидания выполнены" || { echo "E01: не выполнено ожиданий: $fails"; exit 1; }
