#!/usr/bin/env bash
# Контроль З14. README.md:3 — «Zero dependencies, Go standard library only.»
# (ядро = корневой модуль; interop/ — отдельный модуль и в заявление не входит).
# Поиск: `go list -deps -test` по всем пакетам корневого модуля, вывод —
# модули всех нестандартных пакетов. Ожидание: ровно один модуль — сам
# github.com/XtReL/trust-core. Плюс: в go.mod нет require/replace, go.sum нет.
# Подложено (во временной копии): локальный модуль example.com/ext, подключённый
# через require+replace и импортированный новым пакетом plant/ — тот же
# поиск обязан показать example.com/ext (иначе «0 внешних» ничего не значит).
# Сеть не нужна. Запуск из корня временной копии: bash acceptance/c14_no_deps.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}" GOPROXY=off
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }
modules() { go list -deps -test -f '{{if not .Standard}}{{with .Module}}{{.Path}}{{end}}{{end}}' ./... 2>&1 | sort -u | tr '\n' ' '; }

expect "модули нестандартных пакетов (core, включая тесты)" "github.com/XtReL/trust-core " "$(modules)"
expect "в go.mod нет require" 0 "$(grep -c -E '^\s*require\b|^\s*[a-z0-9.-]+\.[a-z]+/[^ ]+ +v[0-9]' go.mod)"
expect "в go.mod нет replace" 0 "$(grep -c -E '^\s*replace\b' go.mod)"
[ ! -e go.sum ]; expect "go.sum в корне отсутствует" 0 $?
expect "interop/ (отдельный модуль) не входит в ./... корня" 0 "$(go list ./... | grep -c '/interop')"

# подложенная зависимость
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp -r . "$W/copy"; rm -rf "$W/copy/.git" "$W/copy/acceptance"
mkdir "$W/ext" && printf 'module example.com/ext\n\ngo 1.22\n' > "$W/ext/go.mod" && printf 'package ext\n\nconst X = 1\n' > "$W/ext/ext.go"
printf '\nrequire example.com/ext v0.0.0\n\nreplace example.com/ext => %s\n' "$W/ext" >> "$W/copy/go.mod"
mkdir "$W/copy/plant" && printf 'package plant\n\nimport "example.com/ext"\n\nvar _ = ext.X\n' > "$W/copy/plant/plant.go"
planted="$(cd "$W/copy" && modules)"
expect "(контроль способности) тот же поиск находит подложенный example.com/ext" 1 "$(printf '%s' "$planted" | grep -c 'example.com/ext')"
expect "(контроль способности) go.mod-поиск require видит подложенный require" 1 "$(grep -c -E '^\s*require\b' "$W/copy/go.mod")"

[ "$fails" -eq 0 ] && echo "C14: все ожидания выполнены" || { echo "C14: не выполнено ожиданий: $fails"; exit 1; }
