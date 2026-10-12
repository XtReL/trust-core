#!/usr/bin/env bash
# Запускает все контроли акта ACT-0.2-trust-core во ВРЕМЕННОМ клоне
# репозитория (рабочая копия репозитория не затрагивается).
# Сеть: только загрузка модулей Go в c13_interop.sh (если модулей нет в кэше).
# Код выхода 0 — ВСЕ ожидания акта выполнены (включая ожидания о наблюдаемых
# дефектах: после исправления кода соответствующие контроли покраснеют, это
# ожидаемо — см. README.md этой папки).
# Переменная LOGDIR (необязательная): в неё сохраняется ПОЛНЫЙ вывод каждого
# прогона отдельным файлом (go-vet.log, go-test.log, <контроль>.log); на экран
# выводится только краткая сводка.
# Использование (из любого места):
#   LOGDIR=/путь bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
[ -n "${LOGDIR:-}" ] && mkdir -p "$LOGDIR"
git clone --quiet "$REPO" "$W/copy" || exit 1
mkdir "$W/copy/acceptance"
for f in "$HERE"/*_test.go.txt; do cp "$f" "$W/copy/acceptance/$(basename "$f" .txt)"; done
for f in "$HERE"/c*.sh "$HERE"/e01_*.sh "$HERE"/s01_*.sh "$HERE"/f02_*.sh "$HERE"/p01_*.sh; do cp "$f" "$W/copy/acceptance/"; done
cp -r "$REPO/docs/acceptance/reference" "$W/copy/acceptance/reference"
cd "$W/copy" || exit 1
echo "# коммит клона: $(git rev-parse HEAD)"
echo "# начало: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
rc=0
run() { # имя-лога команда...
  local name="$1"; shift
  if [ -n "${LOGDIR:-}" ]; then "$@" >"$LOGDIR/$name.log" 2>&1; else "$@" 2>&1; fi
  return $?
}
echo "## go vet ./acceptance/"; run go-vet go vet ./acceptance/ || rc=1
echo "## go test ./acceptance/ -count=1 -v"
if [ -n "${LOGDIR:-}" ]; then
  go test ./acceptance/ -count=1 -v >"$LOGDIR/go-test.log" 2>&1; trc=$?
  grep -E '^(--- |PASS|FAIL|ok)' "$LOGDIR/go-test.log"
else
  go test ./acceptance/ -count=1 -v 2>&1 | grep -E '^(--- |PASS|FAIL|ok)'; trc=${PIPESTATUS[0]}
fi
[ "$trc" -eq 0 ] || rc=1
for s in e01_environment c10_key_mode c11_gitignore c12_backward_compat c13_interop c15_exit_codes s01_no_deps f02_text_findings p01_red_runs_repro; do
  echo "## bash acceptance/$s.sh"
  if [ -n "${LOGDIR:-}" ]; then
    bash "acceptance/$s.sh" >"$LOGDIR/$s.log" 2>&1; src=$?
    tail -1 "$LOGDIR/$s.log"
  else
    bash "acceptance/$s.sh"; src=$?
  fi
  [ "$src" -eq 0 ] || { echo "   код выхода $s: $src"; rc=1; }
done
echo "# конец: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ "$rc" -eq 0 ] && echo "RUN_ALL: все ожидания акта выполнены" || echo "RUN_ALL: есть невыполненные ожидания"
exit $rc
