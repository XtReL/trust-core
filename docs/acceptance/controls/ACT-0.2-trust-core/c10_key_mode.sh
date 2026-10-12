#!/usr/bin/env bash
# Контроль З10. README.md:122 — «Приватные ключи (*.key) ... создаются с
# правами 0600.» (первая половина строки, «исключены через .gitignore»,
# проверяется отдельно: З11, способ Текст.)
# Способ: Прогон — запускается собранный из временной копии `trustcore keygen`.
#   1. права файла *.key после keygen — 600 при umask 000 и при umask 022;
#   2. keygen не перезаписывает существующий ключ (код != 0, файл не изменён);
#   3. контроль способности: файл, созданный без keygen при umask 022, имеет
#      права 644 — то есть проверка прав умеет отвечать «не 600».
# Сеть не нужна. Запуск (из корня временной копии): bash acceptance/c10_key_mode.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--mod=readonly}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }

go build -o "$W/tc" ./cmd/trustcore || exit 1
for um in 000 022; do
  (umask $um; mkdir -p "$W/k$um" && cd "$W/k$um" && "$W/tc" keygen -out k >/dev/null)
  expect "права k.key после keygen при umask $um" 600 "$(stat -c %a "$W/k$um/k.key")"
done
before="$(sha256sum "$W/k000/k.key")"
(cd "$W/k000" && "$W/tc" keygen -out k >/dev/null 2>&1); code=$?
expect "повторный keygen на существующий ключ: код != 0" 1 "$([ "$code" -ne 0 ] && echo 1 || echo 0)"
expect "существующий ключ не изменён" "$before" "$(sha256sum "$W/k000/k.key")"
(umask 022; : > "$W/plain.key")
expect "(контроль способности) файл без keygen при umask 022 имеет права" 644 "$(stat -c %a "$W/plain.key")"

[ "$fails" -eq 0 ] && echo "C10: все ожидания выполнены" || { echo "C10: не выполнено ожиданий: $fails"; exit 1; }
