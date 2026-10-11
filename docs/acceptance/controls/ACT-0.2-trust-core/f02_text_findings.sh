#!/usr/bin/env bash
# Контроли находок вне заявлений, основанные на поиске по тексту (Текст).
# Каждый результат «0»/«нет» сопровождён подложенным случаем во временной
# копии, который тот же поиск обязан найти (правило 1 методики).
#   F05 соответствие CLAUDE.md «Actions только по полным SHA»: число
#       строк `uses:` без 40-символьного SHA в .github/workflows;
#   F06 PROGRESS.md ссылается на правила в CLAUDE.md (энтропия тестового
#       токена, запрет `git config --global`), которых в CLAUDE.md нет;
#   F07 ADR 0002 (docs/adr/0002-key-rotation.md:22) называет развилку
#       «сигналом тревоги», в коде (*.go) обработки развилки нет;
#   F08 CI использует плавающий go-version: stable (число вхождений).
# Запуск (из корня временной копии, нужна не git-история, а только файлы):
#   bash acceptance/f02_text_findings.sh
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0
expect() { if [ "$3" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: ожидалось '$2', получено '$3'"; fails=$((fails+1)); fi; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp -r . "$W/plant"; rm -rf "$W/plant/.git" "$W/plant/acceptance"

unpinned() { grep -rhE '^\s*-?\s*uses:' "$1/.github/workflows" | grep -vE '@[0-9a-f]{40}(\s|$)' | wc -l | tr -d ' '; }
allUses() { grep -rhE '^\s*-?\s*uses:' "$1/.github/workflows" | wc -l | tr -d ' '; }
echo "F05: всего uses: $(allUses .)"
expect "F05 строк uses: без полного SHA в реальных workflow" 0 "$(unpinned .)"
printf '      - uses: actions/checkout@v4\n' >> "$W/plant/.github/workflows/ci.yml"
expect "F05 (контроль способности) подложенный uses: @v4 найден тем же поиском" 1 "$(unpinned "$W/plant")"
cp .github/workflows/ci.yml "$W/plant/.github/workflows/ci.yml"

# без -i: регистр кириллицы зависит от локали, поэтому варианты регистра перечислены явно
n() { grep -c -E "$1" "$2"; }
expect "F06 PROGRESS.md упоминает правило про энтропию" 1 "$([ "$(n 'энтропи|Энтропи' PROGRESS.md)" -gt 0 ] && echo 1 || echo 0)"
expect "F06 PROGRESS.md упоминает запрет git config --global" 1 "$([ "$(n 'git config --global' PROGRESS.md)" -gt 0 ] && echo 1 || echo 0)"
expect "F06 в CLAUDE.md нет слова «энтроп» (число вхождений)" 0 "$(n 'энтроп|Энтроп' CLAUDE.md)"
expect "F06 в CLAUDE.md нет «git config» (число вхождений)" 0 "$(n 'git config' CLAUDE.md)"
printf '%s\n' '- Энтропия тестового токена не ниже порога правила.' '- Не использовать git config --global.' >> "$W/plant/CLAUDE.md"
expect "F06 (контроль способности) подложенные строки найдены в CLAUDE.md" 2 "$(( $(n 'энтроп|Энтроп' "$W/plant/CLAUDE.md") + $(n 'git config' "$W/plant/CLAUDE.md") ))"

gof() { grep -rnE 'fork|Fork|развилк|Развилк' --include='*.go' "$1" | wc -l | tr -d ' '; }
expect "F07 ADR 0002 упоминает развилку" 1 "$([ "$(n 'развилк|Развилк' docs/adr/0002-key-rotation.md)" -gt 0 ] && echo 1 || echo 0)"
expect "F07 в *.go нет обработки развилки (число совпадений fork|развилк)" 0 "$(gof .)"
mkdir -p "$W/plant/zz" && printf 'package zz\n\n// fork detection lives here\n' > "$W/plant/zz/zz.go"
expect "F07 (контроль способности) подложенный комментарий найден тем же поиском" 1 "$(gof "$W/plant")"

expect "F08 вхождений go-version: stable в ci.yml" 2 "$(n 'go-version: stable' .github/workflows/ci.yml)"
expect "F08 go.mod: директива go" "go 1.22" "$(grep -E '^go ' go.mod)"

[ "$fails" -eq 0 ] && echo "F-text: все ожидания выполнены" || { echo "F-text: не выполнено ожиданий: $fails"; exit 1; }
