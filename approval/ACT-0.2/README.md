# ACT-0.2 — независимая проверка trust-core

Объект: XtReL/trust-core @ `f419b0d1693e6d3c06b7effa813239d129f31d6d` (= `main`).
Ветка: `approval/act-0.2` от `main`. Код объекта не изменялся: все прогоны
велись во временных копиях (`git archive` в части 1, `git clone` в части 2
и для `run_all.sh`), ключи создавались там же и удалены вместе с ними.

## Итог

| Часть | Что | Результат |
|---|---|---|
| 1 | Q1: один пробел в записи | обнаруживается, код 1, `entries on disk do not match the signed checkpoint root (log was modified)` |
| 1 | Q2: переписанная история | с `-previous` обнаруживается (код 1, `history was rewritten...`); без него — нет (заявленное ограничение); **с пустым файлом `-previous` проверка молча пропускается, код 0 и `OK` — дефект** |
| 1 | Q3: коды выхода | нет `-log` → **1** (`VERIFICATION FAILED: open .../checkpoint`), нет `-log-pub` → **2**; с README (`2 — ошибка использования`) совпадает только второй случай |
| 1 | Собственные контроли | 3/3, код 0; 45/45 утверждений совпали с записанными заранее ожиданиями |
| 2 | sha256 контролей | 24/24 OK (+ 9/9 `reference/`) |
| 2 | `run_all.sh` | код 1: c13 = 3, TestC14c FAIL, E01 — 1 ожидание; все три — нет модуля `golang.org/x/mod` (офлайн), остальное зелёное |
| — | `scripts/check.sh` | код 1: `test` прошёл, `interop` упал по той же причине (офлайн) |

Подробно: `part1/EXPECTED.md`, `part1/RESULTS.md`, `part2/RESULTS.md`.

## Состав

```
part1/EXPECTED.md          ожидания, закоммичены до первого прогона (ceb2616)
part1/RESULTS.md           ответы на вопросы 1–3
part1/lib.sh, q1_*.sh, q2_*.sh, q3_*.sh, run_part1.sh   контроли (код 1 при расхождении)
part1/out/*.out            полный вывод каждого прогона
part2/sha256-check.out     сверка с docs/acceptance/MANIFEST.sha256 (acceptance/act-v0)
part2/run_all.out          сводка run_all.sh
part2/logs/*.log           полный вывод каждого прогона run_all.sh (LOGDIR)
part2/RESULTS.md           разбор
check.sh.out               полный вывод scripts/check.sh
MANIFEST.sha256            sha256 всех файлов этого каталога, кроме себя
```

Проверка манифеста: `cd approval/ACT-0.2 && sha256sum -c MANIFEST.sha256`.

## Окружение

Linux, go1.24.7 linux/amd64 (`GOTOOLCHAIN=local`, toolchain не загружался),
gcc 13.3.0, OpenSSL 3.0.13. Кэш модулей Go пуст; сеть для модулей задание
не разрешает, поэтому части 2 и check.sh запускались с `GOPROXY=off`.
Сеть не использовалась, кроме git fetch/push с origin.

## Открытые файлы

«Открыт» — содержимое показано мне целиком или частично. Пути объекта —
из копии `git archive f419b0d` во временном каталоге.

### Часть 1 (до любых файлов docs/acceptance/)

| Файл | Как |
|---|---|
| `CLAUDE.md` (рабочая копия, = объект) | подставлен средой в контекст при старте сессии; использовался как данные |
| `README.md` | прочитан целиком; контроль q3 выводит строку 45 через grep |
| `cmd/trustcore/main.go` | прочитан целиком; q3 выводит строку 4 через grep |
| `verify/verify.go` | целиком |
| `tlog/filelog/filelog.go` | целиком |
| `keys/keys.go` | целиком |
| `trustcore.go` | целиком |
| `attest/dsse.go` | целиком |
| `scripts/check.sh` | целиком |
| `examples/gatekeeper-scan.event.json` | целиком (шаблон события для контролей) |
| собственные файлы `approval/ACT-0.2/part1/*` | написаны и прочитаны мной |

В части 1 из docs/acceptance/ не открывалось ничего ни в одной ветке; имя
ветки `acceptance/act-v0` было видно только в выводе `git ls-remote`.

### Часть 2 (после push части 1)

Ветка `origin/acceptance/act-v0` @ `3647200`:

| Файл | Как |
|---|---|
| `docs/acceptance/MANIFEST.sha256` | показан список путей (2-й столбец) всех 66 строк и первые 3 строки целиком; использован для `sha256sum -c` |
| `docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh` | целиком |
| `docs/acceptance/controls/ACT-0.2-trust-core/README.md` | целиком |
| `docs/acceptance/controls/ACT-0.2-trust-core/c13_interop.sh` | строки 1–60 |
| остальные 21 файл в `controls/ACT-0.2-trust-core/` | не читались; показаны только строки, совпавшие с поиском `curl|wget|https?://|git push|ssh |rm -rf|sudo|GOPROXY|nc |/dev/tcp|go (get|install|mod download)`; выполнены через `run_all.sh` |
| `docs/acceptance/reference/**` (9 файлов) | не читались; только извлечены и сверены по sha256 |

Не открывались вовсе: `docs/acceptance/ACT-0.2-trust-core.md` (акт),
`docs/acceptance/logs/**` и прочие файлы ветки `acceptance/act-v0`.

Собственный вывод части 2: `part2/run_all.out`, `check.sh.out`,
`part2/sha256-check.out` (целиком); `part2/logs/c13_interop.log` (целиком);
`part2/logs/go-test.log` (фрагмент TestC14c); `part2/logs/e01_environment.log`
(строки с FAIL); остальные `part2/logs/*.log` — только grep на приватные
ключи (не найдены) и размер `go-vet.log` (0 байт).
