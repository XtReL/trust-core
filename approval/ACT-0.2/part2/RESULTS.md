# ACT-0.2, часть 2 — повтор сохранённых контролей

Начата после коммита и push части 1: `c9bbc302b66f87b19ac4e4e4857443dc7017efa7`
(контроли и результаты) поверх `ceb2616` (ожидания, записанные до прогона).

## Источник и целостность

- Ветка `origin/acceptance/act-v0` @ `364720013cdb659e60e737e72f3753fdf02585cf`.
- Файлы `docs/acceptance/controls/ACT-0.2-trust-core/` (24 шт.) и
  `docs/acceptance/MANIFEST.sha256` извлечены через `git show` в отдельный
  временный каталог.
- Сверка: **24/24 OK** с манифестом из той же ветки, лишних файлов в
  каталоге нет. Полный вывод — `sha256-check.out`.
- `run_all.sh` копирует ещё `docs/acceptance/reference/` (эталонные
  спецификации для C14). Эти 9 файлов тоже извлечены через `git show` и
  сверены с тем же манифестом: **9/9 OK**.

## Копия объекта и запуск

- Копия: `git clone --no-local --single-branch --branch main` в временный
  каталог, `HEAD = f419b0d1693e6d3c06b7effa813239d129f31d6d`, теги v0.1.0 и
  v0.2.0 (нужна история: C11, C12). Контроли и `reference/` положены в
  `docs/acceptance/...` копии как неотслеживаемые файлы; `run_all.sh` сам
  делает из копии ещё один временный клон. Рабочая копия репозитория не
  затронута.
- Команда: `GOPROXY=off LOGDIR=<part2/logs> bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh`.
- `GOPROXY=off`: задание разрешает сеть только для загрузки toolchain Go;
  toolchain не потребовался (go1.24.7 локально, `GOTOOLCHAIN=local`). Кэш
  модулей Go пуст, поэтому всё, что требует `golang.org/x/mod`, в этом
  окружении выполнить нельзя.
- Перед запуском контроли просмотрены поиском на сетевые и разрушающие
  команды: только `rm -rf` своих `mktemp -d`, сеть — только `go mod tidy` в c13.

Вывод: `run_all.out` (сводка), `logs/*.log` (полный вывод каждого прогона).

## Результат: `RUN_ALL: есть невыполненные ожидания`, код 1

| Контроль | Результат | Причина |
|---|---|---|
| c13_interop.sh | **код 3** «Н: сеть недоступна» | `go mod tidy`: `module lookup disabled by GOPROXY=off` |
| go vet ./acceptance/ | OK (пустой вывод) | |
| C01–C09 | PASS (9/9) | |
| TestC14a, b, d, e, f, g, s | PASS (7) | |
| TestC14c | **FAIL** | `модуль golang.org/x/mod@v0.22.0 не загружен (запустите c13_interop.sh)` |
| F01, F02, F03, F04, F09 | PASS (5/5) — дефекты подтверждены | |
| e01_environment.sh | **1 ожидание не выполнено** | ожидалось `golang.org/x/mod@v0.22.0` в кэше модулей, получено пусто |
| c10, c11, c12, c15, s01, f02, p01 | все ожидания выполнены | |

Все три невыполненных ожидания имеют одну причину: в кэше нет модуля
`golang.org/x/mod@v0.22.0`, а загрузку модулей задание не разрешает.
Ни одно из них не указывает на поведение объекта. Чтобы закрыть их, нужно
повторить запуск с разрешённой загрузкой этого модуля (c13 загрузит его, после
чего C14c и E01 смогут проверить его наличие).

Сохранённые контроли подтвердили обе находки части 1, полученные до их
просмотра: `TestF01_EmptyPreviousDisablesRollbackCheck` — пустой `-previous`
отключает проверку истории (часть 1, вопрос 2); `c15_exit_codes.sh` сценарий
D1 — несуществующий `-log` даёт код 1 вопреки README (часть 1, вопрос 3).

`mutations.sh` не запускался: в задании указан только `run_all.sh`, а
`run_all.sh` его не вызывает.

## check.sh

Запущен на `git archive` копии ветки `approval/act-0.2` (объект + `approval/`)
с `GOPROXY=off GOTOOLCHAIN=local`. Полный вывод — `../check.sh.out`. Запуск был до
написания README.md/RESULTS.md части 2 и манифеста; после него добавлены
только .md и MANIFEST.sha256, ни одного файла .go.

- `job: test` — **прошёл**: gofmt (чисто), `go vet ./...` (чисто),
  `go test -race -count=1 ./...` (все пакеты ok), demo — `DEMO PASSED`.
- `job: interop` — **упал**, код 1: `go mod tidy` не может получить
  `golang.org/x/mod` (`module lookup disabled by GOPROXY=off`), та же
  причина, что у c13.
- Итог check.sh: **код 1**. Выводы ради прохождения не менялись.

## Повтор с модулем golang.org/x/mod@v0.22.0 (по разрешению пользователя)

Офлайн-выводы выше сохранены без изменений (`run_all.out`, `logs/`,
`../check.sh.out`). Новые выводы лежат рядом: `module-download.net.out`,
`sha256-check.net.out`, `run_all.net.out`, `logs-net/*.log`, `../check.sh.net.out`.

**Загрузка** (`module-download.net.out`). Разрешено было только
`golang.org/x/mod@v0.22.0` через прокси Go с проверкой по sum.golang.org.
- Команда: `go mod download -x -json golang.org/x/mod@v0.22.0` в каталоге без
  `go.mod`, `GOPROXY=https://proxy.golang.org` (без `direct`),
  `GOSUMDB=sum.golang.org`, переменные `GONOSUMDB/GONOSUMCHECK/GOPRIVATE/GOINSECURE`
  пусты. `-x` фиксирует каждый HTTP-запрос: `.info`, `.mod`, `.zip` модуля с
  proxy.golang.org; `lookup` и 7 тайлов с sum.golang.org (прокси не
  поддерживает зеркалирование sumdb: `supported` → 404).
- `Sum h1:D4nJWe9zXqHOmWqj4VMOJhvzj7bEZg4wEYa759z1pH4=`,
  `GoModSum h1:6SkKJ3Xj0I0BrPOZoBy3bdMptDDU9oJrpohJ3eWZ1fY=`. Обе строки
  совпадают с подписанной записью sum.golang.org (запись 31490473, дерево 68513800).
- После загрузки в кэше модулей только `golang.org/x/mod@v0.22.0`.
- `go.mod` модуля требует `golang.org/x/tools v0.13.0`. Он **не загружался**:
  прогоны ниже шли с `GOPROXY=off`, то есть только из кэша, так что
  получить что-то ещё было невозможно.

**Целостность контролей** перед прогоном: ветка `acceptance/act-v0` не
изменилась (`3647200`), повторная сверка — 33/33 OK (24 контроля + 9 reference,
`sha256-check.net.out`).

**`run_all.sh`** (`run_all.net.out`, `logs-net/`): **код 0, «RUN_ALL: все
ожидания акта выполнены»**.
- c13: все ожидания выполнены. `go mod tidy` прошёл из кэша, `go.sum`
  (2 строки x/mod, sha256 `7c9f4a45…`), 3 теста `interop/` PASS, обе мутации
  краснят тесты.
- C01–C09, C14a–g, C14s, F01–F04, F09 — PASS (22/22), включая
  `TestC14c`.
- E01 выполнен; c10, c11, c12, c15, s01, f02, p01 тоже выполнены.

Все три офлайн-провала (c13, TestC14c, E01) закрылись. Других изменений по
сравнению с офлайн-прогоном нет.

Оговорка: информационная строка c13 «версии модулей (`go list -m all`)»
вывела `module lookup disabled by GOPROXY=off`. Для полного графа нужен
`go.mod` от `golang.org/x/tools`, а его загрузка не разрешена. Это только
печать, ожидания c13 на ней не основаны.

**`check.sh`** (`../check.sh.net.out`), та же копия ветки, `GOPROXY=off`:
**код 0, `check: OK`**. Задание `test` (gofmt, vet, `go test -race`, `DEMO PASSED`)
и задание `interop` (`ok github.com/XtReL/trust-core/interop`) прошли.
Выводы ради прохождения не менялись.
