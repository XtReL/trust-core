# Контроли акта ACT-0.2-trust-core

Акт: [`../../ACT-0.2-trust-core.md`](../../ACT-0.2-trust-core.md). Контроли написаны проверяющим, код репозитория
не меняют и в него не входят. Go-файлы хранятся с окончанием `.txt` (чтобы `gofmt -l .`, `go vet ./...` и CI
их не видели) и перед запуском кладутся во **временную копию** репозитория. По той же причине файлы-источники
`reference/**.go` сохранены с добавленным `.txt`.

## Временная копия

```bash
TMP="$(mktemp -d)"
git clone --quiet <путь к репозиторию> "$TMP/copy"   # нужна история git (c11, c12)
mkdir "$TMP/copy/acceptance"
cp -r <репозиторий>/docs/acceptance/reference "$TMP/copy/acceptance/reference"   # эталонные источники для c14
cd "$TMP/copy"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly       # без автозагрузки toolchain
```

Go-контроли: скопировать файл, отбросив `.txt` (`c01_tamper_test.go.txt` → `acceptance/c01_tamper_test.go`);
обязателен общий `helpers_test.go.txt` → `acceptance/helpers_test.go`. Shell-контроли копируются как есть в `acceptance/`.

**Сеть.** Нужна только `c13_interop.sh` и только для загрузки модулей Go (`golang.org/x/mod`, `go mod tidy`);
при заполненном кэше модулей не нужна. Остальные контроли работают без сети. Репозиторий никогда не получает `go.sum`:
он создаётся только в одноразовой копии.

Всё сразу, с созданием копии: `LOGDIR=/путь bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh`
(код выхода 0 — все ожидания акта выполнены; `LOGDIR` — каталог для полного вывода каждого прогона отдельным файлом).

## Как читать «ожидаемый результат»

Контроль может упасть (`t.Fatalf` / `exit 1`). У контролей подтверждённых заявлений ожидание — «защита срабатывает».
У опровергнутого заявления (З15) и у находок (F01–F04, F09) контроль **утверждает наблюдаемый дефект**: после
исправления кода он покраснеет, и тогда ожидание нужно перевернуть. `c13_interop.sh` при недоступной сети
завершается кодом 3 («Н: сеть недоступна»), `c14` отражает статус Н тем, что покрывает только часть строки
(см. шапку файла).

## Контроли

| Контроль | Заявление / назначение | Куда положить во временной копии | Команда (из корня копии) | Ожидаемый результат |
|---|---|---|---|---|
| `helpers_test.go.txt` | общий для Go-контролей | `acceptance/helpers_test.go` | — | — |
| `c01_tamper_test.go.txt` | З1 `README.md:70` | `acceptance/c01_tamper_test.go` | `go test ./acceptance/ -run TestC01 -count=1 -v` | PASS: пробел в начале/конце и изменённый байт записи 0 и 2 → `Report.OK=false`, проблема «do not match the signed checkpoint root»; исходный и восстановленный журнал → OK |
| `c02_checkpoint_test.go.txt` | З2 `README.md:69` | `acceptance/c02_checkpoint_test.go` | `go test ./acceptance/ -run TestC02 -count=1 -v` | PASS: чужой ключ, чужой origin, чекпоинт другого origin с подписью оператора, правка размера → ошибка `verify.Log`; исходный → OK |
| `c03_entries_test.go.txt` | З3 `README.md:71` | `acceptance/c03_entries_test.go` | `go test ./acceptance/ -run TestC03 -count=1 -v` | PASS: 6 подмен записи → `OK=false` с конкретной причиной; честная запись → OK |
| `c04_manifest_keys_test.go.txt` | З4 `README.md:102` | `acceptance/c04_manifest_keys_test.go` | `go test ./acceptance/ -run TestC04 -count=1 -v` | PASS: журнал злоумышленника с его ключами в репозитории не проходит по манифесту проверяющего; проходит, если манифест сам указывает на этот ключ |
| `c05_previous_test.go.txt` | З5 `README.md:72` | `acceptance/c05_previous_test.go` | `go test ./acceptance/ -run TestC05 -count=1 -v` | PASS: рост → OK и `PreviousSize=2`; переписанный, урезанный журнал и чужой `Previous` → `OK=false`; переписанный журнал без `Previous` проходит (ограничение `README.md:121`) |
| `c06_planned_downgrade_test.go.txt` | З6 `docs/adr/0002-key-rotation.md:70` | `acceptance/c06_planned_downgrade_test.go` | `go test ./acceptance/ -run TestC06 -count=1 -v` | PASS: генезис `planned` с подписью одного нового ключа → не OK; с двумя подписями и честная `rotate.Planned` → OK |
| `c07_unplanned_test.go.txt` | З7 `README.md:115` | `acceptance/c07_unplanned_test.go` | `go test ./acceptance/ -run TestC07 -count=1 -v` | PASS: без `acceptUnplanned`, с keyid старого и случайного ключа → не OK; с верным → OK |
| `c08_frozen_test.go.txt` | З8 `README.md:116` | `acceptance/c08_frozen_test.go` | `go test ./acceptance/ -run TestC08 -count=1 -v` | PASS: откат и порча `checkpoint` замороженной эпохи → цепочка OK, причина в `Notes`; правка записи ниже точки заморозки → не OK |
| `c09_after_freeze_test.go.txt` | З9 `README.md:117` | `acceptance/c09_after_freeze_test.go` | `go test ./acceptance/ -run TestC09 -count=1 -v` | PASS: внеплановая — OK, `Unconfirmed=2`, записи `[3 4]`; плановая — не OK |
| `c10_key_mode.sh` | З10 `README.md:122` (права 0600), Прогон | `acceptance/c10_key_mode.sh` | `bash acceptance/c10_key_mode.sh` | «C10: все ожидания выполнены», код 0 |
| `c11_gitignore.sh` | З11 `README.md:122` (`.gitignore`), Текст | `acceptance/c11_gitignore.sh` | `bash acceptance/c11_gitignore.sh` | «C11: все ожидания выполнены», код 0. Нужен git-клон. Дополнительно: в истории 0 находок приватных ключей, в подложенном клоне — 2 находки и 1 файл `*.key` (путь:строка, длина, энтропия, без содержимого) |
| `c12_backward_compat.sh` | З12 `docs/adr/0002-key-rotation.md:75` | `acceptance/c12_backward_compat.sh` | `bash acceptance/c12_backward_compat.sh` | «C12: все ожидания выполнены», код 0. Нужен git-клон (коммит `15fc79a…` = v0.1.0) |
| `c13_interop.sh` | З13 `README.md:130` | `acceptance/c13_interop.sh` | `bash acceptance/c13_interop.sh` | «C13: все ожидания выполнены», код 0; печатает sha256 созданного `go.sum`, диф `go.mod`, версии модулей; 3 теста `interop/` PASS; мутации `NodeHash` и хэша ключа краснят тесты. Код 3 — нет сети |
| `c14_standards_test.go.txt` | З14 `README.md:128` (статус Н: RFC 9162 без источника) | `acceptance/c14_standards_test.go` + `acceptance/reference/` | `go test ./acceptance/ -run TestC14 -count=1 -v` | PASS (8 тестов, из них `TestC14s_…` — дополнительный, без источника). Нужен `openssl`. Подтверждает всё, кроме RFC 9162 |
| `c15_exit_codes.sh` | З15 `README.md:45` (статус О) | `acceptance/c15_exit_codes.sh` | `bash acceptance/c15_exit_codes.sh` | «C15: all expectations held», код 0. Сценарий D1 **утверждает дефект** (несуществующий `-log` даёт 1) и покраснеет после исправления |
| `s01_no_deps.sh` | дополнительный: `README.md:3` (в счёт заявлений не входит), Текст | `acceptance/s01_no_deps.sh` | `bash acceptance/s01_no_deps.sh` | «S01: все ожидания выполнены», код 0 |
| `e01_environment.sh` | шапка акта, «Окружение» | `acceptance/e01_environment.sh` | `bash acceptance/e01_environment.sh` | «E01: все ожидания выполнены», код 0: автозагрузок toolchain нет, извлечён ровно `golang.org/x/mod@v0.22.0`; подложенные `go 1.99` и два модуля в фиктивном кэше обнаруживаются |
| `f01_findings_test.go.txt` | находки F01–F04, F09 | `acceptance/f01_findings_test.go` | `go test ./acceptance/ -run TestF0 -count=1 -v` | PASS (5 тестов; F09 собирает CLI): утверждают наблюдаемые дефекты |
| `f02_text_findings.sh` | находки F05–F08, F12 | `acceptance/f02_text_findings.sh` | `bash acceptance/f02_text_findings.sh` | «F-text: все ожидания выполнены», код 0; каждый поиск «0» сопровождён подложенным случаем |
| `p01_red_runs_repro.sh` | воспроизведение трёх первоначальных «красных» прогонов (раздел «Процесс» акта) | `acceptance/p01_red_runs_repro.sh` | `bash acceptance/p01_red_runs_repro.sh` | «P01: все ожидания выполнены», код 0 |
| `mutations.sh` | способность C01–C09 и C14 краснеть | не копируется; запускается из репозитория | `LOGDIR=/путь bash docs/acceptance/controls/ACT-0.2-trust-core/mutations.sh` | 15 строк `M1…M15: killed`, код 0; полный вывод каждой мутации — `mutation-Mn.log` в `LOGDIR`; «SURVIVED» или «MUTATION INVALID» — код 1 |
| `run_all.sh` | всё перечисленное, кроме `mutations.sh` | запускается из репозитория | `LOGDIR=/путь bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh` | «RUN_ALL: все ожидания акта выполнены», код 0 |

Контроли `c11`, `s01` и `f02`, у которых результат «0»/«нет» (нет приватных ключей и файлов `*.key`, нет внешних
зависимостей, нет неприкреплённых `uses:`, нет обработки развилки, нет правил в `CLAUDE.md`, нет чтения заголовков
прокси), содержат подложенный случай, который тот же поиск обязан найти. Способность Go-контролей краснеть подтверждена
отдельно (`mutations.sh`); способность `c13` — внутри самого `c13_interop.sh`.
