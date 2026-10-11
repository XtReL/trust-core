# Контроли акта ACT-0.2-trust-core

Акт: [`../../ACT-0.2-trust-core.md`](../../ACT-0.2-trust-core.md). Все контроли написаны
проверяющим, код репозитория они не меняют и в него не входят: Go-файлы
хранятся с окончанием `.txt` (чтобы `gofmt -l .`, `go vet ./...` и CI их не
видели), перед запуском их кладут во **временную копию** репозитория.

## Временная копия

```bash
TMP="$(mktemp -d)"
git clone --quiet <путь к репозиторию> "$TMP/copy"   # нужна история git (C10, C12)
mkdir "$TMP/copy/acceptance"
cd "$TMP/copy"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly       # без автозагрузки toolchain, без правок go.mod/go.sum
```

Go-контроли: скопировать файл, отбросив `.txt` (`c01_tamper_test.go.txt` →
`acceptance/c01_tamper_test.go`); обязателен общий `helpers_test.go.txt` →
`acceptance/helpers_test.go`. Shell-контроли копируются как есть в
`acceptance/`. Сеть не нужна ни одному контролю.

Всё сразу, с созданием копии: `bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh`
(код выхода 0 — все ожидания акта выполнены).

## Как читать «ожидаемый результат»

Контроль может упасть (`t.Fatalf` / `exit 1`), и каждый падает, когда
ожидание не выполнено. У контролей подтверждённых заявлений ожидание —
«защита срабатывает»; у опровергнутого заявления (З14) и у находок (F01–F04)
контроль **утверждает наблюдаемый дефект**: после исправления кода он
покраснеет, и тогда ожидание нужно перевернуть. У З11 (статус Н) контроль
фиксирует блокирующее состояние (нет `interop/go.sum`).

## Контроли

| Контроль | Заявление | Куда положить во временной копии | Команда (из корня копии) | Ожидаемый результат |
|---|---|---|---|---|
| `helpers_test.go.txt` | общий для Go-контролей | `acceptance/helpers_test.go` | — | — |
| `c01_tamper_test.go.txt` | З1 `README.md:70` | `acceptance/c01_tamper_test.go` | `go test ./acceptance/ -run TestC01 -count=1 -v` | PASS: пробел в начале/конце и изменённый байт записи 0 и 2 → `Report.OK=false`, проблема «do not match the signed checkpoint root»; исходный и восстановленный журнал → OK |
| `c02_checkpoint_test.go.txt` | З2 `README.md:69` | `acceptance/c02_checkpoint_test.go` | `go test ./acceptance/ -run TestC02 -count=1 -v` | PASS: чужой ключ, чужой origin, чекпоинт другого origin с подписью оператора, правка размера → ошибка `verify.Log`; исходный → OK |
| `c03_entries_test.go.txt` | З3 `README.md:71` | `acceptance/c03_entries_test.go` | `go test ./acceptance/ -run TestC03 -count=1 -v` | PASS: 6 подмен записи (недоверенный ключ, подсказка keyid, payloadType, `_type`, пустой subject, не JSON) → `OK=false` с конкретной причиной; честная запись → OK |
| `c04_manifest_keys_test.go.txt` | З4 `README.md:102` | `acceptance/c04_manifest_keys_test.go` | `go test ./acceptance/ -run TestC04 -count=1 -v` | PASS: журнал злоумышленника с его ключами в трёх местах репозитория не проходит по манифесту проверяющего; тот же журнал проходит, если манифест сам указывает на этот ключ |
| `c05_previous_test.go.txt` | З5 `README.md:72` | `acceptance/c05_previous_test.go` | `go test ./acceptance/ -run TestC05 -count=1 -v` | PASS: рост → OK и `PreviousSize=2`; переписанный, урезанный журнал и чужой `Previous` → `OK=false`; переписанный журнал без `Previous` проходит (ограничение `README.md:121`) |
| `c06_planned_downgrade_test.go.txt` | З6 `docs/adr/0002-key-rotation.md:70` | `acceptance/c06_planned_downgrade_test.go` | `go test ./acceptance/ -run TestC06 -count=1 -v` | PASS: генезис `planned` с подписью одного нового ключа → не OK (в т.ч. при `acceptUnplanned`); с двумя подписями и честная `rotate.Planned` → OK |
| `c07_unplanned_test.go.txt` | З7 `README.md:115` | `acceptance/c07_unplanned_test.go` | `go test ./acceptance/ -run TestC07 -count=1 -v` | PASS: без `acceptUnplanned`, с keyid старого и случайного ключа → не OK; с верным → OK |
| `c08_frozen_test.go.txt` | З8 `README.md:116` | `acceptance/c08_frozen_test.go` | `go test ./acceptance/ -run TestC08 -count=1 -v` | PASS: откат и порча `checkpoint` замороженной эпохи → цепочка OK, причина в `Notes`, `Size` = размер заморозки; правка записи ниже точки заморозки → не OK |
| `c09_after_freeze_test.go.txt` | З9 `README.md:117` | `acceptance/c09_after_freeze_test.go` | `go test ./acceptance/ -run TestC09 -count=1 -v` | PASS: внеплановая — OK, `Unconfirmed=2`, записи `[3 4]`; плановая — не OK; до дописывания обе OK |
| `c10_private_keys.sh` | З10 `README.md:122` | `acceptance/c10_private_keys.sh` | `bash acceptance/c10_private_keys.sh` | «C10: все ожидания выполнены», код 0. Нужен git-клон. В реальной истории 0 находок; в подложенном клоне — 2 находки (путь:строка, длина, энтропия, без содержимого) и 1 файл `*.key` |
| `c11_backward_compat.sh` | З11 `docs/adr/0002-key-rotation.md:75` | `acceptance/c11_backward_compat.sh` | `bash acceptance/c11_backward_compat.sh` | «C11: все ожидания выполнены», код 0. Нужен git-клон (коммит `15fc79a…` = v0.1.0) |
| `c12_interop_blocked.sh` | З12 `README.md:130` (статус Н) | `acceptance/c12_interop_blocked.sh` | `bash acceptance/c12_interop_blocked.sh` | «C12: состояние «заблокировано» подтверждено», код 0: `interop/go.sum` нет, `go test` в копии `interop/` без сети падает с `missing go.sum entry`, `go.mod` не меняется. Когда `go.sum` появится — покраснеет (тогда запускать сами тесты interop) |
| `c13_standards_test.go.txt` | З13 `README.md:128` | `acceptance/c13_standards_test.go` | `go test ./acceptance/ -run TestC13 -count=1 -v` | PASS (6 тестов). Нужен `openssl` в PATH. Константы векторов — по памяти автора акта, достоверность — по совпадению с вычислением (см. шапку файла) |
| `c14_no_deps.sh` | З14 `README.md:3` | `acceptance/c14_no_deps.sh` | `bash acceptance/c14_no_deps.sh` | «C14: все ожидания выполнены», код 0: единственный модуль — `github.com/XtReL/trust-core`; подложенный `example.com/ext` находится |
| `c15_exit_codes.sh` | З15 `README.md:45` (статус О) | `acceptance/c15_exit_codes.sh` | `bash acceptance/c15_exit_codes.sh` | «C15: all expectations held», код 0. Сценарий D1 **утверждает дефект** (несуществующий `-log` даёт 1, а не 2) и покраснеет после исправления |
| `e01_environment.sh` | шапка акта, «Окружение» (автозагрузок toolchain 0, загрузок модулей 0) | `acceptance/e01_environment.sh` | `bash acceptance/e01_environment.sh` | «E01: все ожидания выполнены», код 0; подложенные `go 1.99` и файл в кэше модулей обнаруживаются |
| `f01_findings_test.go.txt` | находки F01–F04, F09 | `acceptance/f01_findings_test.go` | `go test ./acceptance/ -run TestF0 -count=1 -v` | PASS (5 тестов; F09 собирает CLI командой `go build ../cmd/trustcore`): утверждают наблюдаемые дефекты, после исправления покраснеют |
| `f02_text_findings.sh` | находки F05–F08 | `acceptance/f02_text_findings.sh` | `bash acceptance/f02_text_findings.sh` | «F-text: все ожидания выполнены», код 0; каждый поиск «0» сопровождён подложенным случаем |
| `mutations.sh` | способность C01–C09, C13 краснеть | не копируется; запускается из репозитория | `bash docs/acceptance/controls/ACT-0.2-trust-core/mutations.sh` | 12 строк `M1…M12: killed`, код 0: в временной копии ломается одно защищающее место кода, контроль обязан покраснеть; «SURVIVED» или «MUTATION INVALID» — код 1 |
| `run_all.sh` | всё перечисленное, кроме `mutations.sh` | запускается из репозитория | `bash docs/acceptance/controls/ACT-0.2-trust-core/run_all.sh` | «RUN_ALL: все ожидания акта выполнены», код 0 |

Контроли `c10`, `c14` и `f02`, у которых результат «0»/«нет» (нет приватных
ключей и файлов `*.key`, нет внешних зависимостей, нет неприкреплённых
`uses:`, нет обработки развилки, нет правил в `CLAUDE.md`), содержат
подложенный случай, который тот же поиск обязан найти. У Go-контролей
способность краснеть подтверждена отдельно (`mutations.sh`).
