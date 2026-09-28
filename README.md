# Trust Core

*Verifiable evidence log: signed in-toto attestations (DSSE) in an RFC 6962 transparency log with C2SP checkpoints. Zero dependencies, Go standard library only.*

Общий слой проверяемых доказательств. Любая вертикаль (Gatekeeper, журнал действий ИИ-агентов, MRV, телеметрия) передаёт ядру событие, а ядро превращает его в подписанную аттестацию и добавляет в журнал, который **клиент или аудитор проверяет сам**, имея только публичные ключи.

## Что где лежит

| Путь | Что делает |
|---|---|
| `trustcore.go` | Единственный вызов для вертикалей: `Recorder.Record(event)` |
| `event/` | Схема события и предикат `test-result` (первый тип, для Gatekeeper) |
| `attest/` | in-toto Statement v1 и конверт DSSE: подпись и проверка |
| `keys/` | Ключи Ed25519 в стандартном PEM (читаются openssl) |
| `tlog/` | Дерево Меркла RFC 6962, доказательства включения, чекпоинты C2SP |
| `tlog/filelog/` | Первый бэкенд журнала: обычная папка (`checkpoint` + `entries/`) |
| `verify/` | Независимая проверка: весь журнал, прошлый чекпоинт, одна запись, цепочка эпох |
| `rotate/` | Ротация ключа журнала: новая эпоха с записью-генезисом |
| `cmd/trustcore/` | CLI: `keygen`, `init`, `record`, `verify`, `prove`, `verify-entry`, `rotate`, `verify-chain` |
| `interop/` | Отдельный модуль: сверка с эталонными реализациями Go (`x/mod/sumdb`) |
| `scripts/demo.sh` | Полный сценарий от ключей до обнаружения подмены |
| `examples/` | Пример события сканирования Gatekeeper |

## Быстрый старт

```bash
go test -race ./...          # модульные и сквозные тесты
bash scripts/demo.sh         # полный сценарий, должен закончиться DEMO PASSED
go build -o trustcore ./cmd/trustcore
```

Ручной сценарий:

```bash
ORIGIN=trust.example.com/xtrel/gatekeeper
./trustcore keygen -out keys/log -name $ORIGIN     # ключ оператора журнала
./trustcore keygen -out keys/attester              # ключ сканера
./trustcore init   -log ./evidence -origin $ORIGIN -log-key keys/log.key
./trustcore record -log ./evidence -origin $ORIGIN -log-key keys/log.key \
                   -key keys/attester.key -event examples/gatekeeper-scan.event.json
./trustcore verify -log ./evidence -origin $ORIGIN \
                   -log-pub keys/log.pub -attester-pub keys/attester.pub
```

Коды выхода: `0` — всё проверено, `1` — проверка не прошла, `2` — ошибка использования.

## Как подключается вертикаль

Вертикаль собирает событие и вызывает `Record`. О подписях, журнале и секретах она не знает:

```go
ev, err := event.NewTestResult(
    []event.Subject{{Name: "git+https://github.com/org/repo",
        Digest: map[string]string{"gitCommit": commitSHA}}},
    event.TestResult{
        Result:        event.ResultFailed,
        Configuration: []event.ResourceDescriptor{{Name: "gatekeeper-rules",
            Digest: map[string]string{"sha256": rulesHash}}},
        FailedTests:   []string{"aws-access-token"},
    },
)
receipt, err := (&trustcore.Recorder{Attester: scannerKey, Log: log}).Record(ev)
```

Проверка архитектуры: следующая вертикаль должна подключаться **без изменений в ядре**.

## Что проверяет `verify`

1. Чекпоинт подписан ключом оператора журнала и относится к ожидаемому журналу (`-origin`).
2. Записи на диске дают тот же корень дерева Меркла, что в подписанном чекпоинте. Изменение даже одного пробела обнаруживается.
3. Каждая запись — конверт DSSE с подписью доверенного ключа и корректным in-toto Statement.
4. С флагом `-previous`: сохранённый ранее чекпоинт остаётся префиксом журнала, то есть **история не переписана**.

`prove` и `verify-entry` позволяют проверить одну запись без скачивания всего журнала.

Так выглядит чекпоинт (формат C2SP, совместимый со свидетелями и Tessera):

```
trust.example.com/xtrel/gatekeeper
1
8zh7Q2zfTPJwPrvtVJ0Fcju6Lz9cRTMNfvmqqidF/08=

— trust.example.com/xtrel/gatekeeper 5UxpfiaeKwDlhBTgN0JqdjCHR9jAzIR2YiYDOzubLmpq...
```

## Ротация ключа

Решение и обоснование — [ADR 0002](docs/adr/0002-key-rotation.md). Существующий журнал не меняется: смена ключа начинает новую **эпоху** (origin `<base>/e<k>`). Её запись 0 — генезис, который ссылается на подписанный чекпоинт предыдущей эпохи, то есть на точку заморозки.

```bash
# плановая: старый ключ есть, генезис подписан обоими ключами
./trustcore rotate -from ./evidence -from-origin $ORIGIN -from-pub keys/log.pub -from-key keys/log.key \
                   -new-key keys/log-e2.key -to ./evidence-e2
# внеплановая (ключ потерян или скомпрометирован): без -from-key, с чекпоинтом,
# сохранённым вне журнала (у владельца или аудитора)
./trustcore rotate -from ./evidence -from-origin $ORIGIN -from-pub keys/log.pub \
                   -trusted-checkpoint kept/checkpoint -new-key keys/log-e2.key -to ./evidence-e2

./trustcore verify-chain -manifest my-manifest.json      # -json для полного отчёта
```

Манифест хранит **проверяющий**. Публичные ключи берутся только из него, пути в нём — относительно файла манифеста:

```json
{
  "base": "trust.example.com/xtrel/gatekeeper",
  "epochs": [
    {"epoch": 1, "log": "ev-e1", "publicKey": "keys/e1.pub", "lastKnownCheckpoint": "cp/e1"},
    {"epoch": 2, "log": "ev-e2", "publicKey": "keys/e2.pub", "acceptUnplanned": "<newKeyID>"}
  ]
}
```

- `attesterKeys` (необязательно) — отдельные ключи аттестаторов эпохи. Без него аттестатором считается ключ журнала.
- Внеплановая ротация принимается только с `acceptUnplanned`, равным keyid нового ключа, который проверяющий сверил с владельцем лично.
- Для замороженной эпохи авторитетен чекпоинт заморозки из генезиса: записи до него проверяются по нему, а текущий файл `checkpoint` (его откат или битая подпись) только выводится в отчёт. `lastKnownCheckpoint` замороженной эпохи должен быть не дальше точки заморозки.
- Записи старой эпохи после точки заморозки выводятся как «не подтверждены». После плановой ротации их наличие — ошибка.

## Модель безопасности и ограничения

- **Оператор журнала может переписать историю**, переподписав всё своим ключом. Сам по себе журнал это не ловит. Защита — чекпоинты, которые хранит кто-то другой: клиент (`-previous`), аудитор или свидетель. Поэтому следующий этап ядра — внешние свидетели.
- Приватные ключи (`*.key`) исключены через `.gitignore` и создаются с правами `0600`. Никогда не коммитьте их; в CI держите как секреты.
- `filelog` — однописательский и пересчитывает корень за O(n). Подходит для истории одного репозитория, но не для облачного сервиса. Для масштаба предусмотрен бэкенд на Tessera за тем же интерфейсом `tlog.Log`.
- Порог подписей сейчас равен одной. Ротация ключа — эпохами (см. выше): она защищает будущее, а прошлое при компрометации защищают только чекпоинты у других сторон.

## Стандарты

DSSE v1 · in-toto Statement v1 · in-toto test-result v0.1 · RFC 6962 / RFC 9162 (хэширование и доказательства включения) · C2SP signed-note и tlog-checkpoint · Ed25519.

Совместимость проверяется тестами в `interop/`: наши чекпоинты открываются эталонной реализацией Go, её заметки — нашей, корни и доказательства совпадают поэлементно.

## Публикация репозитория

```bash
# на GitHub создать пустой публичный репозиторий XtReL/trust-core (без README)
cd trust-core
git init -b main
git add .
git commit -m "Trust Core skeleton: DSSE attestations in an RFC 6962 log with C2SP checkpoints"
git remote add origin git@github.com:XtReL/trust-core.git
git push -u origin main
# один раз зафиксировать зависимости модуля сверки:
cd interop && go mod tidy && cd .. && git add interop/go.sum && git commit -m "interop: go.sum" && git push
```

Лицензия: Apache-2.0.
