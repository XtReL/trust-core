# TASK: trust-core v0.2.0 — ротация ключа эпохами (ADR 0002)

Прочитай `docs/adr/0002-key-rotation.md` и `CLAUDE.md` до начала работы. **Решения ADR не меняй.** При расхождении или неясности — остановись и спроси. Один PR в `main`, не сливать. Тег `v0.2.0` ставит человек.

## Жёсткие ограничения
- Ядро — только стандартная библиотека Go.
- `verify.Log`, `trustcore verify`, формат `filelog` на диске, форматы DSSE, in-toto Statement v1, RFC 6962 и C2SP **не меняются**.
- Все изменения аддитивные; существующие тесты не правятся, кроме добавления новых.
- В репозиторий не коммитятся приватные ключи, в том числе тестовые. Фикстуры содержат только журнал и публичный ключ.

## 1. `event`: генезис
- Константа `PredicateLogGenesis = "https://github.com/XtReL/trust-core/log-genesis/v1"`.
- Константы `RotationPlanned = "planned"`, `RotationUnplanned = "unplanned"`.
- Тип `LogGenesis`: `Epoch int`, `PredecessorOrigin string`, `PredecessorSize uint64`, `PredecessorRoot string` (base64), `PredecessorCheckpoint string` (точный текст signed-note), `PredecessorKeyID string`, `NewKeyID string`, `Rotation string`, `Note string` (`omitempty`).
- `NewLogGenesis(g LogGenesis) (Event, error)`: валидирует поля (эпоха ≥ 2; rotation из двух значений; keyid — 64 hex-символа в нижнем регистре; `PredecessorRoot` декодируется в 32 байта); субъект — `name` = `PredecessorOrigin`, `digest.sha256` = hex корня.
- `EpochOrigin(base string, k int) string`: k = 1 → `base`; k ≥ 2 → `base + "/e" + k`. И обратная `ParseEpoch(base, origin string) (int, error)`.

## 2. Пакет `rotate`
- `Planned(from, fromOrigin string, oldSigner *keys.Signer, to string, newSigner *keys.Signer, note string) (Result, error)`:
  - текущий чекпоинт старой эпохи проверяется ключом `oldSigner.Public()`, корень пересчитывается по записям и совпадает; это и есть точка заморозки;
  - новая эпоха: `filelog.Init(to, EpochOrigin(base, k), newSigner)`, `entries/.gitkeep`, запись 0 — генезис с `rotation: planned`, конверт DSSE подписан **обоими** ключами;
  - после — `verify.Log` новой эпохи проходит.
- `Unplanned(from, fromOrigin string, oldPub ed25519.PublicKey, trustedCheckpoint []byte, to string, newSigner *keys.Signer, note string) (Result, error)`:
  - `trustedCheckpoint` проверяется ключом `oldPub` и origin старой эпохи;
  - корень первых `size` записей старой эпохи обязан совпасть с корнем доверенного чекпоинта, иначе ошибка «история переписана до заморозки»;
  - записи старой эпохи после `size` игнорируются (в `Result` — их количество);
  - генезис с `rotation: unplanned`, подпись только новым ключом.
- `Result`: номер новой эпохи, новый origin, `newKeyID`, vkey нового ключа, размер заморозки, число записей после заморозки.
- Базовый origin и номер эпохи выводятся из `fromOrigin` через `ParseEpoch`: суффикс `/e<k>` → следующая эпоха k+1, иначе 2.

## 3. `verify.Chain` и манифест
- `LoadManifest(path) (Manifest, error)`: JSON по ADR (п. 7). Пути разрешаются относительно файла манифеста. Ключи читаются **только** из путей манифеста.
- `Chain(m Manifest) (ChainReport, error)`, правила — ADR п. 5 и 7:
  - эпохи в манифесте идут строго 1, 2, 3…; origin эпохи k = `EpochOrigin(base, k)`;
  - эпоха 1 и каждая эпоха k проверяются через существующий `verify.Log` своим ключом (аттестаторы — тот же ключ, если в манифесте не указан отдельный список `attesterKeys`); `lastKnownCheckpoint` → `Previous`;
  - для k ≥ 2: запись 0 — генезис (иначе ошибка), подписан ключом эпохи k; поля совпадают с манифестом; `predecessorCheckpoint` проверяется ключом эпохи k−1; размер и корень совпадают с полями и субъектом; префикс эпохи k−1 совпадает;
  - для замороженной эпохи k−1 авторитетен `predecessorCheckpoint`; записи после заморозки перечисляются в отчёте как «не подтверждены»; при `planned` их наличие — ошибка;
  - `planned` без валидной подписи старым ключом → ошибка; `unplanned` без `acceptUnplanned == newKeyID` → ошибка;
  - отчёт в JSON: по каждой эпохе — origin, размер, корень, вид ротации, число неподтверждённых записей, проблемы; общий `ok`.

## 4. CLI
- `trustcore rotate -from DIR -from-origin ORIGIN -from-pub OLD.pub [-from-key OLD.key] [-trusted-checkpoint FILE] -new-key NEW.key -to DIR [-note TEXT]`:
  - с `-from-key` → `planned`;
  - без него → `unplanned`, и тогда `-trusted-checkpoint` обязателен;
  - печатает новый origin, keyid, vkey и размер заморозки.
- `trustcore verify-chain -manifest FILE [-json]`: коды выхода как у `verify` (0 / 1 / 2).

## 5. Тесты (все — с ключами, созданными во время теста)
1. `planned`: цепочка из 3 эпох проверяется.
2. `unplanned`: без `acceptUnplanned` — отказ; с неверным keyid — отказ; с верным — OK.
3. Компрометация: после заморозки в старую эпоху дописаны записи, подписанные старым ключом, — при `unplanned` они «не подтверждены», при `planned` — ошибка.
4. `Unplanned` с доверенным чекпоинтом, не совпадающим с префиксом старой эпохи, — отказ.
5. `planned`, генезис которого подписан только новым ключом, — отказ (не понижается до `unplanned`).
6. Запись 0 новой эпохи — не генезис → отказ; генезис ссылается не на ту эпоху или не на тот origin → отказ.
7. Подмена ключа: манифест с ключом эпохи 2, отличным от ключа генезиса, → отказ.
8. Откат: `lastKnownCheckpoint` новее, чем журнал эпохи → отказ.
9. Обратная совместимость: фикстура `testdata/v0.1.0-log/` (журнал в 3 записи, созданный текущей версией, плюс публичный ключ) проверяется и `verify.Log`, и `Chain` как эпоха 1.
10. `demo.sh`: дописать сценарий плановой ротации и `verify-chain`.

## 6. Документация
- `docs/adr/0002-key-rotation.md` — файл ADR как есть.
- README: раздел «Ротация ключа» — две команды и ссылка на ADR.

## Проверка перед push
`scripts/check.sh` → `check: OK`, `git status` чистый. Покажи полный вывод.
