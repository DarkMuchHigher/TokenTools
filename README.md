# TokenTools

<p align="center">
  <img src="assets/app-icon.png" width="88" alt="Иконка TokenTools">
</p>

<p align="center"><strong>Инструменты для работы с контейнерами КриптоПро на аппаратных токенах</strong></p>

TokenTools читает контейнеры КриптоПро через PC/SC, выгружает файлы, разбирает сертификаты, проверяет контейнеры через CryptoPro CSP и запускает CertFix через `p12utility`.

В составе проекта — CLI и нативный GUI на egui/eframe. Готовые сборки: [Releases](https://github.com/DarkMuchHigher/TokenTools/releases).

## Возможности

- поиск PC/SC-считывателей;
- перечисление файловой системы токена по APDU;
- PIN-авторизация со счётчиком попыток;
- выгрузка шестифайловых контейнеров;
- разбор `name.key`, `header.key`, сертификата владельца и цепочки УЦ;
- разбор X.509: субъект, издатель, сроки, отпечатки SHA-1/SHA-256;
- проверка контейнера через CryptoPro CSP;
- обработка контейнера с резервной копией и откатом;
- извлечение и установка сертификатов, экспорт в PEM;
- просмотр личных сертификатов КриптоПро (хранилище `uMy`);
- диагностика окружения командой `doctor`.

Файлы выгруженного контейнера:

```text
name.key       header.key       primary.key
masks.key      primary2.key     masks2.key
```

## Поддерживаемые носители

Токены с APDU-файловой системой (PC/SC). Список носителей расширяется.

## Быстрый старт

### Сборка

```bash
cargo build --workspace --release --locked
```

### Проверка окружения

```bash
cargo run --release -p tokentools -- doctor
```

Команда показывает состояние PC/SC, считывателей, Wine/Flatpak, `p12utility`, `csptest` и `certmgr`.

### CLI

```bash
# Список считывателей
cargo run --release -p tokentools -- list

# Выгрузка контейнеров
cargo run --release -p tokentools -- dump ./dump

# Выгрузка с явным PIN
cargo run --release -p tokentools -- dump ./dump --pin 87654321

# Подробный вывод обхода файловой системы
cargo run --release -p tokentools -- --verbose dump ./dump

# Проверка контейнера
cargo run --release -p tokentools -- verify ./dump/<container>

# Извлечение сертификатов
cargo run --release -p tokentools -- cert ./dump/<container>

# Состав сертификатов, отпечатки SHA-1/SHA-256 и PEM
cargo run --release -p tokentools -- cert ./dump/<container> --show --pem

# Извлечение и установка сертификатов
cargo run --release -p tokentools -- cert ./dump/<container> --install

# CertFix-процесс
cargo run --release -p tokentools -- fix ./dump/<container>
```

Если `p12utility.win32.exe` не находится автоматически:

```bash
export TOKENTOOLS_P12UTILITY=/path/to/p12utility.win32.exe
```

PowerShell:

```powershell
$env:TOKENTOOLS_P12UTILITY = "C:\Tools\p12utility.win32.exe"
```

### PIN

Чтение контейнеров требует авторизации. PIN берётся в порядке:

1. `--pin` у команды `dump`;
2. переменная окружения `TOKENTOOLS_PIN`;
3. стандартный `12345678`.

Перед вводом команда читает счётчик попыток. При неверном PIN выгрузка останавливается с указанием остатка попыток, чтобы не израсходовать их повторными вводами. Заблокированный PIN разблокируется через панель управления токеном или админ-PIN.

```bash
export TOKENTOOLS_PIN=87654321
```

### GUI

```bash
cargo run --release -p tokentools-gui
```

Разделы интерфейса: **Устройства**, **Контейнер**, **Сертификаты** и **Журнал**. PIN вводится в разделе «Устройства»; после неверного PIN автопоиск приостанавливается до нажатия «Обновить». В разделе «Сертификаты» — личные сертификаты КриптоПро из хранилища `uMy` с поиском.

Иконка в доке и меню (Linux): скопируйте `tokentools.desktop` в `~/.local/share/applications/`, а `tokentools.png` в `~/.local/share/icons/hicolor/128x128/apps/`. В релизных архивах оба файла лежат рядом с бинарниками.

## Workspace

| Пакет | Назначение |
| --- | --- |
| `pcsc-transport` | PC/SC-транспорт: динамическая загрузка libpcsclite / winscard. |
| `rutoken-fs` | Обход файловой системы токена по APDU. |
| `cryptopro-container` | Разбор имён, `header.key` и сертификатов. |
| `certfix` | CryptoPro CSP, Wine/Flatpak, проверка и обработка контейнеров. |
| `tokentools` | CLI: `list`, `doctor`, `dump`, `fix`, `verify`, `cert`. |
| `tokentools-gui` | Desktop-интерфейс на egui/eframe. |

## Окружение

- Rust `1.99` или новее;
- `pcscd` и драйвер PC/SC токена в Linux;
- CryptoPro CSP для `verify` и установки сертификатов;
- Wine или Flatpak `org.winehq.Wine` для `fix`;
- `p12utility.win32.exe` для CertFix.

## Разработка

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
```

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) проверяет форматирование, Clippy, тесты и release-сборку на Ubuntu и Windows.

Для обычных push создаются:

```text
TokenTools-linux-x86_64.tar.gz
TokenTools-windows-x86_64.zip
```

Тег вида `vX.Y.Z` публикует оба архива как GitHub Release.

## Лицензия

Исходный код Rust распространяется по лицензии MIT. См. [`LICENSE`](LICENSE).
