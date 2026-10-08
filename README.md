# TokenTools

<p align="center">
  <img src="assets/app-icon.png" width="88" alt="Иконка TokenTools">
</p>

<p align="center"><strong>Инструменты для работы с контейнерами КриптоПро на Рутокенах</strong></p>

TokenTools читает контейнеры КриптоПро через PC/SC, выгружает файлы, разбирает сертификаты, проверяет контейнеры через CryptoPro CSP и запускает CertFix через `p12utility`.

В составе проекта — CLI и нативный GUI на egui/eframe.

## Возможности

- поиск PC/SC-считывателей;
- перечисление файловой системы Рутокена по APDU;
- выгрузка шестифайловых контейнеров;
- разбор `name.key`, `header.key`, сертификата владельца и цепочки УЦ;
- проверка контейнера через CryptoPro CSP;
- обработка контейнера с резервной копией и откатом;
- извлечение и установка сертификатов;
- диагностика окружения командой `doctor`.

Файлы выгруженного контейнера:

```text
name.key       header.key       primary.key
masks.key      primary2.key     masks2.key
```

## Быстрый старт

### Сборка

```bash
cargo build --workspace --release --locked
```

### Проверка окружения

```bash
cargo run --release -p rt-export -- doctor
```

Команда показывает состояние PC/SC, считывателей, Wine/Flatpak, `p12utility`, `csptest` и `certmgr`.

### CLI

```bash
# Список считывателей
cargo run --release -p rt-export -- list

# Выгрузка контейнеров
cargo run --release -p rt-export -- dump ./dump

# Подробный вывод обхода файловой системы
cargo run --release -p rt-export -- --verbose dump ./dump

# Проверка контейнера
cargo run --release -p rt-export -- verify ./dump/<container>

# Извлечение сертификатов
cargo run --release -p rt-export -- cert ./dump/<container>

# Извлечение и установка сертификатов
cargo run --release -p rt-export -- cert ./dump/<container> --install

# CertFix-процесс
cargo run --release -p rt-export -- fix ./dump/<container>
```

Если `p12utility.win32.exe` не находится автоматически:

```bash
export TOKENTOOLS_P12UTILITY=/path/to/p12utility.win32.exe
```

PowerShell:

```powershell
$env:TOKENTOOLS_P12UTILITY = "C:\Tools\p12utility.win32.exe"
```

### GUI

```bash
cargo run --release -p tokentools-gui
```

Разделы интерфейса: **Устройства**, **Контейнер** и **Журнал**.

## Workspace

| Пакет | Назначение |
| --- | --- |
| `rt-pcsc` | PC/SC-транспорт для Linux и Windows. |
| `rt-fs` | APDU-выбор, перечисление файлов и чтение данных Рутокена. |
| `cryptopro-container` | Разбор имён, `header.key` и сертификатов. |
| `certfix-core` | CryptoPro CSP, Wine/Flatpak, проверка и обработка контейнеров. |
| `rt-export` | CLI: `list`, `doctor`, `dump`, `fix`, `verify`, `cert`. |
| `tokentools-gui` | Desktop-интерфейс на egui/eframe. |

## Окружение

- Rust `1.99` или новее;
- `pcscd` и драйвер PC/SC для Рутокена в Linux;
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

Тег вида `v0.1.0` публикует оба архива как GitHub Release.

## Лицензия

Исходный код Rust распространяется по лицензии MIT. См. [`LICENSE`](LICENSE).
