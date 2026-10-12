# Правила проекта

TokenTools — Rust-workspace (CLI + GUI) для выгрузки контейнеров КриптоПро с токенов и снятия
неэкспортируемости. Пакеты — в `crates/`, описание и команды — в `README.md`, история — в `CHANGELOG.md`.

## Проверки перед коммитом

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
```

Тулчейн закреплён: rustc 1.99.0 (`rust-version` в `Cargo.toml`, CI — `dtolnay/rust-toolchain@1.99.0`).

## Конвенции

- Тексты интерфейса, сообщения и журнал — по-русски, технические, без вендорских хардкодов.
- Токен — только чтение; запись на токен запрещена (анти-цель проекта).
- Зависимости минимальны: внешняя — только `anyhow`, GUI — `eframe`.
- Изменение поведения сопровождать правкой `README.md` и `CHANGELOG.md`.
