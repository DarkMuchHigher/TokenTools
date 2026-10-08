use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Parser)]
#[command(
    name = "rt-export",
    version,
    about = "TokenTools: выгрузка контейнеров с Рутокена (Tokens) + снятие неэкспортируемости (CertFix)"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    List,
    Doctor,
    Dump {
        dest: PathBuf,
    },
    Fix {
        dir: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
    },
    Verify {
        dir: PathBuf,
    },
    Cert {
        dir: PathBuf,
        #[arg(long)]
        install: bool,
    },
}
fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List => cmd_list(),
        Cmd::Doctor => cmd_doctor(),
        Cmd::Dump { dest } => cmd_dump(&dest, cli.verbose),
        Cmd::Fix { dir, cert } => cmd_fix(&dir, cert),
        Cmd::Verify { dir } => cmd_verify(&dir),
        Cmd::Cert { dir, install } => cmd_cert(&dir, install),
    }
}
fn cmd_doctor() -> Result<()> {
    let checks = certfix_core::check_dependencies();
    println!("Проверка окружения TokenTools:");
    for check in &checks {
        println!(
            "[{}] {} — {} (используется: {})",
            check.state.label(),
            check.name,
            check.detail,
            check.used_by
        );
    }
    let missing = checks
        .iter()
        .filter(|check| check.state == certfix_core::DependencyState::Missing)
        .count();
    if missing == 0 {
        println!("Итог: все проверенные компоненты обнаружены.");
    } else {
        println!("Итог: не найдено компонентов: {missing}; см. области использования выше.");
    }
    Ok(())
}

fn cmd_list() -> Result<()> {
    let pcsc = rt_pcsc::Pcsc::load()?;
    let readers = pcsc.list_readers()?;
    if readers.is_empty() {
        println!("Считыватели PC/SC не найдены (токен не подключён?)");
        return Ok(());
    }
    println!("Считыватели PC/SC:");
    for r in readers {
        println!("  * {r}");
    }
    Ok(())
}
fn cmd_dump(dest: &Path, verbose: bool) -> Result<()> {
    let pcsc = rt_pcsc::Pcsc::load()?;
    let readers = pcsc.list_readers()?;
    if readers.is_empty() {
        bail!("считыватели PC/SC не найдены — подключите токен");
    }
    std::fs::create_dir_all(dest)?;
    for reader in &readers {
        println!("Считыватель: {reader}");
        let card = match pcsc.connect(reader) {
            Ok(c) => c,
            Err(e) => {
                println!("  ошибка подключения: {e}");
                continue;
            }
        };
        let fs = rt_fs::RutokenFs::new(&card, verbose);
        println!("  выбираю MF (3F00)...");
        let (_, sw) = fs.select_mf()?;
        if sw != 0x9000 {
            println!("  MF недоступен (SW={sw:04x}) — пропускаю");
            continue;
        }
        let trees = match fs.walk(6) {
            Ok(t) => t,
            Err(e) => {
                println!("  ошибка обхода ФС: {e}");
                continue;
            }
        };
        for (path, files) in trees {
            let pathstr = if path.is_empty() {
                "root".to_string()
            } else {
                path.iter()
                    .map(|f| format!("{f:04x}"))
                    .collect::<Vec<_>>()
                    .join("-")
            };
            if files.len() == 6 {
                let mut blobs = Vec::with_capacity(files.len());
                let mut ok = true;
                for (fname, entry) in rt_fs::CONTAINER_FILES.iter().zip(files.iter()) {
                    match fs.read_file(entry.fid, entry.size) {
                        Ok(blob) => blobs.push(((*fname).to_string(), blob)),
                        Err(e) => {
                            println!("    ошибка чтения {fname}: {e}");
                            ok = false;
                        }
                    }
                }
                if !ok {
                    println!("  контейнер /{pathstr}/ пропущен: не удалось прочитать все файлы");
                    continue;
                }
                let out = dest.join(&pathstr);
                let partial = dest.join(format!(
                    ".{pathstr}.partial-{}-{}",
                    std::process::id(),
                    now_nanos()
                ));
                std::fs::create_dir(&partial)?;
                for (fname, blob) in &blobs {
                    if let Err(error) = std::fs::write(partial.join(fname), blob) {
                        let _ = std::fs::remove_dir_all(&partial);
                        return Err(error.into());
                    }
                }
                if out.exists() {
                    let _ = std::fs::remove_dir_all(&partial);
                    println!(
                        "  контейнер /{pathstr}/ пропущен: {} уже существует",
                        out.display()
                    );
                    continue;
                }
                let name = std::fs::read(partial.join("name.key"))
                    .ok()
                    .and_then(|d| cryptopro_container::parse_name_key(&d))
                    .unwrap_or_default();
                if let Err(error) = std::fs::rename(&partial, &out) {
                    let _ = std::fs::remove_dir_all(&partial);
                    return Err(error.into());
                }
                println!(
                    "  контейнер /{pathstr}/ -> {}  [OK]  имя: {name}",
                    out.display()
                );
            } else {
                println!(
                    "  папка /{pathstr}/: {} файл(ов) — не контейнер",
                    files.len()
                );
            }
        }
    }
    Ok(())
}
fn cmd_fix(dir: &Path, cert: Option<PathBuf>) -> Result<()> {
    let dir = dir.canonicalize().context("каталог контейнера не найден")?;
    if !cryptopro_container::is_container_dir(&dir) {
        bail!("{}: неполный контейнер, нужны все 6 файлов", dir.display());
    }
    let cert = match cert {
        Some(c) => c.canonicalize().context("сертификат не найден")?,
        None => {
            let (_, certs) = cryptopro_container::read_container(&dir)?;
            if certs.owner.is_empty() {
                bail!("в header.key не найден сертификат владельца ([5]); укажите --cert");
            }
            let path = dir.join("cert_exchange.cer");
            std::fs::write(&path, &certs.owner)?;
            println!("Сертификат владельца извлечён: {}", path.display());
            path
        }
    };
    println!("Запуск p12utility под Wine: --cprepair --container_folder . --keyexport");
    let out = certfix_core::fix_container(&dir, &cert)?;
    for line in out.lines().filter(|l| {
        !l.starts_with("fixme")
            && !l.starts_with("err:")
            && !l.starts_with("wine:")
            && !l.trim().is_empty()
    }) {
        println!("  {}", line.trim());
    }
    println!("Готово: контейнер переупакован, ключ помечен экспортируемым.");
    Ok(())
}
fn cmd_verify(dir: &Path) -> Result<()> {
    let out = certfix_core::verify_container(dir)?;
    for line in out.lines().filter(|l| {
        l.contains("Check")
            || l.contains("Certificate")
            || l.contains("Keys in")
            || l.contains("exchange")
            || l.contains("signature")
            || l.contains("Error")
    }) {
        println!("  {}", line.trim());
    }
    if out.contains("Check container passed") {
        println!("Итог: контейнер в порядке");
        Ok(())
    } else {
        bail!("проверки не пройдены")
    }
}
fn cmd_cert(dir: &Path, install: bool) -> Result<()> {
    let (name, certs) = cryptopro_container::read_container(dir)?;
    if certs.owner.is_empty() {
        bail!("в header.key не найден сертификат владельца ([5])");
    }
    let owner = dir.join("cert_exchange.cer");
    std::fs::write(&owner, &certs.owner)?;
    println!(
        "Сертификат владельца: {} ({} байт)",
        owner.display(),
        certs.owner.len()
    );
    let mut chain_files = Vec::new();
    for (i, c) in certs.chain.iter().enumerate() {
        let f = dir.join(format!("ca_chain_{i}.cer"));
        std::fs::write(&f, c)?;
        println!("УЦ из цепочки: {} ({} байт)", f.display(), c.len());
        chain_files.push(f);
    }
    if install {
        let cname = name.unwrap_or_else(|| "unknown".into());
        let (out, ok) = certfix_core::certmgr_install(&owner, Some(&cname), "uMy")?;
        println!(
            "Установка сертификата владельца в uMy: {}",
            if ok { "OK" } else { "ошибка" }
        );
        if !ok {
            println!("{out}");
        }
        for (i, f) in chain_files.iter().enumerate() {
            let store = if i == 0 { "uRoot" } else { "uCA" };
            let (_, ok) = certfix_core::certmgr_install(f, None, store)?;
            println!("УЦ #{i} -> {store}: {}", if ok { "OK" } else { "ошибка" });
        }
    }
    Ok(())
}
