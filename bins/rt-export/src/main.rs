use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "\
TokenTools: выгрузка контейнеров с Рутокена (Tokens) + снятие неэкспортируемости (CertFix)

Использование: rt-export [ОПЦИИ] <КОМАНДА>

Команды:
  list                 Считыватели PC/SC
  doctor               Проверка окружения
  dump <DEST>          Выгрузка контейнеров с токена [--pin PIN]
  fix <DIR>            Снять флаг неэкспортируемости [--cert CERT]
  verify <DIR>         Проверка контейнера через CryptoPro CSP
  cert <DIR>           Извлечение сертификатов [--install]

Опции:
  -v, --verbose        Подробный вывод
  -h, --help           Справка
  -V, --version        Версия";

#[derive(Debug, PartialEq)]
enum Cmd {
    List,
    Doctor,
    Dump { dest: PathBuf, pin: Option<String> },
    Fix { dir: PathBuf, cert: Option<PathBuf> },
    Verify { dir: PathBuf },
    Cert { dir: PathBuf, install: bool },
}

enum Parsed {
    Run { verbose: bool, cmd: Cmd },
    Help,
    Version,
}

struct Parser<'a> {
    args: &'a [String],
    pos: usize,
    verbose: bool,
}

impl<'a> Parser<'a> {
    fn new(args: &'a [String], verbose: bool) -> Self {
        Self {
            args,
            pos: 0,
            verbose,
        }
    }
    fn next(&mut self) -> Option<&'a str> {
        let value = self.args.get(self.pos).map(String::as_str);
        if value.is_some() {
            self.pos += 1;
        }
        value
    }
    fn value_for(&mut self, flag: &str) -> Result<&'a str, String> {
        self.next()
            .ok_or_else(|| format!("для {flag} нужно значение"))
    }
}

fn set_once<'a>(slot: &mut Option<&'a str>, value: &'a str, error: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{error}: {value}"));
    }
    *slot = Some(value);
    Ok(())
}

fn no_args(p: &mut Parser<'_>, name: &str) -> Result<(), String> {
    while let Some(arg) = p.next() {
        if arg == "-v" || arg == "--verbose" {
            p.verbose = true;
            continue;
        }
        return Err(format!("{name}: лишний аргумент: {arg}"));
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(Parsed::Help);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        return Ok(Parsed::Version);
    }
    let mut verbose = false;
    let mut i = 0;
    while matches!(args.get(i).map(String::as_str), Some("-v" | "--verbose")) {
        verbose = true;
        i += 1;
    }
    let name = args
        .get(i)
        .map(String::as_str)
        .ok_or("команда не указана")?;
    let mut p = Parser::new(&args[i + 1..], verbose);
    let cmd = match name {
        "list" => {
            no_args(&mut p, "list")?;
            Cmd::List
        }
        "doctor" => {
            no_args(&mut p, "doctor")?;
            Cmd::Doctor
        }
        "dump" => {
            let mut dest = None;
            let mut pin = None;
            while let Some(arg) = p.next() {
                match arg {
                    "-v" | "--verbose" => p.verbose = true,
                    "--pin" => pin = Some(p.value_for("--pin")?.to_string()),
                    _ if arg.starts_with("--pin=") => pin = Some(arg["--pin=".len()..].to_string()),
                    _ if arg.starts_with('-') => {
                        return Err(format!("dump: неизвестная опция: {arg}"));
                    }
                    _ => set_once(&mut dest, arg, "dump: лишний аргумент")?,
                }
            }
            let dest = dest.ok_or("dump: не указан каталог: dump <DEST>")?;
            Cmd::Dump {
                dest: PathBuf::from(dest),
                pin,
            }
        }
        "fix" => {
            let mut dir = None;
            let mut cert = None;
            while let Some(arg) = p.next() {
                match arg {
                    "-v" | "--verbose" => p.verbose = true,
                    "--cert" => cert = Some(PathBuf::from(p.value_for("--cert")?)),
                    _ if arg.starts_with("--cert=") => {
                        cert = Some(PathBuf::from(&arg["--cert=".len()..]));
                    }
                    _ if arg.starts_with('-') => {
                        return Err(format!("fix: неизвестная опция: {arg}"));
                    }
                    _ => set_once(&mut dir, arg, "fix: лишний аргумент")?,
                }
            }
            let dir = dir.ok_or("fix: не указан каталог: fix <DIR>")?;
            Cmd::Fix {
                dir: PathBuf::from(dir),
                cert,
            }
        }
        "verify" => {
            let mut dir = None;
            while let Some(arg) = p.next() {
                match arg {
                    "-v" | "--verbose" => p.verbose = true,
                    _ if arg.starts_with('-') => {
                        return Err(format!("verify: неизвестная опция: {arg}"));
                    }
                    _ => set_once(&mut dir, arg, "verify: лишний аргумент")?,
                }
            }
            let dir = dir.ok_or("verify: не указан каталог: verify <DIR>")?;
            Cmd::Verify {
                dir: PathBuf::from(dir),
            }
        }
        "cert" => {
            let mut dir = None;
            let mut install = false;
            while let Some(arg) = p.next() {
                match arg {
                    "-v" | "--verbose" => p.verbose = true,
                    "--install" => install = true,
                    _ if arg.starts_with('-') => {
                        return Err(format!("cert: неизвестная опция: {arg}"));
                    }
                    _ => set_once(&mut dir, arg, "cert: лишний аргумент")?,
                }
            }
            let dir = dir.ok_or("cert: не указан каталог: cert <DIR>")?;
            Cmd::Cert {
                dir: PathBuf::from(dir),
                install,
            }
        }
        other => return Err(format!("неизвестная команда: {other}")),
    };
    Ok(Parsed::Run {
        verbose: p.verbose,
        cmd,
    })
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    match parsed {
        Parsed::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Parsed::Version => {
            println!("rt-export {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Parsed::Run { verbose, cmd } => run(verbose, cmd),
    }
}

fn run(verbose: bool, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::List => cmd_list(),
        Cmd::Doctor => cmd_doctor(),
        Cmd::Dump { dest, pin } => cmd_dump(&dest, verbose, pin.as_deref()),
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
fn resolve_pin(cli_pin: Option<&str>) -> (String, &'static str) {
    if let Some(pin) = cli_pin.filter(|pin| !pin.is_empty()) {
        return (pin.to_string(), "--pin");
    }
    if let Ok(pin) = std::env::var("TOKENTOOLS_PIN") {
        if !pin.is_empty() {
            return (pin, "TOKENTOOLS_PIN");
        }
    }
    ("12345678".to_string(), "стандартный PIN по умолчанию")
}

fn cmd_dump(dest: &Path, verbose: bool, pin: Option<&str>) -> Result<()> {
    let pcsc = rt_pcsc::Pcsc::load()?;
    let readers = pcsc.list_readers()?;
    if readers.is_empty() {
        bail!("считыватели PC/SC не найдены — подключите токен");
    }
    std::fs::create_dir_all(dest)?;
    let (pin, pin_source) = resolve_pin(pin);
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
        match fs.authenticate_user_pin(&pin) {
            Ok(outcome) if outcome.already_authenticated => {
                println!("  PIN: сессия уже авторизована");
            }
            Ok(_) => println!("  PIN принят ({pin_source})"),
            Err(e) => {
                println!("  PIN: {e}");
                continue;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Parsed, String> {
        parse_args(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_global_verbose_before_command() {
        let Ok(Parsed::Run { verbose, cmd }) = parse(&["--verbose", "list"]) else {
            panic!("должно разобраться");
        };
        assert!(verbose);
        assert_eq!(cmd, Cmd::List);
    }

    #[test]
    fn parses_dump_with_pin() {
        let Ok(Parsed::Run { cmd, .. }) = parse(&["dump", "./out", "--pin", "87654321"]) else {
            panic!("должно разобраться");
        };
        assert_eq!(
            cmd,
            Cmd::Dump {
                dest: PathBuf::from("./out"),
                pin: Some("87654321".into())
            }
        );
    }

    #[test]
    fn parses_pin_equals_form() {
        let Ok(Parsed::Run { cmd, .. }) = parse(&["dump", "--pin=1234", "./out"]) else {
            panic!("должно разобраться");
        };
        assert_eq!(
            cmd,
            Cmd::Dump {
                dest: PathBuf::from("./out"),
                pin: Some("1234".into())
            }
        );
    }

    #[test]
    fn parses_cert_install_and_fix_cert() {
        let Ok(Parsed::Run { cmd, .. }) = parse(&["cert", "./c", "--install"]) else {
            panic!("должно разобраться");
        };
        assert_eq!(
            cmd,
            Cmd::Cert {
                dir: PathBuf::from("./c"),
                install: true
            }
        );
        let Ok(Parsed::Run { cmd, .. }) = parse(&["fix", "./c", "--cert", "./cert.cer"]) else {
            panic!("должно разобраться");
        };
        assert_eq!(
            cmd,
            Cmd::Fix {
                dir: PathBuf::from("./c"),
                cert: Some(PathBuf::from("./cert.cer"))
            }
        );
    }

    #[test]
    fn help_and_version_win_over_parsing() {
        assert!(matches!(parse(&["dump", "--help"]), Ok(Parsed::Help)));
        assert!(matches!(parse(&["-V"]), Ok(Parsed::Version)));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["frobnicate"]).is_err());
        assert!(parse(&["dump"]).is_err());
        assert!(parse(&["verify", "a", "b"]).is_err());
        assert!(parse(&["dump", "./out", "--pin"]).is_err());
        assert!(parse(&["list", "extra"]).is_err());
    }
}
