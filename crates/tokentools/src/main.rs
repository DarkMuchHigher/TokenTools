use anyhow::{Context, Result, bail};
use cryptopro_container::hex_lower;
use std::path::{Path, PathBuf};

const USAGE: &str = "\
TokenTools: выгрузка контейнеров с токена (Tokens) + снятие неэкспортируемости (CertFix)

Использование: tokentools [ОПЦИИ] <КОМАНДА>

Команды:
  list                 Считыватели PC/SC
  doctor               Проверка окружения
  dump <DEST>          Выгрузка контейнеров с токена [--pin PIN]
  fix <DIR>            Снять флаг неэкспортируемости [--cert CERT]
  verify <DIR>         Проверка контейнера через CryptoPro CSP
  cert <DIR>           Извлечение сертификатов [--install] [--show] [--pem]
  storage              Контейнеры в хранилище CSP и на флешках
  deploy <DIR> [DEST]  Установить контейнер в хранилище CSP или в корень флешки
                       [--name ИМЯ] [--link]
  unmount <ИМЯ>        Удалить контейнер из хранилища CSP

Опции:
  -v, --verbose        Подробный вывод
  -h, --help           Справка
  -V, --version        Версия";

#[derive(Debug, PartialEq)]
enum Cmd {
    List,
    Doctor,
    Dump {
        dest: PathBuf,
        pin: Option<String>,
    },
    Fix {
        dir: PathBuf,
        cert: Option<PathBuf>,
    },
    Verify {
        dir: PathBuf,
    },
    Cert {
        dir: PathBuf,
        install: bool,
        show: bool,
        pem: bool,
    },
    Storage,
    Unmount {
        name: String,
    },
    Deploy {
        dir: PathBuf,
        dest: Option<PathBuf>,
        name: Option<String>,
        link: bool,
    },
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

fn reject_extra_args(parser: &mut Parser<'_>, name: &str) -> Result<(), String> {
    while let Some(arg) = parser.next() {
        if arg == "-v" || arg == "--verbose" {
            parser.verbose = true;
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
    let mut parser = Parser::new(&args[i + 1..], verbose);
    let cmd = match name {
        "list" => {
            reject_extra_args(&mut parser, "list")?;
            Cmd::List
        }
        "doctor" => {
            reject_extra_args(&mut parser, "doctor")?;
            Cmd::Doctor
        }
        "dump" => {
            let mut dest = None;
            let mut pin = None;
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
                    "--pin" => pin = Some(parser.value_for("--pin")?.to_string()),
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
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
                    "--cert" => cert = Some(PathBuf::from(parser.value_for("--cert")?)),
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
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
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
            let mut show = false;
            let mut pem = false;
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
                    "--install" => install = true,
                    "--show" => show = true,
                    "--pem" => pem = true,
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
                show,
                pem,
            }
        }
        "storage" => {
            reject_extra_args(&mut parser, "storage")?;
            Cmd::Storage
        }
        "unmount" => {
            let mut name = None;
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
                    _ if arg.starts_with('-') => {
                        return Err(format!("unmount: неизвестная опция: {arg}"));
                    }
                    _ => set_once(&mut name, arg, "unmount: лишний аргумент")?,
                }
            }
            let name = name.ok_or("unmount: не указано имя: unmount <ИМЯ>")?;
            Cmd::Unmount {
                name: name.to_string(),
            }
        }
        "deploy" => {
            let mut dir = None;
            let mut dest = None;
            let mut name = None;
            let mut link = false;
            while let Some(arg) = parser.next() {
                match arg {
                    "-v" | "--verbose" => parser.verbose = true,
                    "--link" => link = true,
                    "--name" => name = Some(parser.value_for("--name")?.to_string()),
                    _ if arg.starts_with("--name=") => {
                        name = Some(arg["--name=".len()..].to_string());
                    }
                    _ if arg.starts_with('-') => {
                        return Err(format!("deploy: неизвестная опция: {arg}"));
                    }
                    _ => {
                        if dir.is_none() {
                            dir = Some(arg);
                        } else {
                            set_once(&mut dest, arg, "deploy: лишний аргумент")?;
                        }
                    }
                }
            }
            let dir = dir.ok_or("deploy: не указан каталог контейнера: deploy <DIR> [DEST]")?;
            Cmd::Deploy {
                dir: PathBuf::from(dir),
                dest: dest.map(PathBuf::from),
                name,
                link,
            }
        }
        other => return Err(format!("неизвестная команда: {other}")),
    };
    Ok(Parsed::Run {
        verbose: parser.verbose,
        cmd,
    })
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
            println!("tokentools {}", env!("CARGO_PKG_VERSION"));
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
        Cmd::Cert {
            dir,
            install,
            show,
            pem,
        } => cmd_cert(&dir, install, show, pem),
        Cmd::Storage => cmd_storage(),
        Cmd::Unmount { name } => cmd_unmount(&name),
        Cmd::Deploy {
            dir,
            dest,
            name,
            link,
        } => cmd_deploy(&dir, dest.as_deref(), name.as_deref(), link),
    }
}

fn cmd_doctor() -> Result<()> {
    let checks = certfix::check_dependencies();
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
        .filter(|check| check.state == certfix::DependencyState::Missing)
        .count();
    if missing == 0 {
        println!("Итог: все проверенные компоненты обнаружены.");
    } else {
        println!("Итог: не найдено компонентов: {missing}; см. области использования выше.");
    }
    Ok(())
}

fn cmd_list() -> Result<()> {
    let pcsc = pcsc_transport::Pcsc::load()?;
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
fn resolve_pin(cli_pin: Option<&str>, env_pin: Option<String>) -> Result<(String, &'static str)> {
    if let Some(pin) = cli_pin.filter(|pin| !pin.is_empty()) {
        return Ok((pin.to_string(), "--pin"));
    }
    if let Some(pin) = env_pin.filter(|pin| !pin.is_empty()) {
        return Ok((pin, "TOKENTOOLS_PIN"));
    }
    bail!("PIN не задан: передайте --pin или установите TOKENTOOLS_PIN")
}

fn cmd_dump(dest: &Path, verbose: bool, pin: Option<&str>) -> Result<()> {
    let pcsc = pcsc_transport::Pcsc::load()?;
    let readers = pcsc.list_readers()?;
    if readers.is_empty() {
        bail!("считыватели PC/SC не найдены — подключите токен");
    }
    let (pin, pin_source) = resolve_pin(pin, std::env::var("TOKENTOOLS_PIN").ok())?;
    for reader in &readers {
        println!("Считыватель: {reader}");
        let card = match pcsc.connect(reader) {
            Ok(c) => c,
            Err(e) => {
                println!("  ошибка подключения: {e}");
                continue;
            }
        };
        let log_sink = |msg: &str| {
            if verbose {
                println!("    [fs] {msg}");
            }
        };
        let fs = rutoken_fs::RutokenFs::new(&card, Some(&log_sink));
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
        let containers = match fs.containers() {
            Ok(c) => c,
            Err(e) => {
                println!("  ошибка поиска контейнеров: {e}");
                continue;
            }
        };
        if containers.is_empty() {
            println!("  контейнеры не найдены");
            continue;
        }
        for container in containers {
            let folder = container.folder;
            let files = match fs.read_container(&container) {
                Ok(files) => files,
                Err(e) => {
                    println!("  контейнер {folder:04x} пропущен: {e}");
                    continue;
                }
            };
            let files: Vec<(String, Vec<u8>)> = files
                .into_iter()
                .filter_map(|(role, data)| {
                    cryptopro_container::file_name_by_role(role)
                        .map(|name| (name.to_string(), data))
                })
                .collect();
            let name = files
                .iter()
                .find(|(name, _)| name == "name.key")
                .and_then(|(_, data)| cryptopro_container::parse_name_key(data));
            let dir = cryptopro_container::container_dir_name(name.as_deref(), folder);
            match certfix::save_container(dest, &dir, &files) {
                Ok(out) => println!(
                    "  контейнер {folder:04x} -> {}  [OK]  имя: {}",
                    out.display(),
                    name.as_deref().unwrap_or("(нет)")
                ),
                Err(e) => println!("  контейнер {folder:04x} пропущен: {e}"),
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
            certfix::write_private_once(&path, &certs.owner)?;
            println!("Сертификат владельца извлечён: {}", path.display());
            path
        }
    };
    println!("Запуск p12utility под Wine: --cprepair --container_folder . --keyexport");
    let out = certfix::fix_container(&dir, &cert)?;
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
    let out = certfix::verify_container(dir)?;
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
fn cmd_cert(dir: &Path, install: bool, show: bool, pem: bool) -> Result<()> {
    let (name, certs) = cryptopro_container::read_container(dir)?;
    if certs.owner.is_empty() {
        bail!("в header.key не найден сертификат владельца ([5])");
    }
    let owner = dir.join("cert_exchange.cer");
    certfix::write_private_once(&owner, &certs.owner)?;
    println!(
        "Сертификат владельца: {} ({} байт)",
        owner.display(),
        certs.owner.len()
    );
    let mut chain_files = Vec::new();
    for (i, c) in certs.chain.iter().enumerate() {
        let f = dir.join(format!("ca_chain_{i}.cer"));
        certfix::write_private_once(&f, c)?;
        println!("УЦ из цепочки: {} ({} байт)", f.display(), c.len());
        chain_files.push(f);
    }
    if show {
        print_cert_info("Владелец", &owner);
        for (i, f) in chain_files.iter().enumerate() {
            print_cert_info(&format!("УЦ #{i}"), f);
        }
    }
    if pem {
        let owner_pem = owner.with_extension("pem");
        certfix::write_private_once(
            &owner_pem,
            cryptopro_container::to_pem(&certs.owner).as_bytes(),
        )?;
        println!("PEM: {}", owner_pem.display());
        for (i, c) in certs.chain.iter().enumerate() {
            let f = dir.join(format!("ca_chain_{i}.pem"));
            certfix::write_private_once(&f, cryptopro_container::to_pem(c).as_bytes())?;
            println!("PEM УЦ #{i}: {}", f.display());
        }
    }
    if install {
        let cname = name.unwrap_or_else(|| "unknown".into());
        let (out, ok) = certfix::certmgr_install(&owner, Some(&cname), "uMy")?;
        println!(
            "Установка сертификата владельца в uMy: {}",
            if ok { "OK" } else { "ошибка" }
        );
        if !ok {
            println!("{out}");
        }
        for (i, f) in chain_files.iter().enumerate() {
            let store = if i == 0 { "uRoot" } else { "uCA" };
            let (_, ok) = certfix::certmgr_install(f, None, store)?;
            println!("УЦ #{i} -> {store}: {}", if ok { "OK" } else { "ошибка" });
        }
    }
    Ok(())
}

fn cmd_storage() -> Result<()> {
    let containers = certfix::storage_containers();
    if containers.is_empty() {
        println!("Контейнеров нет. Установка: tokentools deploy <папка контейнера>");
        return Ok(());
    }
    for container in &containers {
        let name = container
            .container_name()
            .unwrap_or_else(|| container.name.clone());
        let state = if container.is_complete() {
            "полный"
        } else {
            "неполный"
        };
        println!(
            "  {} — {name} ({}/6 файлов, {state})",
            container.csp_name(),
            container.files
        );
    }
    Ok(())
}

fn cmd_unmount(name: &str) -> Result<()> {
    let dir = certfix::unmount_container(name)?;
    println!("Удалён: {}", dir.display());
    Ok(())
}

fn cmd_deploy(dir: &Path, dest: Option<&Path>, name: Option<&str>, link: bool) -> Result<()> {
    let dir = dir.canonicalize().context("каталог контейнера не найден")?;
    let dest = match dest {
        Some(dest) => dest.to_path_buf(),
        None => certfix::csp_keys_dir()?,
    };
    let deployed = certfix::deploy_container(&dir, &dest, name)?;
    println!("Установлен: {}", deployed.dir.display());
    let Some(csp_name) = deployed.csp_name else {
        println!("Каталог не является хранилищем CSP или корнем флешки: КриптоПро его не увидит");
        return Ok(());
    };
    println!("КриптоПро видит контейнер как {csp_name}");
    if link {
        let out = certfix::link_certificate(&csp_name)?;
        for line in out.lines().filter(|line| !line.trim().is_empty()) {
            println!("  {}", line.trim_end());
        }
        println!("Сертификат скопирован в хранилище uMy со ссылкой на ключ");
    }
    Ok(())
}

fn print_cert_info(label: &str, path: &Path) {
    let der = match std::fs::read(path) {
        Ok(der) => der,
        Err(error) => {
            println!("{label}: {error}");
            return;
        }
    };
    match cryptopro_container::parse_cert(&der) {
        Ok(info) => {
            println!("{label}: {}", path.display());
            if let Some(cn) = &info.subject_cn {
                println!("  Субъект: {cn}");
            }
            if let Some(cn) = &info.issuer_cn {
                println!("  Издатель: {cn}");
            }
            println!("  Серийный номер: {}", info.serial_hex);
            if let (Some(from), Some(to)) = (&info.not_before, &info.not_after) {
                println!("  Действует: с {from} по {to}");
            }
            println!("  SHA-1:   {}", hex_lower(&info.sha1));
            println!("  SHA-256: {}", hex_lower(&info.sha256));
        }
        Err(error) => println!("{label}: {}: {error}", path.display()),
    }
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
                install: true,
                show: false,
                pem: false
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
    fn parses_cert_show_and_pem() {
        let Ok(Parsed::Run { cmd, .. }) = parse(&["cert", "./c", "--show", "--pem"]) else {
            panic!("должно разобраться");
        };
        assert_eq!(
            cmd,
            Cmd::Cert {
                dir: PathBuf::from("./c"),
                install: false,
                show: true,
                pem: true
            }
        );
    }

    #[test]
    fn pin_must_be_explicit_or_configured() {
        assert!(resolve_pin(None, None).is_err());
        assert_eq!(
            resolve_pin(None, Some("87654321".to_string())).unwrap(),
            ("87654321".to_string(), "TOKENTOOLS_PIN")
        );
        assert_eq!(
            resolve_pin(Some("1234"), Some("87654321".to_string())).unwrap(),
            ("1234".to_string(), "--pin")
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
