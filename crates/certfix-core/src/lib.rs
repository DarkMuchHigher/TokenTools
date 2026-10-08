use anyhow::{bail, Context, Result};
use cryptopro_container::{build_name_key, cp1251_to_string, is_container_dir, CONTAINER_FILES};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn decode_csp_output(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| cp1251_to_string(bytes))
}

fn contains_success_marker(output: &[u8]) -> bool {
    output
        .windows(7)
        .any(|w| w == b"\xf3\xf1\xef\xe5\xf8\xed\xee")
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn find_p12utility() -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("TOKENTOOLS_P12UTILITY") {
        candidates.push(PathBuf::from(p));
    }
    candidates.push(PathBuf::from("p12utility.win32.exe"));
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..4 {
            if let Some(d) = dir {
                candidates.push(d.join("p12utility.win32.exe"));
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    if let Some(home) = user_home() {
        candidates.push(home.join("wine-test").join("p12utility.win32.exe"));
    }
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .context("p12utility.win32.exe не найден (положите рядом с rt-export или задайте TOKENTOOLS_P12UTILITY)")
}

#[cfg(not(target_os = "windows"))]
fn sandbox_exe(exe: &Path) -> Result<PathBuf> {
    let Some(home) = user_home() else {
        return Ok(exe.to_path_buf());
    };
    if exe.starts_with(&home) {
        return Ok(exe.to_path_buf());
    }
    let cache = home.join(".cache").join("tokentools");
    std::fs::create_dir_all(&cache)?;
    let dst = cache.join("p12utility.win32.exe");
    std::fs::copy(exe, &dst).with_context(|| {
        format!(
            "не удалось скопировать {} в {}",
            exe.display(),
            dst.display()
        )
    })?;
    Ok(dst)
}

#[cfg(target_os = "windows")]
fn sandbox_exe(exe: &Path) -> Result<PathBuf> {
    Ok(exe.to_path_buf())
}

fn command_available(cmd: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|path| {
        let candidate = path.join(cmd);
        candidate.is_file()
            || (cfg!(target_os = "windows") && path.join(format!("{cmd}.exe")).is_file())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyState {
    Ready,
    Notice,
    Missing,
}

impl DependencyState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "OK",
            Self::Notice => "INFO",
            Self::Missing => "MISSING",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DependencyStatus {
    pub name: &'static str,
    pub state: DependencyState,
    pub detail: String,
    pub used_by: &'static str,
}

fn flatpak_wine_available() -> bool {
    Command::new("flatpak")
        .args(["info", "org.winehq.Wine"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn check_pcsc() -> DependencyStatus {
    match rt_pcsc::Pcsc::load() {
        Ok(pcsc) => match pcsc.list_readers() {
            Ok(readers) if readers.is_empty() => DependencyStatus {
                name: "PC/SC",
                state: DependencyState::Notice,
                detail: "библиотека загружена, считыватели не найдены".into(),
                used_by: "list, dump",
            },
            Ok(readers) => DependencyStatus {
                name: "PC/SC",
                state: DependencyState::Ready,
                detail: format!("библиотека загружена, считывателей: {}", readers.len()),
                used_by: "list, dump",
            },
            Err(error) => DependencyStatus {
                name: "PC/SC",
                state: DependencyState::Missing,
                detail: format!("не удалось получить список считывателей: {error}"),
                used_by: "list, dump",
            },
        },
        Err(error) => DependencyStatus {
            name: "PC/SC",
            state: DependencyState::Missing,
            detail: error.to_string(),
            used_by: "list, dump",
        },
    }
}

fn check_wine() -> DependencyStatus {
    if cfg!(target_os = "windows") {
        return DependencyStatus {
            name: "Wine / Flatpak Wine",
            state: DependencyState::Ready,
            detail: "не требуется на Windows".into(),
            used_by: "fix",
        };
    }
    let wine = command_available("wine");
    let flatpak = command_available("flatpak") && flatpak_wine_available();
    let detail = match (wine, flatpak) {
        (true, true) => "найдены wine и Flatpak Wine".to_string(),
        (true, false) => "найден wine".to_string(),
        (false, true) => "найден Flatpak Wine".to_string(),
        (false, false) => "не найден wine или установленный org.winehq.Wine".to_string(),
    };
    DependencyStatus {
        name: "Wine / Flatpak Wine",
        state: if wine || flatpak {
            DependencyState::Ready
        } else {
            DependencyState::Missing
        },
        detail,
        used_by: "fix",
    }
}

fn check_p12utility() -> DependencyStatus {
    match find_p12utility() {
        Ok(path) => DependencyStatus {
            name: "p12utility.win32.exe",
            state: DependencyState::Ready,
            detail: path.display().to_string(),
            used_by: "fix",
        },
        Err(error) => DependencyStatus {
            name: "p12utility.win32.exe",
            state: DependencyState::Missing,
            detail: error.to_string(),
            used_by: "fix",
        },
    }
}

fn check_csp_tool(name: &'static str, used_by: &'static str) -> DependencyStatus {
    match find_csp_tool(name) {
        Ok(path) => DependencyStatus {
            name,
            state: DependencyState::Ready,
            detail: path.display().to_string(),
            used_by,
        },
        Err(error) => DependencyStatus {
            name,
            state: DependencyState::Missing,
            detail: error.to_string(),
            used_by,
        },
    }
}

pub fn check_dependencies() -> Vec<DependencyStatus> {
    vec![
        check_pcsc(),
        check_wine(),
        check_p12utility(),
        check_csp_tool("csptest", "verify"),
        check_csp_tool("certmgr", "cert --install"),
    ]
}

fn backup_container(container_dir: &Path) -> Result<PathBuf> {
    if !is_container_dir(container_dir) {
        bail!(
            "{}: неполный контейнер, нужны все 6 файлов",
            container_dir.display()
        );
    }
    let parent = container_dir
        .parent()
        .context("у контейнера нет родительского каталога")?;
    let name = container_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("container");
    for attempt in 0..100 {
        let backup = parent.join(format!(
            ".{name}.tokentools-backup-{}-{attempt}",
            now_nanos()
        ));
        match std::fs::create_dir(&backup) {
            Ok(()) => {
                for file in CONTAINER_FILES {
                    if let Err(error) = std::fs::copy(container_dir.join(file), backup.join(file)) {
                        let _ = std::fs::remove_dir_all(&backup);
                        return Err(error)
                            .with_context(|| format!("не удалось сохранить backup файла {file}"));
                    }
                }
                return Ok(backup);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("не удалось создать backup контейнера"),
        }
    }
    bail!("не удалось подобрать уникальное имя backup контейнера")
}

fn restore_container(container_dir: &Path, backup: &Path) -> Result<()> {
    for file in CONTAINER_FILES {
        std::fs::copy(backup.join(file), container_dir.join(file))
            .with_context(|| format!("не удалось восстановить {file} из backup"))?;
    }
    Ok(())
}

pub fn fix_container(container_dir: &Path, cert: &Path) -> Result<String> {
    let container_dir = container_dir
        .canonicalize()
        .context("каталог контейнера не найден")?;
    let cert = cert.canonicalize().context("сертификат не найден")?;
    if !cert.is_file() {
        bail!("{}: это не файл сертификата", cert.display());
    }
    let backup = backup_container(&container_dir)?;
    let exe = sandbox_exe(&find_p12utility()?.canonicalize()?)?;
    let mut cmd;
    if cfg!(target_os = "windows") {
        cmd = Command::new(&exe);
    } else if command_available("wine") {
        cmd = Command::new("wine");
        cmd.arg(&exe);
    } else if command_available("flatpak") && flatpak_wine_available() {
        cmd = Command::new("flatpak");
        cmd.args(["run"]);
        cmd.arg(format!("--filesystem={}", container_dir.display()));
        if cert.parent() != container_dir.parent() {
            if let Some(parent) = cert.parent() {
                cmd.arg(format!("--filesystem={}", parent.display()));
            }
        }
        cmd.args(["org.winehq.Wine"]).arg(&exe);
    } else {
        bail!("Wine не найден: установите flatpak org.winehq.Wine//wow64-25.08 (или wine)");
    }
    let out = cmd
        .args(["--cprepair", "--container_folder", ".", "--cert"])
        .arg(&cert)
        .arg("--keyexport")
        .current_dir(&container_dir)
        .output()
        .context("не удалось запустить p12utility")?;
    let mut text = decode_csp_output(&out.stdout);
    text.push_str(&decode_csp_output(&out.stderr));
    let succeeded = out.status.success()
        && (contains_success_marker(&out.stdout)
            || contains_success_marker(&out.stderr)
            || text.contains("успешно")
            || text.to_ascii_lowercase().contains("success"));
    if !succeeded {
        if let Err(error) = restore_container(&container_dir, &backup) {
            bail!(
                "p12utility завершился с ошибкой, а откат не удался: {error}; backup: {}\n{text}",
                backup.display()
            );
        }
        bail!(
            "p12utility не подтвердил успешную операцию; исходный контейнер восстановлен из {}\n{}",
            backup.display(),
            text
        );
    }
    text.push_str(&format!("\nBackup: {}\n", backup.display()));
    Ok(text)
}

fn find_csp_tool(name: &str) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "windows") {
        for base in [
            r"C:\Program Files\Crypto Pro\CSP",
            r"C:\Program Files (x86)\Crypto Pro\CSP",
        ] {
            candidates.push(PathBuf::from(base).join(format!("{name}.exe")));
        }
    } else {
        for base in ["/opt/cprocsp/bin/amd64", "/opt/cprocsp/bin"] {
            candidates.push(Path::new(base).join(name));
        }
    }
    if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
        return Ok(p);
    }
    bail!("КриптоПро CSP: {name} не найден (проверьте установку CSP)")
}

fn copy_container(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir(dst)?;
    for file in CONTAINER_FILES {
        let source = src.join(file);
        if !source.is_file() {
            bail!("{}: отсутствует {file}", src.display());
        }
        std::fs::copy(&source, dst.join(file))?;
    }
    Ok(())
}

fn verify_name(attempt: u32) -> String {
    let value = (now_nanos() as u64)
        .wrapping_add(std::process::id() as u64)
        .wrapping_add(attempt as u64)
        & 0x0fff_ffff;
    format!("t{value:07x}")
}

pub fn verify_container(container_dir: &Path) -> Result<String> {
    let container_dir = container_dir
        .canonicalize()
        .context("каталог контейнера не найден")?;
    if !is_container_dir(&container_dir) {
        bail!(
            "{}: неполный контейнер, нужны все 6 файлов",
            container_dir.display()
        );
    }
    if cfg!(target_os = "windows") {
        let out = Command::new(find_csp_tool("csptest")?)
            .args(["-keyset", "-check", "-container"])
            .arg(&container_dir)
            .output()
            .context("не удалось запустить csptest")?;
        let mut text = decode_csp_output(&out.stdout);
        text.push_str(&decode_csp_output(&out.stderr));
        if !out.status.success() {
            bail!("csptest завершился с ошибкой\n{text}");
        }
        return Ok(text);
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let keys = PathBuf::from("/var/opt/cprocsp/keys").join(&user);
    if !keys.is_dir() {
        bail!("каталог ключей CSP не найден: {}", keys.display());
    }
    let mut tmp = None;
    for attempt in 0..100 {
        let name = verify_name(attempt);
        let path = keys.join(format!("{name}.000"));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                tmp = Some((name, path));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("не удалось создать временный CSP-контейнер"),
        }
    }
    let Some((name, tmp)) = tmp else {
        bail!("не удалось подобрать уникальное имя временного CSP-контейнера");
    };
    let result = (|| -> Result<std::process::Output> {
        copy_container(&container_dir, &tmp)?;
        std::fs::write(tmp.join("name.key"), build_name_key(name.as_bytes()))?;
        Command::new(find_csp_tool("csptest")?)
            .args(["-keyset", "-check", "-container"])
            .arg(format!("\\\\.\\hdimage\\{name}"))
            .output()
            .context("не удалось запустить csptest")
    })();
    let cleanup = std::fs::remove_dir_all(&tmp);
    let out = result?;
    if let Err(error) = cleanup {
        bail!(
            "не удалось удалить временный CSP-контейнер {}: {error}",
            tmp.display()
        );
    }
    let mut text = decode_csp_output(&out.stdout);
    text.push_str(&decode_csp_output(&out.stderr));
    if !out.status.success() {
        bail!("csptest завершился с ошибкой\n{text}");
    }
    Ok(text)
}

pub fn certmgr_install(
    cert: &Path,
    container: Option<&str>,
    store: &str,
) -> Result<(String, bool)> {
    let mut cmd = Command::new(find_csp_tool("certmgr")?);
    cmd.args(["-install", "-file"]).arg(cert);
    if let Some(c) = container {
        cmd.args(["-container", c]);
    }
    cmd.args(["-store", store]);
    let out = cmd.output().context("не удалось запустить certmgr")?;
    let mut text = decode_csp_output(&out.stdout);
    text.push_str(&decode_csp_output(&out.stderr));
    Ok((text, out.status.success()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_cp1251_success_message() {
        let bytes = [0xf3, 0xf1, 0xef, 0xe5, 0xf8, 0xed, 0xee];
        assert_eq!(decode_csp_output(&bytes), "успешно");
        assert!(contains_success_marker(&bytes));
    }

    #[test]
    fn preserves_utf8_output() {
        assert_eq!(
            decode_csp_output("Операция успешно завершена.".as_bytes()),
            "Операция успешно завершена."
        );
    }

    #[test]
    fn dependency_state_labels_are_stable() {
        assert_eq!(DependencyState::Ready.label(), "OK");
        assert_eq!(DependencyState::Notice.label(), "INFO");
        assert_eq!(DependencyState::Missing.label(), "MISSING");
    }
}
