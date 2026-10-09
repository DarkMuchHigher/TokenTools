use anyhow::{Context, Result, bail};
use cryptopro_container::{
    CONTAINER_FILES, build_name_key, cp1251_to_string, is_container_dir, parse_name_key,
    read_container,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn decode_csp_output(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| cp1251_to_string(bytes))
}

#[cfg(unix)]
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

#[cfg(unix)]
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

#[cfg(not(unix))]
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

pub fn write_private_once(path: &Path, data: &[u8]) -> Result<()> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == data {
            return Ok(());
        }
        bail!(
            "{} уже существует и отличается от извлечённого: удалите или переименуйте файл",
            path.display()
        );
    }
    write_private(path, data).with_context(|| format!("не удалось записать {}", path.display()))?;
    Ok(())
}

pub fn save_container(dest: &Path, folder: &str, files: &[(String, Vec<u8>)]) -> Result<PathBuf> {
    let out = dest.join(folder);
    if out.exists() {
        bail!("{} уже существует; перезапись запрещена", out.display());
    }
    std::fs::create_dir_all(dest)
        .with_context(|| format!("не удалось создать {}", dest.display()))?;
    let partial = dest.join(format!(
        ".{folder}.partial-{}-{}",
        std::process::id(),
        now_nanos()
    ));
    create_private_dir(&partial)
        .with_context(|| format!("не удалось создать {}", partial.display()))?;
    let result = files
        .iter()
        .try_for_each(|(name, data)| {
            let path = partial.join(name);
            write_private(&path, data)
                .with_context(|| format!("не удалось записать {}", path.display()))
        })
        .and_then(|()| {
            std::fs::rename(&partial, &out)
                .with_context(|| format!("не удалось создать {}", out.display()))
        });
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&partial);
    }
    result.map(|()| out)
}

fn contains_success_marker(output: &[u8]) -> bool {
    output
        .windows(7)
        .any(|w| w == b"\xf3\xf1\xef\xe5\xf8\xed\xee")
}

pub fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

pub fn now_nanos() -> u128 {
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
        .context("p12utility.win32.exe не найден (положите рядом с tokentools или задайте TOKENTOOLS_P12UTILITY)")
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

fn status(
    name: &'static str,
    used_by: &'static str,
    state: DependencyState,
    detail: String,
) -> DependencyStatus {
    DependencyStatus {
        name,
        state,
        detail,
        used_by,
    }
}

fn status_from_path(
    name: &'static str,
    used_by: &'static str,
    found: Result<PathBuf>,
) -> DependencyStatus {
    match found {
        Ok(path) => status(
            name,
            used_by,
            DependencyState::Ready,
            path.display().to_string(),
        ),
        Err(error) => status(name, used_by, DependencyState::Missing, error.to_string()),
    }
}

fn check_pcsc() -> DependencyStatus {
    let pcsc = |state, detail| status("PC/SC", "list, dump", state, detail);
    match pcsc_transport::Pcsc::load().and_then(|pcsc| pcsc.list_readers()) {
        Ok(readers) if readers.is_empty() => pcsc(
            DependencyState::Notice,
            "библиотека загружена, считыватели не найдены".into(),
        ),
        Ok(readers) => pcsc(
            DependencyState::Ready,
            format!("библиотека загружена, считывателей: {}", readers.len()),
        ),
        Err(error) => pcsc(DependencyState::Missing, error.to_string()),
    }
}

fn check_wine() -> DependencyStatus {
    let wine = |state, detail: &str| status("Wine / Flatpak Wine", "fix", state, detail.into());
    if cfg!(target_os = "windows") {
        return wine(DependencyState::Ready, "не требуется на Windows");
    }
    let wine_found = command_available("wine");
    let flatpak = command_available("flatpak") && flatpak_wine_available();
    match (wine_found, flatpak) {
        (true, true) => wine(DependencyState::Ready, "найдены wine и Flatpak Wine"),
        (true, false) => wine(DependencyState::Ready, "найден wine"),
        (false, true) => wine(DependencyState::Ready, "найден Flatpak Wine"),
        (false, false) => wine(
            DependencyState::Missing,
            "не найден wine или установленный org.winehq.Wine",
        ),
    }
}

pub fn check_dependencies() -> Vec<DependencyStatus> {
    vec![
        check_pcsc(),
        check_wine(),
        status_from_path("p12utility.win32.exe", "fix", find_p12utility()),
        status_from_path("csptest", "verify", find_csp_tool("csptest")),
        status_from_path("certmgr", "cert --install", find_csp_tool("certmgr")),
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
        match create_private_dir(&backup) {
            Ok(()) => {
                for file in CONTAINER_FILES {
                    let data = match std::fs::read(container_dir.join(file)) {
                        Ok(data) => data,
                        Err(error) => {
                            let _ = std::fs::remove_dir_all(&backup);
                            return Err(error)
                                .with_context(|| format!("не удалось прочитать {file}"));
                        }
                    };
                    if let Err(error) = write_private(&backup.join(file), &data) {
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
        if cert.parent() != container_dir.parent()
            && let Some(parent) = cert.parent()
        {
            cmd.arg(format!("--filesystem={}", parent.display()));
        }
        cmd.args(["org.winehq.Wine"]).arg(&exe);
    } else {
        bail!("Wine не найден: установите flatpak org.winehq.Wine//wow64-25.08 (или wine)");
    }
    cmd.args(["--cprepair", "--container_folder", ".", "--cert"])
        .arg(&cert)
        .arg("--keyexport")
        .current_dir(&container_dir);
    let backup = backup_container(&container_dir)?;
    let command_line = describe_command(&cmd);
    let out = cmd.output().context("не удалось запустить p12utility")?;
    let output = command_output(&out);
    let succeeded = out.status.success()
        && (contains_success_marker(&out.stdout)
            || contains_success_marker(&out.stderr)
            || output.contains("успешно")
            || output.to_ascii_lowercase().contains("success"));
    let text = format!("$ {command_line}\n{output}");
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
    Ok(format!("{text}\nBackup: {}\n", backup.display()))
}

fn command_output(out: &std::process::Output) -> String {
    decode_csp_output(&out.stdout) + &decode_csp_output(&out.stderr)
}

fn describe_command(cmd: &Command) -> String {
    let mut parts = vec![cmd.get_program().to_string_lossy().into_owned()];
    for arg in cmd.get_args() {
        let arg = arg.to_string_lossy();
        if arg.contains(' ') {
            parts.push(format!("\"{arg}\""));
        } else {
            parts.push(arg.into_owned());
        }
    }
    parts.join(" ")
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
    for file in CONTAINER_FILES {
        let source = src.join(file);
        if !source.is_file() {
            bail!("{}: отсутствует {file}", src.display());
        }
        write_private(&dst.join(file), &std::fs::read(&source)?)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbVolume {
    pub uuid: String,
    pub mount: PathBuf,
}

impl UsbVolume {
    pub fn label(&self) -> String {
        self.mount
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.uuid.clone())
    }
}

fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = (bytes[i] == b'\\' && i + 4 <= bytes.len())
            .then(|| std::str::from_utf8(&bytes[i + 1..i + 4]).ok())
            .flatten()
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_usb_device(device: &str) -> bool {
    let Some(name) = Path::new(device).file_name() else {
        return false;
    };
    std::fs::canonicalize(Path::new("/sys/class/block").join(name))
        .is_ok_and(|path| path.to_string_lossy().contains("/usb"))
}

fn volume_uuid_of(device: &str) -> Option<String> {
    let device = std::fs::canonicalize(device).ok()?;
    std::fs::read_dir("/dev/disk/by-uuid")
        .ok()?
        .flatten()
        .find(|entry| std::fs::canonicalize(entry.path()).ok().as_deref() == Some(device.as_path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
}

pub fn usb_volumes() -> Vec<UsbVolume> {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    let mut volumes: Vec<UsbVolume> = Vec::new();
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let (Some(device), Some(mount)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !device.starts_with("/dev/") || !is_usb_device(device) {
            continue;
        }
        let mount = PathBuf::from(unescape_mount_field(mount));
        if volumes.iter().any(|volume| volume.mount == mount) {
            continue;
        }
        if let Some(uuid) = volume_uuid_of(device) {
            volumes.push(UsbVolume { uuid, mount });
        }
    }
    volumes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployedContainer {
    pub name: String,
    pub dir: PathBuf,
    pub csp_name: Option<String>,
}

pub fn link_certificate(container_name: &str) -> Result<String> {
    let mut cmd = Command::new(find_csp_tool("cryptcp")?);
    cmd.args(["-cspcert", "-cont"])
        .arg(container_name)
        .arg("-du");
    let command_line = describe_command(&cmd);
    let out = cmd.output().context("не удалось запустить cryptcp")?;
    let text = format!("$ {command_line}\n{}", command_output(&out));
    if !out.status.success() {
        bail!("cryptcp не подтвердил установку сертификата\n{text}");
    }
    Ok(text)
}

pub fn csp_keys_dir() -> Result<PathBuf> {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let keys = PathBuf::from("/var/opt/cprocsp/keys").join(user);
    if !keys.is_dir() {
        bail!("каталог ключей CSP не найден: {}", keys.display());
    }
    Ok(keys)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageContainer {
    pub name: String,
    pub dir: PathBuf,
    pub files: usize,
    pub volume: Option<String>,
}

impl StorageContainer {
    pub fn csp_name(&self) -> String {
        match &self.volume {
            Some(uuid) => format!("\\\\.\\{uuid}\\{}", self.name),
            None => format!("\\\\.\\HDIMAGE\\{}", self.name),
        }
    }

    pub fn container_name(&self) -> Option<String> {
        std::fs::read(self.dir.join("name.key"))
            .ok()
            .and_then(|data| parse_name_key(&data))
    }

    pub fn is_complete(&self) -> bool {
        self.files == CONTAINER_FILES.len()
    }
}

fn storage_name(name: &str) -> Result<String> {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        bail!("некорректное имя контейнера: {name}");
    }
    Ok(sanitized.to_string())
}

fn storage_dir(name: &str) -> Result<PathBuf> {
    Ok(csp_keys_dir()?.join(format!("{}.000", storage_name(name)?)))
}

enum Target {
    Store,
    Flash(String),
    Folder,
}

fn resolve_target(dest: &Path) -> Result<Target> {
    if csp_keys_dir().is_ok_and(|keys| keys.canonicalize().ok().as_deref() == Some(dest)) {
        return Ok(Target::Store);
    }
    for volume in usb_volumes() {
        let Ok(mount) = volume.mount.canonicalize() else {
            continue;
        };
        if mount == dest {
            return Ok(Target::Flash(volume.uuid));
        }
        if dest.starts_with(&mount) {
            bail!(
                "КриптоПро ищет контейнеры только в корне флешки: {}",
                mount.display()
            );
        }
    }
    Ok(Target::Folder)
}

pub fn deploy_container(src: &Path, dest: &Path, name: Option<&str>) -> Result<DeployedContainer> {
    if !is_container_dir(src) {
        bail!("{}: неполный контейнер, нужны все 6 файлов", src.display());
    }
    let own_name = read_container(src)?
        .0
        .context("в name.key нет имени контейнера")?;
    let name = storage_name(name.unwrap_or(&own_name))?;
    std::fs::create_dir_all(dest)
        .with_context(|| format!("не удалось создать {}", dest.display()))?;
    let canonical = dest.canonicalize()?;
    let target = resolve_target(&canonical)?;
    let dir = canonical.join(format!("{name}.000"));
    if dir.exists() {
        bail!("{} уже существует", dir.display());
    }
    create_private_dir(&dir).with_context(|| format!("не удалось создать {}", dir.display()))?;
    let result = copy_container(src, &dir).and_then(|()| {
        if name == own_name {
            return Ok(());
        }
        std::fs::write(dir.join("name.key"), build_name_key(name.as_bytes()))
            .with_context(|| format!("не удалось переименовать контейнер в {name}"))
    });
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(error);
    }
    #[cfg(unix)]
    for path in [&dir, &canonical] {
        let _ = std::fs::File::open(path).and_then(|handle| handle.sync_all());
    }
    let csp_name = match target {
        Target::Store => Some(format!("\\\\.\\HDIMAGE\\{name}")),
        Target::Flash(uuid) => Some(format!("\\\\.\\{uuid}\\{name}")),
        Target::Folder => None,
    };
    Ok(DeployedContainer {
        name,
        dir,
        csp_name,
    })
}

pub fn remove_container(dir: &Path) -> Result<()> {
    let dir = dir
        .canonicalize()
        .with_context(|| format!("{} не найден", dir.display()))?;
    if !dir.to_string_lossy().ends_with(".000") || !is_container_dir(&dir) {
        bail!(
            "{}: не похоже на контейнер, удаление отменено",
            dir.display()
        );
    }
    let parent = dir
        .parent()
        .context("у контейнера нет родительского каталога")?;
    let known = csp_keys_dir()
        .ok()
        .into_iter()
        .chain(usb_volumes().into_iter().map(|volume| volume.mount))
        .any(|root| root.canonicalize().ok().as_deref() == Some(parent));
    if !known {
        bail!(
            "{}: контейнер лежит не в хранилище CSP и не на флешке, удаление отменено",
            dir.display()
        );
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("не удалось удалить {}", dir.display()))
}

pub fn unmount_container(name: &str) -> Result<PathBuf> {
    let dir = storage_dir(name)?;
    remove_container(&dir)?;
    Ok(dir)
}

fn scan_containers(root: &Path, volume: Option<&str>, out: &mut Vec<StorageContainer>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = file_name.strip_suffix(".000") else {
            continue;
        };
        if !dir.is_dir() {
            continue;
        }
        out.push(StorageContainer {
            name: name.to_string(),
            files: CONTAINER_FILES
                .iter()
                .filter(|file| dir.join(file).is_file())
                .count(),
            dir,
            volume: volume.map(str::to_string),
        });
    }
}

pub fn storage_containers() -> Vec<StorageContainer> {
    let mut out = Vec::new();
    if let Ok(keys) = csp_keys_dir() {
        scan_containers(&keys, None, &mut out);
    }
    for volume in usb_volumes() {
        scan_containers(&volume.mount, Some(&volume.uuid), &mut out);
    }
    out.sort_by(|a, b| (&a.volume, &a.name).cmp(&(&b.volume, &b.name)));
    out
}

fn unique_storage_name() -> Result<String> {
    for attempt in 0..100 {
        let name = verify_name(attempt);
        if !storage_dir(&name)?.exists() {
            return Ok(name);
        }
    }
    bail!("не удалось подобрать уникальное имя временного CSP-контейнера")
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
        let mut cmd = Command::new(find_csp_tool("csptest")?);
        cmd.args(["-keyset", "-check", "-container"])
            .arg(&container_dir);
        let command_line = describe_command(&cmd);
        let out = cmd.output().context("не удалось запустить csptest")?;
        let text = format!("$ {command_line}\n{}", command_output(&out));
        if !out.status.success() {
            bail!("csptest завершился с ошибкой\n{text}");
        }
        return Ok(text);
    }
    let csptest = find_csp_tool("csptest")?;
    let name = unique_storage_name()?;
    let deployed = deploy_container(&container_dir, &csp_keys_dir()?, Some(&name))?;
    let csp_name = deployed
        .csp_name
        .clone()
        .context("временный контейнер не попал в хранилище CSP")?;
    let mut cmd = Command::new(csptest);
    cmd.args(["-keyset", "-check", "-container"]).arg(csp_name);
    let command_line = describe_command(&cmd);
    let result = cmd.output().context("не удалось запустить csptest");
    let cleanup = remove_container(&deployed.dir);
    let out = result?;
    if let Err(error) = cleanup {
        bail!("не удалось удалить временный CSP-контейнер: {error}");
    }
    let text = format!("$ {command_line}\n{}", command_output(&out));
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
    let command_line = describe_command(&cmd);
    let output = cmd.output().context("не удалось запустить certmgr")?;
    let text = format!("$ {command_line}\n{}", command_output(&output));
    Ok((text, output.status.success()))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreCert {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sha1: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub has_key: bool,
    pub container: Option<String>,
}

pub fn certmgr_list(store: &str) -> Result<Vec<StoreCert>> {
    let output = Command::new(find_csp_tool("certmgr")?)
        .args(["-list", "-store", store])
        .output()
        .context("не удалось запустить certmgr")?;
    let text = decode_csp_output(&output.stdout);
    if !output.status.success() && !text.contains("-------") {
        bail!("certmgr завершился с ошибкой: $ certmgr -list -store {store}");
    }
    Ok(parse_certmgr_list(&text))
}

fn parse_certmgr_list(text: &str) -> Vec<StoreCert> {
    let mut certs = Vec::new();
    let mut current: Option<StoreCert> = None;
    for line in text.lines() {
        let line = line.trim_end();
        if is_cert_block_header(line) {
            certs.extend(current.take());
            current = Some(StoreCert::default());
            continue;
        }
        let Some(cert) = current.as_mut() else {
            continue;
        };
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match label.trim() {
            "Субъект" => cert.subject = value.to_string(),
            "Издатель" => cert.issuer = value.to_string(),
            "Серийный номер" => cert.serial = value.to_string(),
            "SHA1 отпечаток" => cert.sha1 = value.to_string(),
            "Выдан" => cert.not_before = Some(normalize_certmgr_date(value)),
            "Истекает" => cert.not_after = Some(normalize_certmgr_date(value)),
            "Ссылка на ключ" => cert.has_key = value == "Есть",
            "Контейнер" => cert.container = Some(value.to_string()),
            _ => {}
        }
    }
    certs.extend(current);
    certs
}

fn is_cert_block_header(line: &str) -> bool {
    let line = line.trim();
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && line[digits..].chars().all(|c| c == '-')
}

fn normalize_certmgr_date(value: &str) -> String {
    let tokens: Vec<&str> = value.split(['/', ' ']).filter(|t| !t.is_empty()).collect();
    if tokens.len() >= 3 && tokens[0].len() == 2 && tokens[1].len() == 2 && tokens[2].len() == 4 {
        let rest = tokens[3..].join(" ");
        if rest.is_empty() {
            format!("{}-{}-{}", tokens[2], tokens[1], tokens[0])
        } else {
            format!("{}-{}-{} {rest}", tokens[2], tokens[1], tokens[0])
        }
    } else {
        value.to_string()
    }
}

pub fn cn_from_dn(dn: &str) -> Option<String> {
    let start = dn.find("CN=")? + "CN=".len();
    let rest = &dn[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = quoted.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    out.push('"');
                    chars.next();
                } else {
                    break;
                }
            } else {
                out.push(c);
            }
        }
        Some(out)
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
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
    fn copy_container_accepts_precreated_dir_and_uses_private_permissions() {
        let base = std::env::temp_dir().join(format!("tokentools-copy-{}", now_nanos()));
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(&src).expect("source dir");
        std::fs::create_dir(&dst).expect("destination dir is created by the caller");
        for file in CONTAINER_FILES {
            std::fs::write(src.join(file), b"x").expect("source file");
        }
        copy_container(&src, &dst).expect("copy into an existing directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dst.join("name.key"))
                .expect("copied file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "container files must stay owner-only");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn save_container_is_atomic_and_never_overwrites() {
        let base = std::env::temp_dir().join(format!("tokentools-save-{}", now_nanos()));
        let files = vec![("name.key".to_string(), b"a".to_vec())];
        let out = save_container(&base, "2560-0001", &files).expect("first save");
        assert_eq!(std::fs::read(out.join("name.key")).expect("saved"), b"a");
        assert!(save_container(&base, "2560-0001", &files).is_err());
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .expect("dest dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, ["2560-0001"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_private_once_keeps_existing_different_file() {
        let path = std::env::temp_dir().join(format!("tokentools-once-{}", now_nanos()));
        write_private_once(&path, b"first").expect("first write");
        write_private_once(&path, b"first").expect("identical content is fine");
        assert!(write_private_once(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).expect("file readable"), b"first");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unescapes_proc_mounts_fields() {
        assert_eq!(
            unescape_mount_field("/run/media/dark/My\\040Flash"),
            "/run/media/dark/My Flash"
        );
        assert_eq!(unescape_mount_field("/mnt/a\\134b"), "/mnt/a\\b");
        assert_eq!(unescape_mount_field("/mnt/plain\\"), "/mnt/plain\\");
    }

    #[test]
    fn deploy_and_remove_roundtrip_in_plain_folder() {
        let base = std::env::temp_dir().join(format!("tokentools-deploy-{}", now_nanos()));
        let src = base.join("src");
        std::fs::create_dir_all(&src).expect("src dir");
        for file in CONTAINER_FILES {
            std::fs::write(src.join(file), b"x").expect("file");
        }
        std::fs::write(src.join("name.key"), build_name_key(b"orig")).expect("name.key");
        let dest = base.join("dest");
        let deployed = deploy_container(&src, &dest, Some("copy")).expect("deploy");
        assert_eq!(deployed.csp_name, None);
        assert_eq!(deployed.name, "copy");
        assert_eq!(
            parse_name_key(&std::fs::read(deployed.dir.join("name.key")).expect("name.key")),
            Some("copy".to_string())
        );
        assert!(deploy_container(&src, &dest, Some("copy")).is_err());
        assert!(remove_container(&deployed.dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn dependency_state_labels_are_stable() {
        assert_eq!(DependencyState::Ready.label(), "OK");
        assert_eq!(DependencyState::Notice.label(), "INFO");
        assert_eq!(DependencyState::Missing.label(), "MISSING");
    }

    #[test]
    fn parses_certmgr_list_blocks() {
        let sample = r#"Certmgr Ver:5.0.13003 OS:Linux CPU:AMD64 (c) "КРИПТО-ПРО", 2007-2024.
=============================================================================
1-------
Издатель            : ИНН ЮЛ=7707329152, CN=Федеральная налоговая служба
Субъект             : ИНН ЮЛ=7801571136, CN="ООО ""АНДРЕЕВСКИЙ ДОМ""", T=ГЕНЕРАЛЬНЫЙ ДИРЕКТОР
Серийный номер      : 0x03B0979C0073B4A1A0499CC8CDF876E675
SHA1 отпечаток      : e2eaea9134f40622ce79675ba9d49aaf9f53cebe
Выдан               : 24/06/2026 09:20:08 UTC
Истекает            : 24/09/2027 09:30:08 UTC
Ссылка на ключ      : Есть
Контейнер           : GENERIC\FLASH_AAAC0DD1\2560\D08E
Назначение/EKU      : 1.3.6.1.5.5.7.3.2 Проверка подлинности клиента
                      1.3.6.1.5.5.7.3.4 Защищенная электронная почта
2-------
Издатель            : CN=Корень
Субъект             : CN=Корень
Серийный номер      : 0x01
SHA1 отпечаток      : aabb
Истекает            : 01/01/2040 00:00:00 UTC
Ссылка на ключ      : Нет
"#;
        let certs = parse_certmgr_list(sample);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].serial, "0x03B0979C0073B4A1A0499CC8CDF876E675");
        assert_eq!(
            certs[0].not_before.as_deref(),
            Some("2026-06-24 09:20:08 UTC")
        );
        assert_eq!(
            certs[0].not_after.as_deref(),
            Some("2027-09-24 09:30:08 UTC")
        );
        assert!(certs[0].has_key);
        assert_eq!(
            certs[0].container.as_deref(),
            Some("GENERIC\\FLASH_AAAC0DD1\\2560\\D08E")
        );
        assert_eq!(
            cn_from_dn(&certs[0].subject).as_deref(),
            Some("ООО \"АНДРЕЕВСКИЙ ДОМ\"")
        );
        assert!(!certs[1].has_key);
        assert_eq!(cn_from_dn(&certs[1].subject).as_deref(), Some("Корень"));
    }

    #[test]
    fn cn_from_dn_handles_plain_and_quoted() {
        assert_eq!(
            cn_from_dn("C=RU, CN=Простой, O=X").as_deref(),
            Some("Простой")
        );
        assert_eq!(
            cn_from_dn("CN=\"A \"\"B\"\" C\"").as_deref(),
            Some("A \"B\" C")
        );
        assert_eq!(cn_from_dn("O=Без CN"), None);
    }
}
