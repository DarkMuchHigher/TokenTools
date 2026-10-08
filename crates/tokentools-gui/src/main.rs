use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Devices,
    Container,
    Certs,
    Log,
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Info,
    Ok,
    Err,
}

#[derive(Clone)]
struct TokenContainer {
    path: Vec<u16>,
    name: String,
    files: Vec<(String, Vec<u8>)>,
}

impl TokenContainer {
    fn folder(&self) -> String {
        if self.path.is_empty() {
            "корень".to_string()
        } else {
            self.path
                .iter()
                .map(|f| format!("{f:04x}"))
                .collect::<Vec<_>>()
                .join("-")
        }
    }

    fn size(&self) -> usize {
        self.files.iter().map(|(_, d)| d.len()).sum()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum PickFor {
    Container,
    Dump,
}

struct Picker {
    path: PathBuf,
    dirs: Vec<String>,
    for_what: PickFor,
}

impl Picker {
    fn new(for_what: PickFor, start: &str) -> Self {
        let mut path = PathBuf::from(start);
        while !path.is_dir() {
            if !path.pop() {
                path = PathBuf::from("/");
                break;
            }
        }
        let mut p = Self {
            path,
            dirs: Vec::new(),
            for_what,
        };
        p.reload();
        p
    }

    fn reload(&mut self) {
        let mut dirs: Vec<String> = std::fs::read_dir(&self.path)
            .map(|rd| {
                rd.filter_map(|e| {
                    let e = e.ok()?;
                    if e.file_type().ok()?.is_dir() {
                        Some(e.file_name().to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .collect()
            })
            .unwrap_or_default();
        dirs.retain(|d| !d.starts_with('.'));
        dirs.sort_by_key(|d| d.to_lowercase());
        self.dirs = dirs;
    }

    fn enter(&mut self, name: &str) {
        self.path.push(name);
        self.reload();
    }

    fn go_to_parent(&mut self) {
        if self.path.pop() && self.path.as_os_str().is_empty() {
            self.path = PathBuf::from("/");
        }
        self.reload();
    }
}

enum Msg {
    Log(Level, String),
    Status(String),
    Readers(Vec<String>),
    Containers(Vec<TokenContainer>),
    PinFailed,
    Certs(Result<Vec<certfix::StoreCert>, String>),
    PollDone,
    Done,
}

#[derive(Clone, Copy)]
struct Palette {
    bg: egui::Color32,
    card: egui::Color32,
    stroke: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    accent: egui::Color32,
    ok: egui::Color32,
    err: egui::Color32,
}

fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            bg: egui::Color32::from_rgb(0x1B, 0x1F, 0x24),
            card: egui::Color32::from_rgb(0x23, 0x28, 0x2E),
            stroke: egui::Color32::from_rgb(0x32, 0x39, 0x43),
            text: egui::Color32::from_rgb(0xE7, 0xEA, 0xEE),
            muted: egui::Color32::from_rgb(0x96, 0xA0, 0xAC),
            accent: egui::Color32::from_rgb(0x5B, 0x8D, 0xD6),
            ok: egui::Color32::from_rgb(0x6F, 0xBF, 0x73),
            err: egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
        }
    } else {
        Palette {
            bg: egui::Color32::from_rgb(0xF1, 0xF3, 0xF6),
            card: egui::Color32::from_rgb(0xFF, 0xFF, 0xFF),
            stroke: egui::Color32::from_rgb(0xDA, 0xDF, 0xE5),
            text: egui::Color32::from_rgb(0x1E, 0x23, 0x29),
            muted: egui::Color32::from_rgb(0x66, 0x70, 0x7C),
            accent: egui::Color32::from_rgb(0x2E, 0x5C, 0x9E),
            ok: egui::Color32::from_rgb(0x2E, 0x8B, 0x57),
            err: egui::Color32::from_rgb(0xC0, 0x39, 0x2B),
        }
    }
}

fn apply_theme(ctx: &egui::Context, dark: bool) {
    let palette = palette(dark);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.style_mut_of(theme, |style| {
            let v = &mut style.visuals;
            v.dark_mode = dark;
            v.panel_fill = palette.bg;
            v.window_fill = palette.card;
            v.extreme_bg_color = palette.card;
            v.faint_bg_color = palette.card;
            v.override_text_color = Some(palette.text);
            v.window_stroke = egui::Stroke::new(1.0, palette.stroke);
            v.window_corner_radius = egui::CornerRadius::same(10);
            v.selection.bg_fill = palette.accent;
            v.selection.stroke = egui::Stroke::new(1.0, palette.text);
            v.hyperlink_color = palette.accent;
            let w = &mut v.widgets;
            for s in [
                &mut w.noninteractive,
                &mut w.inactive,
                &mut w.hovered,
                &mut w.active,
                &mut w.open,
            ] {
                s.corner_radius = egui::CornerRadius::same(6);
                s.bg_stroke = egui::Stroke::new(1.0, palette.stroke);
            }
            w.noninteractive.bg_fill = palette.card;
            w.noninteractive.weak_bg_fill = palette.card;
            w.noninteractive.fg_stroke = egui::Stroke::new(1.0, palette.text);
            w.inactive.bg_fill = palette.card;
            w.inactive.weak_bg_fill = palette.card;
            w.inactive.fg_stroke = egui::Stroke::new(1.0, palette.text);
            w.hovered.bg_fill = palette.stroke;
            w.hovered.weak_bg_fill = palette.stroke;
            w.hovered.fg_stroke = egui::Stroke::new(1.0, palette.text);
            w.active.bg_fill = palette.accent;
            w.active.weak_bg_fill = palette.accent;
            w.active.fg_stroke = egui::Stroke::new(1.0, palette.text);
            w.open.bg_fill = palette.card;
            w.open.weak_bg_fill = palette.card;
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 7.0);
            style.spacing.interact_size.y = 26.0;
            style.spacing.scroll.bar_width = 8.0;
            use egui::{FontFamily::Proportional, FontId, TextStyle};
            style.text_styles = [
                (TextStyle::Heading, FontId::new(19.0, Proportional)),
                (TextStyle::Body, FontId::new(14.0, Proportional)),
                (TextStyle::Button, FontId::new(14.0, Proportional)),
                (TextStyle::Small, FontId::new(12.0, Proportional)),
                (
                    TextStyle::Monospace,
                    FontId::new(13.0, egui::FontFamily::Monospace),
                ),
            ]
            .into();
        });
    }
}

struct App {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    log: Vec<(Level, String)>,
    readers: Vec<String>,
    token_containers: Vec<TokenContainer>,
    container_dir: String,
    dump_dir: String,
    page: Page,
    busy: bool,
    dark: bool,
    applied_dark: bool,
    app_icon: egui::TextureHandle,
    picker: Option<Picker>,
    status: String,
    container_info: Option<ContainerInfo>,
    info_for: String,
    next_poll: f64,
    polling: bool,
    pin: String,
    pin_failed: bool,
    certs_query: String,
    certs: Vec<certfix::StoreCert>,
    certs_loaded: bool,
    certs_loading: bool,
}

fn default_pin() -> String {
    std::env::var("TOKENTOOLS_PIN")
        .ok()
        .filter(|pin| !pin.is_empty())
        .unwrap_or_else(|| "12345678".to_string())
}

struct CertRow {
    info: Option<cryptopro_container::CertInfo>,
    size: usize,
}

struct ContainerInfo {
    name: Option<String>,
    files: Vec<(String, u64)>,
    owner: CertRow,
    chain: Vec<CertRow>,
}

fn container_info(dir: &str) -> Option<ContainerInfo> {
    if dir.trim().is_empty() {
        return None;
    }
    let path = PathBuf::from(dir);
    let (name, certs) = cryptopro_container::read_container(&path).ok()?;
    let files = cryptopro_container::CONTAINER_FILES
        .iter()
        .filter_map(|fname| {
            std::fs::metadata(path.join(fname))
                .ok()
                .map(|meta| ((*fname).to_string(), meta.len()))
        })
        .collect();
    let chain = certs
        .chain
        .iter()
        .map(|der| CertRow {
            info: cryptopro_container::parse_cert(der).ok(),
            size: der.len(),
        })
        .collect();
    Some(ContainerInfo {
        name,
        files,
        owner: CertRow {
            info: cryptopro_container::parse_cert(&certs.owner).ok(),
            size: certs.owner.len(),
        },
        chain,
    })
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} Б")
    } else {
        format!("{:.1} КБ", bytes as f64 / 1024.0)
    }
}

fn days_until(moment: &str) -> Option<i64> {
    let bytes = moment.as_bytes();
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        std::str::from_utf8(bytes.get(range)?).ok()?.parse().ok()
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    let target = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some((target - now).div_euclid(86_400))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn days_chip(ui: &mut egui::Ui, palette: &Palette, not_after: &str) {
    match days_until(not_after) {
        Some(days) if days < 0 => {
            ui.label(
                egui::RichText::new("просрочен")
                    .size(12.0)
                    .color(palette.err),
            );
        }
        Some(days) if days <= 90 => {
            ui.label(
                egui::RichText::new(format!("осталось {days} дн."))
                    .size(12.0)
                    .color(palette.accent),
            );
        }
        _ => {}
    }
}

fn cert_block(ui: &mut egui::Ui, palette: &Palette, title: &str, row: &CertRow, detailed: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new(title)
                .strong()
                .size(13.0)
                .color(palette.text),
        );
        let Some(cert) = &row.info else {
            let note = if row.size == 0 {
                "сертификат отсутствует"
            } else {
                "не разобран"
            };
            ui.label(egui::RichText::new(note).size(12.5).color(palette.err));
            return;
        };
        let subject = cert
            .subject_cn
            .clone()
            .unwrap_or_else(|| "(без CN)".to_string());
        ui.label(egui::RichText::new(subject).size(13.0).color(palette.text));
        if let Some(not_after) = &cert.not_after {
            days_chip(ui, palette, not_after);
        }
    });
    let Some(cert) = &row.info else {
        return;
    };
    if !detailed {
        return;
    }
    let field = |ui: &mut egui::Ui, label: &str, value: String, mono: bool| {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(label).size(12.0).color(palette.muted));
            let text = egui::RichText::new(value).size(12.0).color(palette.muted);
            ui.label(if mono { text.monospace() } else { text });
        });
    };
    if let Some(issuer) = &cert.issuer_cn {
        field(ui, "Издатель:", issuer.clone(), false);
    }
    field(ui, "Серийный номер:", cert.serial_hex.clone(), true);
    if let (Some(from), Some(to)) = (&cert.not_before, &cert.not_after) {
        field(ui, "Действует:", format!("с {from} по {to}"), false);
    }
    field(ui, "SHA-1:", hex_lower(&cert.sha1), true);
    field(ui, "SHA-256:", hex_lower(&cert.sha256), true);
}

fn cert_row(ui: &mut egui::Ui, palette: &Palette, index: usize, cert: &certfix::StoreCert) {
    let id = ui.make_persistent_id(("store-cert", index));
    let mut state =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false);
    let header = ui.horizontal(|ui| {
        let toggle = state.show_toggle_button(ui, egui::collapsing_header::paint_default_icon);
        let title = certfix::cn_from_dn(&cert.subject).unwrap_or_else(|| cert.subject.clone());
        ui.label(egui::RichText::new(title).size(13.0).color(palette.text));
        if let Some(not_after) = &cert.not_after {
            days_chip(ui, palette, not_after);
        }
        if cert.has_key {
            ui.label(egui::RichText::new("ключ").size(11.5).color(palette.ok));
        }
        toggle
    });
    if header.response.interact(egui::Sense::click()).clicked() && !header.inner.clicked() {
        state.toggle(ui);
    }
    state.show_body_indented(&header.response, ui, |ui| {
        let field = |ui: &mut egui::Ui, label: &str, value: &str, mono: bool| {
            if value.is_empty() {
                return;
            }
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(label).size(12.0).color(palette.muted));
                let text = egui::RichText::new(value).size(12.0).color(palette.muted);
                ui.label(if mono { text.monospace() } else { text });
            });
        };
        field(ui, "Субъект:", &cert.subject, false);
        field(ui, "Издатель:", &cert.issuer, false);
        field(ui, "Серийный номер:", &cert.serial, true);
        field(ui, "SHA-1:", &cert.sha1, true);
        if let Some(from) = &cert.not_before {
            field(ui, "Выдан:", from, false);
        }
        if let Some(to) = &cert.not_after {
            field(ui, "Истекает:", to, false);
        }
        if let Some(container) = &cert.container {
            field(ui, "Контейнер:", container, true);
        }
    });
    ui.add_space(4.0);
}

fn detect_task(tx: &Sender<Msg>, announce: bool, pin: String, silent: bool) {
    if !silent {
        let _ = tx.send(Msg::Readers(Vec::new()));
        let _ = tx.send(Msg::Containers(Vec::new()));
        let _ = tx.send(Msg::Status("Поиск устройств…".into()));
    }
    let pcsc = match pcsc_transport::Pcsc::load() {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
            return;
        }
    };
    let readers = match pcsc.list_readers() {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
            return;
        }
    };
    let _ = tx.send(Msg::Readers(readers.clone()));
    if readers.is_empty() {
        let _ = tx.send(Msg::Containers(Vec::new()));
        if announce {
            let _ = tx.send(Msg::Log(Level::Info, "Устройства не найдены".into()));
        }
        return;
    }
    let mut containers = Vec::new();
    for reader in readers {
        let _ = tx.send(Msg::Log(Level::Info, format!("Устройство: {reader}")));
        let _ = tx.send(Msg::Status(format!("Читаю {reader}…")));
        let card = match pcsc.connect(&reader) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::Log(Level::Err, format!("{reader}: {e}")));
                continue;
            }
        };
        let fs = rutoken_fs::RutokenFs::new(&card, false);
        match fs.authenticate_user_pin(&pin) {
            Ok(outcome) => {
                let text = if outcome.already_authenticated {
                    "  PIN: сессия уже авторизована"
                } else {
                    "  PIN принят"
                };
                let _ = tx.send(Msg::Log(Level::Ok, text.into()));
            }
            Err(e) => {
                let _ = tx.send(Msg::Log(Level::Err, format!("  PIN: {e}")));
                let _ = tx.send(Msg::PinFailed);
                continue;
            }
        }
        match fs.select_mf() {
            Ok((_, 0x9000)) => {
                let _ = tx.send(Msg::Log(Level::Info, "  MF выбран (3F00)".into()));
            }
            Ok((_, sw)) => {
                let _ = tx.send(Msg::Log(
                    Level::Err,
                    format!("  MF недоступен: SW={sw:04x}"),
                ));
                continue;
            }
            Err(e) => {
                let _ = tx.send(Msg::Log(Level::Err, format!("  {e}")));
                continue;
            }
        }
        let trees = match fs.walk(6) {
            Ok(t) => t,
            Err(e) => {
                let _ = tx.send(Msg::Log(Level::Err, format!("  обход ФС: {e}")));
                continue;
            }
        };
        for (path, entries) in trees {
            let folder = if path.is_empty() {
                "корень".to_string()
            } else {
                path.iter()
                    .map(|f| format!("{f:04x}"))
                    .collect::<Vec<_>>()
                    .join("-")
            };
            if entries.len() != 6 {
                let _ = tx.send(Msg::Log(
                    Level::Info,
                    format!("  /{folder}/: {} объект(ов) — не контейнер", entries.len()),
                ));
                continue;
            }
            let mut files = Vec::with_capacity(entries.len());
            let mut ok = true;
            for (fname, entry) in rutoken_fs::CONTAINER_FILES.iter().zip(entries.iter()) {
                match fs.read_file(entry.fid, entry.size) {
                    Ok(blob) => {
                        let _ = tx.send(Msg::Log(
                            Level::Info,
                            format!("  /{folder}/{fname}: {} байт", blob.len()),
                        ));
                        files.push((fname.to_string(), blob));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Log(Level::Err, format!("  /{folder}/{fname}: {e}")));
                        ok = false;
                    }
                }
            }
            if !ok {
                let _ = tx.send(Msg::Log(
                    Level::Err,
                    format!("Контейнер /{folder}/ пропущен: не удалось прочитать все файлы"),
                ));
                continue;
            }
            let name = files
                .iter()
                .find(|(n, _)| n == "name.key")
                .and_then(|(_, d)| cryptopro_container::parse_name_key(d))
                .unwrap_or_else(|| "без имени".to_string());
            let _ = tx.send(Msg::Log(
                Level::Ok,
                format!("Контейнер «{name}» (/{folder}/)"),
            ));
            containers.push(TokenContainer { path, name, files });
        }
    }
    let _ = tx.send(Msg::Containers(containers));
}

fn card<R>(ui: &mut egui::Ui, palette: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(palette.card)
        .stroke(egui::Stroke::new(1.0, palette.stroke))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width() - 2.0);
            add(ui)
        })
        .inner
}

fn section_title(ui: &mut egui::Ui, palette: &Palette, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(15.0)
            .color(palette.text)
            .strong(),
    );
    ui.add_space(2.0);
}

fn primary_button(ui: &mut egui::Ui, palette: &Palette, text: &str) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(text)
            .color(egui::Color32::WHITE)
            .strong(),
    )
    .fill(palette.accent);
    ui.add(btn)
}

fn nav_item(ui: &mut egui::Ui, palette: &Palette, current: &mut Page, page: Page, label: &str) {
    let selected = *current == page;
    let text = if selected {
        egui::RichText::new(label)
            .size(14.5)
            .color(palette.accent)
            .strong()
    } else {
        egui::RichText::new(label).size(14.5).color(palette.muted)
    };
    let fill = if selected {
        palette.accent.gamma_multiply(0.20)
    } else {
        egui::Color32::TRANSPARENT
    };
    let resp = ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::selectable(selected, text).fill(fill),
    );
    if resp.clicked() {
        *current = page;
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let app_icon =
            cc.egui_ctx
                .load_texture("app_icon", app_icon_image(), egui::TextureOptions::LINEAR);
        let dark = cc.egui_ctx.theme().eq(&egui::Theme::Dark);
        apply_theme(&cc.egui_ctx, dark);
        let (tx, rx) = channel();
        let mut app = Self {
            tx,
            rx,
            log: Vec::new(),
            readers: Vec::new(),
            token_containers: Vec::new(),
            container_dir: String::new(),
            dump_dir: std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join("TokenTools").display().to_string())
                .unwrap_or_else(|| "TokenTools".into()),
            page: Page::Devices,
            busy: false,
            dark,
            applied_dark: dark,
            app_icon,
            picker: None,
            status: "Готово".to_string(),
            container_info: None,
            info_for: String::new(),
            next_poll: 0.0,
            polling: false,
            pin: default_pin(),
            pin_failed: false,
            certs_query: String::new(),
            certs: Vec::new(),
            certs_loaded: false,
            certs_loading: false,
        };
        app.log(Level::Info, "TokenTools запущен".to_string());
        let tx = app.tx.clone();
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || {
            for check in certfix::check_dependencies() {
                let level = match check.state {
                    certfix::DependencyState::Ready => Level::Ok,
                    certfix::DependencyState::Notice => Level::Info,
                    certfix::DependencyState::Missing => Level::Err,
                };
                let _ = tx.send(Msg::Log(
                    level,
                    format!(
                        "Зависимость {}: {} (используется: {})",
                        check.name, check.detail, check.used_by
                    ),
                ));
            }
            ctx.request_repaint();
        });
        app.detect(true);
        app
    }

    fn palette(&self) -> Palette {
        palette(self.dark)
    }

    fn log(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let dir = PathBuf::from(home).join(".cache").join("tokentools");
            let _ = std::fs::create_dir_all(&dir);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("session.log"))
            {
                use std::io::Write;
                let mark = match level {
                    Level::Info => "--",
                    Level::Ok => "OK",
                    Level::Err => "!!",
                };
                let _ = writeln!(f, "{mark} {text}");
            }
        }
        self.log.push((level, text));
        if self.log.len() > 2000 {
            self.log.drain(0..self.log.len() - 2000);
        }
    }

    fn spawn<F>(&mut self, f: F)
    where
        F: FnOnce(&Sender<Msg>) + Send + 'static,
    {
        if self.busy {
            return;
        }
        self.busy = true;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || f(&tx2)));
            if result.is_err() {
                let _ = tx.send(Msg::Log(Level::Err, "Внутренняя ошибка операции".into()));
            }
            let _ = tx.send(Msg::Done);
        });
    }

    fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Log(l, s) => self.log(l, s),
                Msg::Status(s) => self.status = s,
                Msg::Readers(r) => self.readers = r,
                Msg::Containers(found) => self.token_containers = found,
                Msg::PinFailed => self.pin_failed = true,
                Msg::Certs(result) => {
                    self.certs_loading = false;
                    self.certs_loaded = true;
                    match result {
                        Ok(list) => self.certs = list,
                        Err(error) => {
                            self.certs.clear();
                            self.log(Level::Err, format!("certmgr: {error}"));
                        }
                    }
                }
                Msg::PollDone => self.polling = false,
                Msg::Done => {
                    self.busy = false;
                    self.status = "Готово".to_string();
                }
            }
        }
    }

    fn detect(&mut self, announce: bool) {
        self.readers.clear();
        self.token_containers.clear();
        self.status = "Поиск устройств…".to_string();
        let pin = self.pin.clone();
        self.spawn(move |tx| detect_task(tx, announce, pin, false));
    }

    fn poll_devices(&mut self, ctx: &egui::Context) {
        if self.busy || self.polling {
            return;
        }
        self.polling = true;
        let pin = self.pin.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            detect_task(&tx, false, pin, true);
            let _ = tx.send(Msg::PollDone);
            ctx.request_repaint();
        });
    }

    fn dump(&mut self, items: Vec<TokenContainer>) {
        let dest = PathBuf::from(self.dump_dir.clone());
        if items.is_empty() {
            return;
        }
        self.status = "Сохранение контейнеров…".to_string();
        self.spawn(move |tx| {
            if let Err(e) = std::fs::create_dir_all(&dest) {
                let _ = tx.send(Msg::Log(Level::Err, format!("{}: {e}", dest.display())));
                return;
            }
            for c in &items {
                let out = dest.join(c.folder());
                let partial = dest.join(format!(
                    ".{}.partial-{}-{}",
                    c.folder(),
                    std::process::id(),
                    certfix::now_nanos()
                ));
                if let Err(e) = std::fs::create_dir(&partial) {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{}: {e}", partial.display())));
                    continue;
                }
                let mut ok = true;
                for (name, data) in &c.files {
                    let path = partial.join(name);
                    if let Err(e) = std::fs::write(&path, data) {
                        let _ = tx.send(Msg::Log(Level::Err, format!("  {}: {e}", path.display())));
                        ok = false;
                    }
                }
                if !ok {
                    let _ = std::fs::remove_dir_all(&partial);
                    continue;
                }
                if out.exists() {
                    let _ = std::fs::remove_dir_all(&partial);
                    let _ = tx.send(Msg::Log(
                        Level::Err,
                        format!("{} уже существует; перезапись запрещена", out.display()),
                    ));
                    continue;
                }
                if let Err(e) = std::fs::rename(&partial, &out) {
                    let _ = std::fs::remove_dir_all(&partial);
                    let _ = tx.send(Msg::Log(Level::Err, format!("{}: {e}", out.display())));
                    continue;
                }
                for (name, data) in &c.files {
                    let _ = tx.send(Msg::Log(
                        Level::Info,
                        format!("  {}: {} байт", out.join(name).display(), data.len()),
                    ));
                }
                let _ = tx.send(Msg::Log(
                    Level::Ok,
                    format!("{} — сохранено в {}", c.name, out.display()),
                ));
            }
        });
    }

    fn with_container_dir<F>(&mut self, f: F)
    where
        F: FnOnce(&Sender<Msg>, PathBuf) + Send + 'static,
    {
        let dir = self.container_dir.trim().to_string();
        if dir.is_empty() {
            self.log(Level::Err, "Укажите папку контейнера");
            return;
        }
        let path = match PathBuf::from(dir).canonicalize() {
            Ok(path) => path,
            Err(_) => {
                self.log(Level::Err, "Папка контейнера не найдена");
                return;
            }
        };
        if !cryptopro_container::is_container_dir(&path) {
            self.log(Level::Err, "Неполный контейнер: нужны все 6 файлов");
            return;
        }
        self.spawn(move |tx| f(tx, path));
    }

    fn verify(&mut self) {
        self.status = "Проверка контейнера…".to_string();
        self.with_container_dir(|tx, dir| {
            let _ = tx.send(Msg::Log(
                Level::Info,
                format!("Проверка: {}", dir.display()),
            ));
            match certfix::verify_container(&dir) {
                Ok(out) => {
                    for line in out.lines().filter(|l| !l.trim().is_empty()) {
                        let _ = tx.send(Msg::Log(Level::Info, format!("  {}", line.trim_end())));
                    }
                    let ok = out.contains("Check container passed");
                    let _ = tx.send(Msg::Log(
                        if ok { Level::Ok } else { Level::Err },
                        if ok {
                            "Контейнер в порядке".to_string()
                        } else {
                            "Проверка не пройдена".to_string()
                        },
                    ));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
                }
            }
        });
    }

    fn fix(&mut self) {
        self.status = "Обработка контейнера…".to_string();
        self.with_container_dir(|tx, dir| {
            let certs = match cryptopro_container::read_container(&dir) {
                Ok((_, c)) => c,
                Err(e) => {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
                    return;
                }
            };
            if certs.owner.is_empty() {
                let _ = tx.send(Msg::Log(Level::Err, "В контейнере нет сертификата".into()));
                return;
            }
            let cert = dir.join("cert_exchange.cer");
            if let Err(e) = std::fs::write(&cert, &certs.owner) {
                let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
                return;
            }
            let _ = tx.send(Msg::Log(
                Level::Info,
                format!(
                    "Сертификат владельца: {} ({} байт)",
                    cert.display(),
                    certs.owner.len()
                ),
            ));
            match certfix::fix_container(&dir, &cert) {
                Ok(out) => {
                    for line in out.lines().filter(|l| {
                        let t = l.trim();
                        !t.is_empty()
                            && !t.starts_with("fixme")
                            && !t.starts_with("err:")
                            && !t.starts_with("wine:")
                            && !t.starts_with("00")
                    }) {
                        let _ = tx.send(Msg::Log(Level::Info, format!("  {}", line.trim())));
                    }
                    let _ = tx.send(Msg::Log(
                        Level::Ok,
                        "Ключ помечен экспортируемым".to_string(),
                    ));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
                }
            }
        });
    }

    fn extract_certs(&mut self) {
        self.certs_flow(false);
    }

    fn install_certs(&mut self) {
        self.certs_flow(true);
    }

    fn certs_flow(&mut self, install: bool) {
        self.status = if install {
            "Установка сертификатов…"
        } else {
            "Извлечение сертификатов…"
        }
        .to_string();
        self.with_container_dir(move |tx, dir| {
            let (name, certs) = match cryptopro_container::read_container(&dir) {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{e}")));
                    return;
                }
            };
            if certs.owner.is_empty() {
                let _ = tx.send(Msg::Log(Level::Err, "В контейнере нет сертификата".into()));
                return;
            }
            let owner = dir.join("cert_exchange.cer");
            if let Err(e) = std::fs::write(&owner, &certs.owner) {
                let _ = tx.send(Msg::Log(Level::Err, format!("{}: {e}", owner.display())));
                return;
            }
            let _ = tx.send(Msg::Log(
                Level::Ok,
                format!(
                    "Сертификат сохранён: {} ({} байт)",
                    owner.display(),
                    certs.owner.len()
                ),
            ));
            let mut chain = Vec::new();
            for (i, c) in certs.chain.iter().enumerate() {
                let f = dir.join(format!("ca_chain_{i}.cer"));
                if let Err(e) = std::fs::write(&f, c) {
                    let _ = tx.send(Msg::Log(Level::Err, format!("{}: {e}", f.display())));
                    return;
                }
                let _ = tx.send(Msg::Log(
                    Level::Info,
                    format!("  УЦ: {} ({} байт)", f.display(), c.len()),
                ));
                chain.push(f);
            }
            if !install {
                return;
            }
            let cname = name.unwrap_or_else(|| "unknown".into());
            let (out, mut all_ok) = match certfix::certmgr_install(&owner, Some(&cname), "uMy") {
                Ok(result) => result,
                Err(e) => {
                    let _ = tx.send(Msg::Log(Level::Err, format!("Установка сертификата: {e}")));
                    return;
                }
            };
            for line in out.lines().filter(|l| !l.trim().is_empty()) {
                let _ = tx.send(Msg::Log(Level::Info, format!("  {}", line.trim_end())));
            }
            let _ = tx.send(Msg::Log(
                if all_ok { Level::Ok } else { Level::Err },
                if all_ok {
                    "Сертификат установлен".to_string()
                } else {
                    "Не удалось установить сертификат".to_string()
                },
            ));
            for (i, f) in chain.iter().enumerate() {
                let store = if i == 0 { "uRoot" } else { "uCA" };
                match certfix::certmgr_install(f, None, store) {
                    Ok((out, ok)) => {
                        all_ok &= ok;
                        for line in out.lines().filter(|l| !l.trim().is_empty()) {
                            let _ = tx.send(Msg::Log(
                                Level::Info,
                                format!("  {}: {}", store, line.trim_end()),
                            ));
                        }
                        let _ = tx.send(Msg::Log(
                            if ok { Level::Ok } else { Level::Err },
                            format!("УЦ #{i} -> {store}: {}", if ok { "OK" } else { "ошибка" }),
                        ));
                    }
                    Err(e) => {
                        all_ok = false;
                        let _ = tx.send(Msg::Log(Level::Err, format!("УЦ #{i} -> {store}: {e}")));
                    }
                }
            }
            if !all_ok {
                let _ = tx.send(Msg::Log(
                    Level::Err,
                    "Не все сертификаты установлены".into(),
                ));
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if self.applied_dark != self.dark {
            apply_theme(ui.ctx(), self.dark);
            self.applied_dark = self.dark;
        }
        let palette = self.palette();
        let now = ui.ctx().input(|i| i.time);
        if !self.busy
            && !self.polling
            && !self.pin_failed
            && self.readers.is_empty()
            && now > self.next_poll
        {
            self.next_poll = now + 2.5;
            let ctx = ui.ctx().clone();
            self.poll_devices(&ctx);
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(
                    self.app_icon.id(),
                    egui::vec2(24.0, 24.0),
                )));
                ui.add_space(6.0);
                ui.label(egui::RichText::new("TokenTools").size(17.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(if self.dark {
                            "Светлая"
                        } else {
                            "Тёмная"
                        })
                        .clicked()
                    {
                        self.dark = !self.dark;
                    }
                    ui.add_space(6.0);
                    if self.busy {
                        ui.spinner();
                    }
                });
            });
            ui.add_space(6.0);
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(&self.status)
                        .size(12.5)
                        .color(palette.muted),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .size(12.5)
                            .color(palette.muted),
                    );
                });
            });
            ui.add_space(2.0);
        });

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(196.0)
            .show(ui, |ui| {
                ui.add_space(10.0);
                nav_item(ui, &palette, &mut self.page, Page::Devices, "Устройства");
                nav_item(ui, &palette, &mut self.page, Page::Container, "Контейнер");
                nav_item(ui, &palette, &mut self.page, Page::Certs, "Сертификаты");
                nav_item(ui, &palette, &mut self.page, Page::Log, "Журнал");
            });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(10.0);
            match self.page {
                Page::Devices => self.render_devices(ui),
                Page::Container => self.render_container(ui),
                Page::Certs => self.render_certs(ui),
                Page::Log => self.render_log(ui),
            }
        });

        self.render_picker(ui);

        if self.busy {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}

impl App {
    fn render_devices(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        ui.add_enabled_ui(!self.busy, |ui| {
            card(ui, &palette, |ui| {
                section_title(ui, &palette, "Устройство");
                ui.horizontal(|ui| {
                    if ui.button("Обновить").clicked() {
                        self.pin_failed = false;
                        self.detect(true);
                    }
                    ui.label(
                        egui::RichText::new("поиск выполняется автоматически")
                            .size(12.5)
                            .color(palette.muted),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("PIN пользователя").color(palette.muted));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin)
                            .password(true)
                            .desired_width(140.0),
                    );
                    ui.label(
                        egui::RichText::new("по умолчанию 12345678")
                            .size(12.5)
                            .color(palette.muted),
                    );
                });
                ui.add_space(4.0);
                if self.readers.is_empty() {
                    ui.label(
                        egui::RichText::new(
                            "Токен не найден. Подключите его — контейнеры появятся сами.",
                        )
                        .color(palette.muted),
                    );
                } else {
                    for r in &self.readers {
                        ui.label(egui::RichText::new(format!("• {r}")).color(palette.text));
                    }
                }
            });

            ui.add_space(10.0);

            card(ui, &palette, |ui| {
                section_title(ui, &palette, "Контейнеры на токене");
                if self.token_containers.is_empty() {
                    ui.label(egui::RichText::new("Пока ничего не найдено").color(palette.muted));
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!("найдено: {}", self.token_containers.len()))
                            .color(palette.muted),
                    );
                    if ui.button("Выгрузить все").clicked() {
                        let items = self.token_containers.clone();
                        self.dump(items);
                    }
                });
                ui.add_space(4.0);
                let mut dump_one: Option<TokenContainer> = None;
                egui::Grid::new("containers")
                    .striped(true)
                    .min_col_width(90.0)
                    .spacing([14.0, 6.0])
                    .show(ui, |ui| {
                        for h in ["Папка", "Имя контейнера", "Размер", ""] {
                            ui.label(egui::RichText::new(h).color(palette.muted).size(12.5));
                        }
                        ui.end_row();
                        for c in &self.token_containers {
                            ui.label(c.folder());
                            ui.label(&c.name);
                            ui.label(format!("{} КБ", c.size() / 1024));
                            if ui.button("Выгрузить").clicked() {
                                dump_one = Some(c.clone());
                            }
                            ui.end_row();
                        }
                    });
                if let Some(c) = dump_one {
                    self.dump(vec![c]);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Сохранять в").color(palette.muted));
                    ui.add(egui::TextEdit::singleline(&mut self.dump_dir).desired_width(340.0));
                    if ui.button("Выбрать…").clicked() {
                        self.picker = Some(Picker::new(PickFor::Dump, &self.dump_dir));
                    }
                });
            });
        });
    }

    fn render_container(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        ui.add_enabled_ui(!self.busy, |ui| {
            card(ui, &palette, |ui| {
                section_title(ui, &palette, "Папка контейнера");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.container_dir).desired_width(360.0),
                    );
                    if ui.button("Выбрать…").clicked() {
                        let start = if self.container_dir.is_empty() {
                            std::env::var_os("HOME")
                                .or_else(|| std::env::var_os("USERPROFILE"))
                                .map(|home| PathBuf::from(home).display().to_string())
                                .unwrap_or_else(|| "/".into())
                        } else {
                            self.container_dir.clone()
                        };
                        self.picker = Some(Picker::new(PickFor::Container, &start));
                    }
                });
                if self.info_for != self.container_dir {
                    self.info_for = self.container_dir.clone();
                    self.container_info = container_info(&self.container_dir);
                }
                ui.add_space(6.0);
                match &self.container_info {
                    Some(info) => {
                        if let Some(name) = &info.name {
                            ui.label(
                                egui::RichText::new(format!("Имя: {name}"))
                                    .size(13.0)
                                    .color(palette.text),
                            );
                        }
                        if !info.files.is_empty() {
                            let files = info
                                .files
                                .iter()
                                .map(|(name, size)| format!("{name} {}", human_size(*size)))
                                .collect::<Vec<_>>()
                                .join("   ·   ");
                            ui.label(
                                egui::RichText::new(format!("Файлы: {files}"))
                                    .size(12.0)
                                    .color(palette.muted),
                            );
                        }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Проверить").clicked() {
                                self.verify();
                            }
                            if primary_button(ui, &palette, "Сделать экспортируемым").clicked()
                            {
                                self.fix();
                            }
                            if ui.button("Извлечь сертификаты").clicked() {
                                self.extract_certs();
                            }
                            if ui.button("Установить сертификаты").clicked() {
                                self.install_certs();
                            }
                        });
                    }
                    None => {
                        let text = if self.container_dir.trim().is_empty() {
                            "Укажите папку с файлами контейнера"
                        } else if !std::path::Path::new(&self.container_dir).is_dir() {
                            "Папка не найдена"
                        } else {
                            "В папке нет шестифайлового контейнера"
                        };
                        ui.label(egui::RichText::new(text).size(12.5).color(palette.muted));
                    }
                }
            });
            if let Some(info) = &self.container_info {
                ui.add_space(10.0);
                card(ui, &palette, |ui| {
                    section_title(ui, &palette, "Сертификаты");
                    ui.add_space(4.0);
                    cert_block(ui, &palette, "Владелец", &info.owner, true);
                    for (i, cert) in info.chain.iter().enumerate() {
                        ui.add_space(6.0);
                        cert_block(ui, &palette, &format!("УЦ #{i}"), cert, false);
                    }
                });
            }
        });
    }

    fn render_certs(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        ui.add_enabled_ui(!self.busy, |ui| {
            card(ui, &palette, |ui| {
                ui.horizontal(|ui| {
                    section_title(ui, &palette, "Личные сертификаты (uMy)");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Обновить").clicked() {
                            self.certs_loaded = false;
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Поиск:").color(palette.muted));
                    ui.add(egui::TextEdit::singleline(&mut self.certs_query).desired_width(300.0));
                    if !self.certs_query.is_empty() && ui.button("Сбросить").clicked() {
                        self.certs_query.clear();
                    }
                });
                if !self.certs_loaded && !self.certs_loading {
                    self.certs_loading = true;
                    self.status = "Читаю uMy…".to_string();
                    self.spawn(move |tx| {
                        let result =
                            certfix::certmgr_list("uMy").map_err(|error| error.to_string());
                        let _ = tx.send(Msg::Certs(result));
                    });
                }
                ui.add_space(8.0);
                if self.certs_loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new("Читаю хранилище…").color(palette.muted));
                    });
                } else {
                    let query = self.certs_query.trim().to_lowercase();
                    let filtered: Vec<(usize, &certfix::StoreCert)> = self
                        .certs
                        .iter()
                        .enumerate()
                        .filter(|(_, cert)| {
                            query.is_empty()
                                || cert.subject.to_lowercase().contains(&query)
                                || cert.issuer.to_lowercase().contains(&query)
                                || cert.serial.to_lowercase().contains(&query)
                                || cert.sha1.to_lowercase().contains(&query)
                        })
                        .collect();
                    let counter = if query.is_empty() {
                        format!("сертификатов: {}", self.certs.len())
                    } else {
                        format!("показано {} из {}", filtered.len(), self.certs.len())
                    };
                    ui.label(egui::RichText::new(counter).size(12.0).color(palette.muted));
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for (index, cert) in filtered {
                                cert_row(ui, &palette, index, cert);
                            }
                        });
                }
            });
        });
    }

    fn render_log(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        card(ui, &palette, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, &palette, "Журнал");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Очистить").clicked() {
                        self.log.clear();
                    }
                });
            });
            ui.label(
                egui::RichText::new("полный журнал: ~/.cache/tokentools/session.log")
                    .size(12.0)
                    .color(palette.muted),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (level, line) in &self.log {
                        let color = match level {
                            Level::Info => palette.text,
                            Level::Ok => palette.ok,
                            Level::Err => palette.err,
                        };
                        ui.label(egui::RichText::new(line).color(color).size(13.0));
                    }
                });
        });
    }

    fn render_picker(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        if let Some(picker) = &mut self.picker {
            let mut close = false;
            let mut chosen: Option<PathBuf> = None;
            egui::Window::new("Выбор папки")
                .collapsible(false)
                .resizable(true)
                .default_size([560.0, 420.0])
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("↑").clicked() {
                            picker.go_to_parent();
                        }
                        ui.label(
                            egui::RichText::new(picker.path.display().to_string())
                                .color(palette.muted)
                                .size(12.5),
                        );
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(260.0)
                        .show(ui, |ui| {
                            for d in picker.dirs.clone() {
                                if ui
                                    .add_sized(
                                        [ui.available_width(), 26.0],
                                        egui::Button::new(format!("  {d}"))
                                            .fill(egui::Color32::TRANSPARENT),
                                    )
                                    .clicked()
                                {
                                    picker.enter(&d);
                                }
                            }
                        });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if primary_button(ui, &palette, "Выбрать эту папку").clicked()
                        {
                            chosen = Some(picker.path.clone());
                            close = true;
                        }
                        if ui.button("Отмена").clicked() {
                            close = true;
                        }
                    });
                });
            if let Some(path) = chosen {
                match self.picker.as_ref().map(|p| p.for_what) {
                    Some(PickFor::Container) => self.container_dir = path.display().to_string(),
                    Some(PickFor::Dump) => self.dump_dir = path.display().to_string(),
                    None => {}
                }
            }
            if close {
                self.picker = None;
            }
        }
    }
}

const APP_ICON_SIZE: usize = 128;
const APP_ICON_RGBA: &[u8] = include_bytes!("../../../assets/app-icon-128.rgba");
const _: () = assert!(APP_ICON_RGBA.len() == APP_ICON_SIZE * APP_ICON_SIZE * 4);

fn app_icon_image() -> egui::ColorImage {
    egui::ColorImage::from_rgba_unmultiplied([APP_ICON_SIZE, APP_ICON_SIZE], APP_ICON_RGBA)
}

fn load_icon() -> egui::IconData {
    egui::IconData {
        rgba: APP_ICON_RGBA.to_vec(),
        width: APP_ICON_SIZE as u32,
        height: APP_ICON_SIZE as u32,
    }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let text = format!("{info}");
        eprintln!("panic: {text}");
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let dir = PathBuf::from(home).join(".cache").join("tokentools");
            let _ = std::fs::create_dir_all(&dir);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("crash.log"))
            {
                use std::io::Write;
                let _ = writeln!(f, "{text}");
            }
        }
        default_hook(info);
    }));
}

fn main() -> eframe::Result<()> {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }
    install_panic_hook();
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1020.0, 720.0])
            .with_min_inner_size([780.0, 560.0])
            .with_title("TokenTools")
            .with_app_id("tokentools")
            .with_icon(Arc::new(load_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "TokenTools",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
