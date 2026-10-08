use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Devices,
    Container,
    Log,
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Info,
    Ok,
    Err,
}

#[derive(Clone)]
struct Found {
    path: Vec<u16>,
    name: String,
    files: Vec<(String, Vec<u8>)>,
}

impl Found {
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

    fn up(&mut self) {
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
    Found(Vec<Found>),
    PinFailed,
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
    let pal = palette(dark);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.style_mut_of(theme, |style| {
            let v = &mut style.visuals;
            v.dark_mode = dark;
            v.panel_fill = pal.bg;
            v.window_fill = pal.card;
            v.extreme_bg_color = pal.card;
            v.faint_bg_color = pal.card;
            v.override_text_color = Some(pal.text);
            v.window_stroke = egui::Stroke::new(1.0, pal.stroke);
            v.window_corner_radius = egui::CornerRadius::same(10);
            v.selection.bg_fill = pal.accent;
            v.selection.stroke = egui::Stroke::new(1.0, pal.text);
            v.hyperlink_color = pal.accent;
            let w = &mut v.widgets;
            for s in [
                &mut w.noninteractive,
                &mut w.inactive,
                &mut w.hovered,
                &mut w.active,
                &mut w.open,
            ] {
                s.corner_radius = egui::CornerRadius::same(6);
                s.bg_stroke = egui::Stroke::new(1.0, pal.stroke);
            }
            w.noninteractive.bg_fill = pal.card;
            w.noninteractive.weak_bg_fill = pal.card;
            w.noninteractive.fg_stroke = egui::Stroke::new(1.0, pal.text);
            w.inactive.bg_fill = pal.card;
            w.inactive.weak_bg_fill = pal.card;
            w.inactive.fg_stroke = egui::Stroke::new(1.0, pal.text);
            w.hovered.bg_fill = pal.stroke;
            w.hovered.weak_bg_fill = pal.stroke;
            w.hovered.fg_stroke = egui::Stroke::new(1.0, pal.text);
            w.active.bg_fill = pal.accent;
            w.active.weak_bg_fill = pal.accent;
            w.active.fg_stroke = egui::Stroke::new(1.0, pal.text);
            w.open.bg_fill = pal.card;
            w.open.weak_bg_fill = pal.card;
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
    found: Vec<Found>,
    container_dir: String,
    dump_dir: String,
    page: Page,
    busy: bool,
    dark: bool,
    applied_dark: bool,
    app_icon: egui::TextureHandle,
    picker: Option<Picker>,
    status: String,
    container_info: Option<String>,
    info_for: String,
    next_poll: f64,
    pin: String,
    pin_failed: bool,
}

fn default_pin() -> String {
    std::env::var("TOKENTOOLS_PIN")
        .ok()
        .filter(|pin| !pin.is_empty())
        .unwrap_or_else(|| "12345678".to_string())
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn container_summary(dir: &str) -> Option<String> {
    if dir.trim().is_empty() {
        return None;
    }
    let (name, certs) = cryptopro_container::read_container(&PathBuf::from(dir)).ok()?;
    let mut parts = Vec::new();
    if let Some(n) = name {
        parts.push(format!("Имя: {n}"));
    }
    if !certs.owner.is_empty() {
        parts.push(format!(
            "Сертификат: {:.1} КБ",
            certs.owner.len() as f32 / 1024.0
        ));
    }
    if !certs.chain.is_empty() {
        parts.push(format!("УЦ в цепочке: {}", certs.chain.len()));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("    ·    "))
    }
}

fn detect_task(tx: &Sender<Msg>, announce: bool, pin: String) {
    let _ = tx.send(Msg::Readers(Vec::new()));
    let _ = tx.send(Msg::Found(Vec::new()));
    let _ = tx.send(Msg::Status("Поиск устройств…".into()));
    let pcsc = match rt_pcsc::Pcsc::load() {
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
        if announce {
            let _ = tx.send(Msg::Log(Level::Info, "Устройства не найдены".into()));
        }
        return;
    }
    let mut found = Vec::new();
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
        let fs = rt_fs::RutokenFs::new(&card, false);
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
            for (fname, entry) in rt_fs::CONTAINER_FILES.iter().zip(entries.iter()) {
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
            found.push(Found { path, name, files });
        }
    }
    let _ = tx.send(Msg::Found(found));
}

fn card<R>(ui: &mut egui::Ui, pal: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(pal.card)
        .stroke(egui::Stroke::new(1.0, pal.stroke))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width() - 2.0);
            add(ui)
        })
        .inner
}

fn section_title(ui: &mut egui::Ui, pal: &Palette, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(15.0)
            .color(pal.text)
            .strong(),
    );
    ui.add_space(2.0);
}

fn primary_button(ui: &mut egui::Ui, pal: &Palette, text: &str) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(text)
            .color(egui::Color32::WHITE)
            .strong(),
    )
    .fill(pal.accent);
    ui.add(btn)
}

fn nav_item(ui: &mut egui::Ui, pal: &Palette, current: &mut Page, page: Page, label: &str) {
    let selected = *current == page;
    let text = if selected {
        egui::RichText::new(label)
            .size(14.5)
            .color(pal.accent)
            .strong()
    } else {
        egui::RichText::new(label).size(14.5).color(pal.muted)
    };
    let fill = if selected {
        pal.accent.gamma_multiply(0.20)
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
            found: Vec::new(),
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
            pin: default_pin(),
            pin_failed: false,
        };
        app.log(Level::Info, "TokenTools запущен".to_string());
        for check in certfix_core::check_dependencies() {
            let level = match check.state {
                certfix_core::DependencyState::Ready => Level::Ok,
                certfix_core::DependencyState::Notice => Level::Info,
                certfix_core::DependencyState::Missing => Level::Err,
            };
            app.log(
                level,
                format!(
                    "Зависимость {}: {} (используется: {})",
                    check.name, check.detail, check.used_by
                ),
            );
        }
        app.detect(true);
        app
    }

    fn pal(&self) -> Palette {
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
                Msg::Found(f) => self.found = f,
                Msg::PinFailed => self.pin_failed = true,
                Msg::Done => {
                    self.busy = false;
                    self.status = "Готово".to_string();
                }
            }
        }
    }

    fn detect(&mut self, announce: bool) {
        self.readers.clear();
        self.found.clear();
        self.status = "Поиск устройств…".to_string();
        let pin = self.pin.clone();
        self.spawn(move |tx| detect_task(tx, announce, pin));
    }

    fn dump(&mut self, items: Vec<Found>) {
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
                    now_nanos()
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

    fn with_dir<F>(&mut self, f: F)
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
        self.with_dir(|tx, dir| {
            let _ = tx.send(Msg::Log(
                Level::Info,
                format!("Проверка: {}", dir.display()),
            ));
            match certfix_core::verify_container(&dir) {
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
        self.with_dir(|tx, dir| {
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
            match certfix_core::fix_container(&dir, &cert) {
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

    fn certs(&mut self, install: bool) {
        self.status = if install {
            "Установка сертификатов…"
        } else {
            "Извлечение сертификатов…"
        }
        .to_string();
        self.with_dir(move |tx, dir| {
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
            let (out, mut all_ok) = match certfix_core::certmgr_install(&owner, Some(&cname), "uMy")
            {
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
                match certfix_core::certmgr_install(f, None, store) {
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
        let pal = self.pal();
        let now = ui.ctx().input(|i| i.time);
        if !self.busy && !self.pin_failed && self.readers.is_empty() && now > self.next_poll {
            self.next_poll = now + 2.5;
            self.detect(false);
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
                        .color(pal.muted),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .size(12.5)
                            .color(pal.muted),
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
                nav_item(ui, &pal, &mut self.page, Page::Devices, "Устройства");
                nav_item(ui, &pal, &mut self.page, Page::Container, "Контейнер");
                nav_item(ui, &pal, &mut self.page, Page::Log, "Журнал");
            });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(10.0);
            match self.page {
                Page::Devices => {
                    ui.add_enabled_ui(!self.busy, |ui| {
                        card(ui, &pal, |ui| {
                            section_title(ui, &pal, "Устройство");
                            ui.horizontal(|ui| {
                                if ui.button("Обновить").clicked() {
                                    self.pin_failed = false;
                                    self.detect(true);
                                }
                                ui.label(
                                    egui::RichText::new("поиск выполняется автоматически")
                                        .size(12.5)
                                        .color(pal.muted),
                                );
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("PIN пользователя").color(pal.muted));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.pin)
                                        .password(true)
                                        .desired_width(140.0),
                                );
                                ui.label(
                                    egui::RichText::new("по умолчанию 12345678")
                                        .size(12.5)
                                        .color(pal.muted),
                                );
                            });
                            ui.add_space(4.0);
                            if self.readers.is_empty() {
                                ui.label(
                                    egui::RichText::new(
                                        "Токен не найден. Подключите его — контейнеры появятся сами.",
                                    )
                                    .color(pal.muted),
                                );
                            } else {
                                for r in &self.readers {
                                    ui.label(egui::RichText::new(format!("• {r}")).color(pal.text));
                                }
                            }
                        });

                        ui.add_space(10.0);

                        card(ui, &pal, |ui| {
                            section_title(ui, &pal, "Контейнеры на токене");
                            if self.found.is_empty() {
                                ui.label(
                                    egui::RichText::new("Пока ничего не найдено").color(pal.muted),
                                );
                                return;
                            }
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("найдено: {}", self.found.len()))
                                        .color(pal.muted),
                                );
                                if ui.button("Выгрузить все").clicked() {
                                    let items = self.found.clone();
                                    self.dump(items);
                                }
                            });
                            ui.add_space(4.0);
                            let mut dump_one: Option<Found> = None;
                            egui::Grid::new("found")
                                .striped(true)
                                .min_col_width(90.0)
                                .spacing([14.0, 6.0])
                                .show(ui, |ui| {
                                    for h in ["Папка", "Имя контейнера", "Размер", ""] {
                                        ui.label(egui::RichText::new(h).color(pal.muted).size(12.5));
                                    }
                                    ui.end_row();
                                    for c in &self.found {
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
                                ui.label(egui::RichText::new("Сохранять в").color(pal.muted));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.dump_dir)
                                        .desired_width(340.0),
                                );
                                if ui.button("Выбрать…").clicked() {
                                    self.picker = Some(Picker::new(PickFor::Dump, &self.dump_dir));
                                }
                            });
                        });
                    });
                }
                Page::Container => {
                    ui.add_enabled_ui(!self.busy, |ui| {
                        card(ui, &pal, |ui| {
                            section_title(ui, &pal, "Папка контейнера");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.container_dir)
                                        .desired_width(360.0),
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
                                self.container_info = container_summary(&self.container_dir);
                            }
                            ui.add_space(4.0);
                            match &self.container_info {
                                Some(info) => {
                                    ui.label(egui::RichText::new(info).size(12.5).color(pal.muted));
                                }
                                None => {
                                    ui.label(
                                        egui::RichText::new("Укажите папку с файлами контейнера")
                                            .size(12.5)
                                            .color(pal.muted),
                                    );
                                }
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui.button("Проверить").clicked() {
                                    self.verify();
                                }
                                if primary_button(ui, &pal, "Сделать экспортируемым").clicked() {
                                    self.fix();
                                }
                                if ui.button("Извлечь сертификаты").clicked() {
                                    self.certs(false);
                                }
                                if ui.button("Установить сертификаты").clicked() {
                                    self.certs(true);
                                }
                            });
                        });
                    });
                }
                Page::Log => {
                    card(ui, &pal, |ui| {
                        ui.horizontal(|ui| {
                            section_title(ui, &pal, "Журнал");
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Очистить").clicked() {
                                    self.log.clear();
                                }
                            });
                        });
                        ui.label(
                            egui::RichText::new("полный журнал: ~/.cache/tokentools/session.log")
                                .size(12.0)
                                .color(pal.muted),
                        );
                        ui.add_space(4.0);
                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for (level, line) in &self.log {
                                    let color = match level {
                                        Level::Info => pal.text,
                                        Level::Ok => pal.ok,
                                        Level::Err => pal.err,
                                    };
                                    ui.label(egui::RichText::new(line).color(color).size(13.0));
                                }
                            });
                    });
                }
            }
        });

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
                            picker.up();
                        }
                        ui.label(
                            egui::RichText::new(picker.path.display().to_string())
                                .color(pal.muted)
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
                        if primary_button(ui, &pal, "Выбрать эту папку").clicked() {
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

        if self.busy {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
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
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    install_panic_hook();
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1020.0, 720.0])
            .with_min_inner_size([780.0, 560.0])
            .with_title("TokenTools")
            .with_icon(Arc::new(load_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "TokenTools",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
