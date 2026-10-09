use anyhow::{Result, anyhow, bail};
use pcsc_transport::Card;

pub const PIN_REF_USER: u8 = 0x02;
pub const CONTAINER_ROLES: u8 = 6;
pub const CONTAINER_ROOTS: [&[u16]; 3] = [&[0x1000, 0x1003], &[0x1000, 0x1004], &[]];
pub const CONTAINER_FOLDER_FIRST: u16 = 0x0A00;
pub const CONTAINER_FOLDER_LAST: u16 = 0x1800;
pub const CONTAINER_FOLDER_STEP: u16 = 0x100;
const READ_CHUNK: usize = 220;

const SW_OK: u16 = 0x9000;
const SW_NOT_FOUND: u16 = 0x6A82;
const SW_SECURITY: u16 = 0x6982;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    Authenticated,
    TriesLeft(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutcome {
    pub already_authenticated: bool,
}

fn verify_apdu(pin_ref: u8, pin: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x20, 0x00, pin_ref, pin.len() as u8];
    apdu.extend_from_slice(pin);
    apdu
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn trace_apdu_text(apdu: &[u8]) -> String {
    if apdu.len() < 5 {
        return hex(apdu);
    }
    let header = hex(&apdu[..4]);
    if apdu.len() == 5 {
        return format!("{header} Le={:02X}", apdu[4]);
    }
    let lc = apdu[4] as usize;
    let mut text = if apdu[1] == 0x20 {
        format!("{header} Lc={lc:02X} data=<redacted:{lc}B>")
    } else {
        format!(
            "{header} Lc={lc:02X} data={}",
            apdu.get(5..5 + lc).map(hex).unwrap_or_default()
        )
    };
    if apdu.len() > 5 + lc {
        text.push_str(&format!(" Le={:02X}", apdu[5 + lc]));
    }
    text
}

fn trace_response(data_len: usize, sw: u16) -> String {
    format!("<- data={data_len}B SW={sw:04x}")
}

fn pin_state_from_sw(sw: u16) -> Option<PinState> {
    match sw {
        0x9000 => Some(PinState::Authenticated),
        0x63C0..=0x63CF => Some(PinState::TriesLeft((sw & 0x0F) as u8)),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub root: Vec<u16>,
    pub folder: u16,
}

impl Container {
    pub fn path(&self) -> Vec<u16> {
        let mut path = self.root.clone();
        path.push(self.folder);
        path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub fid: u16,
    pub size: usize,
    pub is_df: bool,
}

impl FileEntry {
    pub fn role_in(&self, folder: u16) -> Option<u8> {
        let role = self.fid.checked_sub(folder)?;
        (1..=u16::from(CONTAINER_ROLES))
            .contains(&role)
            .then_some(role as u8)
    }
}

fn parse_tlv(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let tag = data[i];
        let mut ln = data[i + 1] as usize;
        i += 2;
        if ln == 0x81 && i < data.len() {
            ln = data[i] as usize;
            i += 1;
        } else if ln == 0x82 && i + 1 < data.len() {
            ln = ((data[i] as usize) << 8) | data[i + 1] as usize;
            i += 2;
        }
        if i + ln > data.len() {
            break;
        }
        out.push((tag, data[i..i + ln].to_vec()));
        i += ln;
    }
    out
}

fn parse_fcp(resp: &[u8]) -> Option<FileEntry> {
    if resp.len() < 2 || (resp[0] != 0x62 && resp[0] != 0x6F) {
        return None;
    }
    let end = (2 + resp[1] as usize).min(resp.len());
    let mut entry = FileEntry {
        fid: 0,
        size: 0,
        is_df: false,
    };
    for (tag, value) in parse_tlv(&resp[2..end]) {
        match tag {
            0x83 if value.len() == 2 => {
                entry.fid = ((value[0] as u16) << 8) | value[1] as u16;
            }
            0x80 if value.len() == 2 => {
                entry.size = ((value[0] as usize) << 8) | value[1] as usize;
            }
            0x82 if !value.is_empty() => entry.is_df = value[0] == 0x38,
            _ => {}
        }
    }
    Some(entry)
}

pub struct RutokenFs<'a> {
    card: &'a Card,
    log: Option<&'a dyn Fn(&str)>,
}

impl<'a> RutokenFs<'a> {
    pub fn new(card: &'a Card, log: Option<&'a dyn Fn(&str)>) -> Self {
        Self { card, log }
    }

    fn log(&self, msg: impl FnOnce() -> String) {
        if let Some(log) = self.log {
            log(&msg());
        }
    }

    fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        self.log(|| format!("-> {}", trace_apdu_text(apdu)));
        let (data, sw) = self.card.transmit(apdu)?;
        self.log(|| trace_response(data.len(), sw));
        Ok((data, sw))
    }

    fn select_raw(&self, p1: u8, p2: u8, data: &[u8], le: u8) -> Result<(Vec<u8>, u16)> {
        let mut apdu = vec![0x00, 0xA4, p1, p2];
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        apdu.push(le);
        self.transmit(&apdu)
    }

    pub fn select_by_id(&self, fid: u16) -> Result<Option<FileEntry>> {
        let (resp, sw) = self.select_raw(0x00, 0x00, &fid.to_be_bytes(), 0x00)?;
        Self::entry_or_not_found(&resp, sw)
    }

    pub fn select_path(&self, path: &[u16]) -> Result<Option<FileEntry>> {
        let mut data = Vec::with_capacity(path.len() * 2);
        for fid in path {
            data.extend_from_slice(&fid.to_be_bytes());
        }
        let (resp, sw) = self.select_raw(0x09, 0x04, &data, 0x00)?;
        Self::entry_or_not_found(&resp, sw)
    }

    pub fn select_mf(&self) -> Result<Option<FileEntry>> {
        self.select_by_id(0x3F00)
    }

    fn select_parent(&self) -> Result<u16> {
        let (_, sw) = self.transmit(&[0x00, 0xA4, 0x03, 0x00])?;
        Ok(sw)
    }

    fn enum_first(&self) -> Result<Option<FileEntry>> {
        let (resp, sw) = self.transmit(&[0x00, 0xA4, 0x00, 0x04, 0x00])?;
        Self::entry_or_not_found(&resp, sw)
    }

    fn enum_next(&self, fid: u16) -> Result<Option<FileEntry>> {
        let mut data = vec![0x02];
        data.extend_from_slice(&fid.to_be_bytes());
        let (resp, sw) = self.select_raw(0x00, 0x06, &data, 0x00)?;
        Self::entry_or_not_found(&resp, sw)
    }

    fn entry_or_not_found(resp: &[u8], sw: u16) -> Result<Option<FileEntry>> {
        if sw == SW_NOT_FOUND {
            return Ok(None);
        }
        if sw == SW_SECURITY {
            bail!("доступ запрещён (SW={sw:04x}): нужен PIN пользователя");
        }
        if sw != SW_OK {
            bail!("SELECT: SW={sw:04x}");
        }
        parse_fcp(resp)
            .map(Some)
            .ok_or_else(|| anyhow!("не разобран FCP ({} байт)", resp.len()))
    }

    fn read_binary(&self, size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let want = (size - out.len()).min(READ_CHUNK);
            let le = if want == 256 { 0x00 } else { want as u8 };
            let p1 = ((out.len() >> 8) & 0x7F) as u8;
            let p2 = (out.len() & 0xFF) as u8;
            let (resp, sw) = self.transmit(&[0x00, 0xB0, p1, p2, le])?;
            if sw != SW_OK {
                bail!("READ BINARY @{}: SW={sw:04x}", out.len());
            }
            if resp.is_empty() || resp.len() > want {
                bail!(
                    "READ BINARY @{}: получено {} байт, ожидалось не больше {want}",
                    out.len(),
                    resp.len()
                );
            }
            out.extend_from_slice(&resp);
        }
        Ok(out)
    }

    pub fn read_file(&self, fid: u16) -> Result<Vec<u8>> {
        let entry = self
            .select_by_id(fid)?
            .ok_or_else(|| anyhow!("файл {fid:04X} не найден"))?;
        if entry.size == 0 {
            bail!("файл {fid:04X}: нулевой размер в FCP");
        }
        self.read_binary(entry.size)
    }

    pub fn containers(&self) -> Result<Vec<Container>> {
        for root in CONTAINER_ROOTS {
            self.select_mf()?
                .ok_or_else(|| anyhow!("MF (3F00) не выбран"))?;
            if !root.is_empty() && self.select_path(root)?.is_none() {
                self.log(|| {
                    let shown = root
                        .iter()
                        .map(|f| format!("{f:04X}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    format!("корень {shown} не найден")
                });
                continue;
            }
            let found = self.folders_in_root(root)?;
            if !found.is_empty() {
                return Ok(found);
            }
        }
        Ok(Vec::new())
    }

    fn folders_in_root(&self, root: &[u16]) -> Result<Vec<Container>> {
        let mut out = Vec::new();
        let mut folder = CONTAINER_FOLDER_FIRST;
        while folder <= CONTAINER_FOLDER_LAST {
            if self.select_by_id(folder)?.is_some_and(|entry| entry.is_df) {
                self.log(|| format!("папка контейнера {folder:04X}"));
                out.push(Container {
                    root: root.to_vec(),
                    folder,
                });
                if !root.is_empty() {
                    self.select_mf()?;
                    self.select_path(root)?;
                }
            }
            folder += CONTAINER_FOLDER_STEP;
        }
        Ok(out)
    }

    pub fn read_container(&self, container: &Container) -> Result<Vec<(u8, Vec<u8>)>> {
        self.select_mf()?
            .ok_or_else(|| anyhow!("MF (3F00) не выбран"))?;
        let path = container.path();
        if self.select_path(&path)?.is_none() {
            let shown = path
                .iter()
                .map(|f| format!("{f:04X}"))
                .collect::<Vec<_>>()
                .join(":");
            bail!("папка контейнера {shown} не выбрана");
        }
        let mut files = Vec::with_capacity(usize::from(CONTAINER_ROLES));
        for role in 1..=CONTAINER_ROLES {
            let fid = container.folder + u16::from(role);
            let Some(entry) = self.select_by_id(fid)? else {
                bail!("в контейнере нет файла роли {role} (FID {fid:04X})");
            };
            if entry.size == 0 {
                bail!("файл роли {role} (FID {fid:04X}): нулевой размер");
            }
            let data = self.read_binary(entry.size)?;
            self.log(|| format!("роль {role} (FID {fid:04X}): {} байт", data.len()));
            files.push((role, data));
            self.select_mf()?;
            self.select_path(&path)?;
        }
        Ok(files)
    }

    pub fn walk(&self, max_depth: usize) -> Result<Vec<(Vec<u16>, Vec<FileEntry>)>> {
        self.select_mf()?
            .ok_or_else(|| anyhow!("MF (3F00) не выбран"))?;
        let mut found = Vec::new();
        self.walk_into(&[], &mut found, max_depth)?;
        Ok(found)
    }

    fn walk_into(
        &self,
        path: &[u16],
        found: &mut Vec<(Vec<u16>, Vec<FileEntry>)>,
        max_depth: usize,
    ) -> Result<()> {
        if path.len() > max_depth {
            return Ok(());
        }
        let entries = self.enum_current()?;
        let (dirs, files): (Vec<FileEntry>, Vec<FileEntry>) =
            entries.into_iter().partition(|e| e.is_df);
        self.log(|| {
            format!(
                "/{}/ — {} файл(ов), {} пап(ок)",
                label(path),
                files.len(),
                dirs.len()
            )
        });
        if !files.is_empty() {
            found.push((path.to_vec(), files));
        }
        for dir in dirs {
            let mut child = path.to_vec();
            child.push(dir.fid);
            match self.select_path(&child)? {
                Some(_) => self.walk_into(&child, found, max_depth)?,
                None => self.log(|| format!("не удалось войти в папку {:04X}", dir.fid)),
            }
            if !path.is_empty() {
                self.select_mf()?;
                self.select_path(path)?;
            }
        }
        Ok(())
    }

    fn enum_current(&self) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        let Some(first) = self.enum_first()? else {
            return Ok(entries);
        };
        let mut cursor = first.fid;
        entries.push(first);
        loop {
            self.select_parent()?;
            let Some(next) = self.enum_next(cursor)? else {
                break;
            };
            cursor = next.fid;
            entries.push(next);
        }
        Ok(entries)
    }

    pub fn pin_state(&self, pin_ref: u8) -> Result<PinState> {
        let (_, sw) = self.transmit(&[0x00, 0x20, 0x00, pin_ref])?;
        pin_state_from_sw(sw).ok_or_else(|| anyhow!("VERIFY: неожиданный SW={sw:04x}"))
    }

    fn verify_pin(&self, pin_ref: u8, pin: &[u8]) -> Result<u16> {
        if pin.is_empty() || pin.len() > 255 {
            bail!("некорректная длина PIN ({} байт)", pin.len());
        }
        let (_, sw) = self.transmit(&verify_apdu(pin_ref, pin))?;
        Ok(sw)
    }

    pub fn authenticate_user_pin(&self, pin: &str) -> Result<AuthOutcome> {
        match self.pin_state(PIN_REF_USER)? {
            PinState::Authenticated => Ok(AuthOutcome {
                already_authenticated: true,
            }),
            PinState::TriesLeft(0) => bail!(
                "PIN пользователя заблокирован: попыток не осталось \
                 (разблокировка — через панель управления токеном или админ-PIN)"
            ),
            PinState::TriesLeft(tries) => match self.verify_pin(PIN_REF_USER, pin.as_bytes())? {
                0x9000 => Ok(AuthOutcome {
                    already_authenticated: false,
                }),
                0x6983 => bail!("PIN пользователя заблокирован (SW=6983)"),
                sw if (0x63C0..=0x63CF).contains(&sw) => {
                    bail!("неверный PIN: осталось попыток {}", sw & 0x0F)
                }
                sw => bail!(
                    "VERIFY: неожиданный SW={sw:04x} (перед вводом оставалось попыток: {tries})"
                ),
            },
        }
    }
}

fn label(path: &[u16]) -> String {
    if path.is_empty() {
        return "MF".to_string();
    }
    path.iter()
        .map(|fid| format!("{fid:04X}"))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rutoken_fcp_uses_big_endian_fid() {
        let entry = parse_fcp(&[
            0x62, 0x0c, 0x83, 0x02, 0x0A, 0x06, 0x80, 0x02, 0x01, 0x2C, 0x82, 0x02, 0x10, 0x00,
        ])
        .expect("valid FCP");
        assert_eq!(entry.fid, 0x0A06);
        assert_eq!(entry.size, 300);
        assert!(!entry.is_df);
    }

    #[test]
    fn parse_fcp_marks_df() {
        let entry = parse_fcp(&[
            0x62, 0x0b, 0x83, 0x02, 0x0A, 0x00, 0x80, 0x02, 0x00, 0x60, 0x82, 0x01, 0x38,
        ])
        .expect("valid FCP");
        assert_eq!(entry.fid, 0x0A00);
        assert_eq!(entry.size, 96);
        assert!(entry.is_df);
    }

    #[test]
    fn parse_tlv_supports_long_lengths() {
        assert_eq!(
            parse_tlv(&[0x01, 0x02, 0xaa, 0xbb, 0x02, 0x82, 0x00, 0x01, 0xcc]),
            vec![(0x01, vec![0xaa, 0xbb]), (0x02, vec![0xcc])]
        );
    }

    #[test]
    fn verify_apdu_builds_case3() {
        assert_eq!(
            verify_apdu(PIN_REF_USER, b"12345678"),
            vec![
                0x00, 0x20, 0x00, 0x02, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8'
            ]
        );
    }

    #[test]
    fn trace_redacts_only_pin() {
        let verify = verify_apdu(PIN_REF_USER, b"12345678");
        assert_eq!(
            trace_apdu_text(&verify),
            "00 20 00 02 Lc=08 data=<redacted:8B>"
        );
        assert_eq!(
            trace_apdu_text(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x0A, 0x06, 0x00]),
            "00 A4 00 00 Lc=02 data=0A 06 Le=00"
        );
        assert_eq!(
            trace_apdu_text(&[0x00, 0xB0, 0x00, 0x00, 0xDC]),
            "00 B0 00 00 Le=DC"
        );
        assert_eq!(trace_response(24, 0x9000), "<- data=24B SW=9000");
    }

    #[test]
    fn pin_state_parses_sw() {
        assert_eq!(pin_state_from_sw(0x9000), Some(PinState::Authenticated));
        assert_eq!(pin_state_from_sw(0x63C3), Some(PinState::TriesLeft(3)));
        assert_eq!(pin_state_from_sw(0x63C0), Some(PinState::TriesLeft(0)));
        assert_eq!(pin_state_from_sw(0x6A82), None);
    }

    #[test]
    fn container_path_includes_folder() {
        let container = Container {
            root: vec![0x1000, 0x1003],
            folder: 0x0A00,
        };
        assert_eq!(container.path(), vec![0x1000, 0x1003, 0x0A00]);
    }

    #[test]
    fn file_entry_role_is_offset_from_folder() {
        let file = |fid| FileEntry {
            fid,
            size: 60,
            is_df: false,
        };
        assert_eq!(file(0x0A01).role_in(0x0A00), Some(1));
        assert_eq!(file(0x0A06).role_in(0x0A00), Some(6));
        assert_eq!(file(0x0A07).role_in(0x0A00), None);
        assert_eq!(file(0x0A00).role_in(0x0A00), None);
        assert_eq!(file(0x0B01).role_in(0x0A00), None);
    }
}
