use anyhow::{anyhow, bail, Result};
use rt_pcsc::Card;
pub const CONTAINER_FILES: [&str; 6] = [
    "name.key",
    "header.key",
    "primary.key",
    "masks.key",
    "primary2.key",
    "masks2.key",
];
pub const PIN_REF_USER: u8 = 0x02;

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

fn pin_state_from_sw(sw: u16) -> Option<PinState> {
    match sw {
        0x9000 => Some(PinState::Authenticated),
        0x63C0..=0x63CF => Some(PinState::TriesLeft((sw & 0x0F) as u8)),
        _ => None,
    }
}
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub fid: u16,
    fid_raw: [u8; 2],
    pub size: usize,
    pub is_df: bool,
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
pub struct RutokenFs<'a> {
    card: &'a Card,
    verbose: bool,
}
impl<'a> RutokenFs<'a> {
    pub fn new(card: &'a Card, verbose: bool) -> Self {
        Self { card, verbose }
    }
    fn log(&self, msg: &str) {
        if self.verbose {
            println!("    [fs] {msg}");
        }
    }
    fn select_raw(&self, p1: u8, p2: u8, data: &[u8], le: u8) -> Result<(Vec<u8>, u16)> {
        let mut apdu = vec![0x00, 0xA4, p1, p2];
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        apdu.push(le);
        self.card.transmit(&apdu)
    }
    fn select_first(&self) -> Result<(Vec<u8>, u16)> {
        self.select_raw(0x00, 0x00, &[], 0)
    }
    fn select_next(&self, fid_raw: &[u8]) -> Result<(Vec<u8>, u16)> {
        self.select_raw(0x00, 0x02, fid_raw, 0)
    }
    fn select_parent(&self) -> Result<(Vec<u8>, u16)> {
        self.select_raw(0x03, 0x00, &[], 0)
    }
    fn select_id(&self, fid: u16) -> Result<(Vec<u8>, u16)> {
        self.select_raw(0x00, 0x00, &[fid as u8, (fid >> 8) as u8], 0)
    }
    pub fn select_mf(&self) -> Result<(Vec<u8>, u16)> {
        self.select_id(0x3F00)
    }
    fn read_binary(&self, mut offset: usize, mut length: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(length);
        while length > 0 {
            let n = length.min(256);
            let (resp, sw) =
                self.card
                    .transmit(&[0x00, 0xB0, (offset >> 8) as u8, offset as u8, n as u8])?;
            if sw != 0x9000 {
                bail!("READ BINARY @{offset}: SW={sw:04x}");
            }
            if resp.is_empty() {
                bail!("READ BINARY @{offset}: пустой ответ при ожидании {length} байт");
            }
            if resp.len() > length {
                bail!(
                    "READ BINARY @{offset}: получено {} байт, ожидалось не более {length}",
                    resp.len()
                );
            }
            out.extend_from_slice(&resp);
            offset += resp.len();
            length -= resp.len();
        }
        Ok(out)
    }
    pub fn read_file(&self, fid: u16, length: usize) -> Result<Vec<u8>> {
        let (_, sw) = self.select_id(fid)?;
        if sw != 0x9000 {
            bail!("не удалось выбрать файл {fid:04x}: SW={sw:04x}");
        }
        self.read_binary(0, length)
    }
    pub fn pin_state(&self, pin_ref: u8) -> Result<PinState> {
        let (_, sw) = self.card.transmit(&[0x00, 0x20, 0x00, pin_ref])?;
        pin_state_from_sw(sw).ok_or_else(|| anyhow!("VERIFY: неожиданный SW={sw:04x}"))
    }
    pub fn verify_pin(&self, pin_ref: u8, pin: &[u8]) -> Result<u16> {
        if pin.is_empty() || pin.len() > 255 {
            bail!("некорректная длина PIN ({} байт)", pin.len());
        }
        let (_, sw) = self.card.transmit(&verify_apdu(pin_ref, pin))?;
        Ok(sw)
    }
    pub fn authenticate_user_pin(&self, pin: &str) -> Result<AuthOutcome> {
        match self.pin_state(PIN_REF_USER)? {
            PinState::Authenticated => Ok(AuthOutcome {
                already_authenticated: true,
            }),
            PinState::TriesLeft(0) => bail!(
                "PIN пользователя заблокирован: попыток не осталось \
                 (разблокировка — через Панель управления Рутокен или админ-PIN)"
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
    fn parse_fcp(resp: &[u8]) -> Option<FileEntry> {
        if resp.len() < 2 || resp[0] != 0x62 {
            return None;
        }
        let end = (2 + resp[1] as usize).min(resp.len());
        let body = parse_tlv(&resp[2..end]);
        let mut entry = FileEntry {
            fid: 0,
            fid_raw: [0, 0],
            size: 0,
            is_df: false,
        };
        for (tag, value) in &body {
            match *tag {
                0x83 if value.len() == 2 => {
                    entry.fid_raw = [value[0], value[1]];
                    entry.fid = ((value[1] as u16) << 8) | value[0] as u16;
                }
                0x80 | 0x81 if value.len() == 2 && entry.size == 0 => {
                    entry.size = ((value[1] as usize) << 8) | value[0] as usize;
                }
                0x82 if !value.is_empty() => entry.is_df = value[0] == 0x38,
                _ => {}
            }
        }
        Some(entry)
    }
    fn enum_current(&self) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        let (mut resp, mut sw) = self.select_first()?;
        loop {
            if sw == 0x6A82 {
                break;
            }
            if sw != 0x9000 {
                self.log(&format!("enum: SW={sw:04x} — прекращаю перечисление"));
                break;
            }
            let Some(info) = Self::parse_fcp(&resp) else {
                self.log("enum: не разобран FCP");
                break;
            };
            let is_df = info.is_df;
            let fid_raw = info.fid_raw;
            entries.push(info);
            if is_df {
                let _ = self.select_parent()?;
            }
            let (r, s) = self.select_next(&fid_raw)?;
            resp = r;
            sw = s;
        }
        Ok(entries)
    }
    pub fn walk(&self, max_depth: usize) -> Result<Vec<(Vec<u16>, Vec<FileEntry>)>> {
        let mut found = Vec::new();
        self.walk_into(&mut Vec::new(), &mut found, max_depth)?;
        Ok(found)
    }
    fn walk_into(
        &self,
        path: &mut Vec<u16>,
        found: &mut Vec<(Vec<u16>, Vec<FileEntry>)>,
        max_depth: usize,
    ) -> Result<()> {
        if path.len() > max_depth {
            return Ok(());
        }
        let entries = self.enum_current()?;
        let files: Vec<FileEntry> = entries.iter().filter(|e| !e.is_df).cloned().collect();
        let dirs: Vec<FileEntry> = entries.iter().filter(|e| e.is_df).cloned().collect();
        let pname = path
            .iter()
            .map(|f| format!("{f:04x}"))
            .collect::<Vec<_>>()
            .join("/");
        self.log(&format!(
            "/{pname}/ — {} файл(ов), {} пап(ок)",
            files.len(),
            dirs.len()
        ));
        if !files.is_empty() {
            found.push((path.clone(), files));
        }
        for d in dirs {
            let (_, sw) = self.select_id(d.fid)?;
            if sw != 0x9000 {
                self.log(&format!(
                    "не удалось войти в папку {:04x} (SW={sw:04x})",
                    d.fid
                ));
                continue;
            }
            path.push(d.fid);
            self.walk_into(path, found, max_depth)?;
            path.pop();
            let _ = self.select_parent()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rutoken_fcp() {
        let entry = RutokenFs::parse_fcp(&[
            0x62, 0x0b, 0x83, 0x02, 0x34, 0x12, 0x80, 0x02, 0x46, 0x00, 0x82, 0x01, 0x38,
        ])
        .expect("valid FCP");
        assert_eq!(entry.fid, 0x1234);
        assert_eq!(entry.fid_raw, [0x34, 0x12]);
        assert_eq!(entry.size, 70);
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
            vec![0x00, 0x20, 0x00, 0x02, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8']
        );
    }

    #[test]
    fn pin_state_parses_sw() {
        assert_eq!(pin_state_from_sw(0x9000), Some(PinState::Authenticated));
        assert_eq!(pin_state_from_sw(0x63C3), Some(PinState::TriesLeft(3)));
        assert_eq!(pin_state_from_sw(0x63C0), Some(PinState::TriesLeft(0)));
        assert_eq!(pin_state_from_sw(0x6A82), None);
    }
}
