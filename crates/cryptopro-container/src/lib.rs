use anyhow::{Result, bail};
use std::path::Path;

mod x509;

pub use x509::{CertInfo, parse_cert, to_pem};

pub const CONTAINER_FILES: [&str; 6] = [
    "name.key",
    "header.key",
    "primary.key",
    "masks.key",
    "primary2.key",
    "masks2.key",
];
pub const CONTAINER_ROLES: [(u8, &str); 6] = [
    (1, "masks.key"),
    (2, "primary.key"),
    (3, "header.key"),
    (4, "masks2.key"),
    (5, "primary2.key"),
    (6, "name.key"),
];

pub fn file_name_by_role(role: u8) -> Option<&'static str> {
    CONTAINER_ROLES
        .iter()
        .find(|(value, _)| *value == role)
        .map(|(_, name)| *name)
}

pub fn container_dir_name(name: Option<&str>, folder: u16) -> String {
    let sanitized: String = name
        .unwrap_or_default()
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
    if sanitized.is_empty() {
        format!("{folder:04x}")
    } else {
        sanitized.to_string()
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
const CP1251_HIGH: [char; 64] = [
    'Ђ', 'Ѓ', '‚', 'ѓ', '„', '…', '†', '‡', '€', '‰', 'Љ', '‹', 'Њ', 'Ќ', 'Ћ', 'Џ', 'ђ', '‘', '’',
    '“', '”', '•', '–', '—', '?', '™', 'љ', '›', 'њ', 'ќ', 'ћ', 'џ', '\u{A0}', 'Ў', 'ў', 'Ј', '¤',
    'Ґ', '¦', '§', 'Ё', '©', 'Є', '«', '¬', '\u{AD}', '®', 'Ї', '°', '±', 'І', 'і', 'ґ', 'µ', '¶',
    '·', 'ё', '№', 'є', '»', 'ј', 'Ѕ', 'ѕ', 'ї',
];
pub fn cp1251_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0xC0..=0xFF => char::from_u32(0x0410 + u32::from(b - 0xC0)).unwrap_or('?'),
            0x80..=0xBF => CP1251_HIGH[usize::from(b - 0x80)],
            0x20..=0x7E | b'\t' | b'\n' | b'\r' => b as char,
            _ => '?',
        })
        .collect()
}
pub(crate) fn parse_tlv_sequence(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
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
fn tlv_content(data: &[u8]) -> &[u8] {
    if data.len() < 2 {
        return data;
    }
    let (start, len) = if data[1] & 0x80 == 0 {
        (2usize, data[1] as usize)
    } else {
        let n = (data[1] & 0x7F) as usize;
        if 2 + n > data.len() {
            return data;
        }
        let mut v = 0usize;
        for k in 0..n {
            v = (v << 8) | data[2 + k] as usize;
        }
        (2 + n, v)
    };
    let end = start
        .checked_add(len)
        .map_or(data.len(), |end| end.min(data.len()));
    if start > end {
        return &[];
    }
    &data[start..end]
}
pub fn parse_name_key(data: &[u8]) -> Option<String> {
    if data.len() > 4 && data[0] == 0x30 && data[2] == 0x16 {
        let len = data[3] as usize;
        if 4 + len <= data.len() {
            return Some(cp1251_to_string(&data[4..4 + len]));
        }
    }
    None
}
pub fn build_name_key(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30, (name.len() + 2) as u8, 0x16, name.len() as u8];
    out.extend_from_slice(name);
    out
}
#[derive(Debug, Default, Clone)]
pub struct ContainerCerts {
    pub owner: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}
fn header_certs(header: &[u8]) -> ContainerCerts {
    let mut out = ContainerCerts::default();
    let outer = if !header.is_empty() && header[0] == 0x30 {
        tlv_content(header).to_vec()
    } else {
        header.to_vec()
    };
    let inner = if !outer.is_empty() && outer[0] == 0x30 {
        tlv_content(&outer).to_vec()
    } else {
        outer
    };
    for (tag, content) in parse_tlv_sequence(&inner) {
        match tag {
            0x85 => out.owner = content,
            0xac => {
                for (ext_tag, ext) in parse_tlv_sequence(&content) {
                    if ext_tag != 0x30 {
                        continue;
                    }
                    let sub = parse_tlv_sequence(&ext);
                    if sub.len() == 2
                        && sub[0].1 == [0x2a, 0x85, 0x03, 0x02, 0x02, 0x25, 0x03, 0x01]
                    {
                        let mut blob = sub[1].1.clone();
                        if !blob.is_empty() && blob[0] == 0x31 {
                            blob = tlv_content(&blob).to_vec();
                        }
                        let mut j = 0usize;
                        while j + 4 <= blob.len() && blob[j] == 0x30 {
                            let ln = ((blob[j + 2] as usize) << 8) | blob[j + 3] as usize;
                            if j + 4 + ln > blob.len() {
                                break;
                            }
                            out.chain.push(blob[j..j + 4 + ln].to_vec());
                            j += 4 + ln;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}
pub fn is_container_dir(dir: &Path) -> bool {
    CONTAINER_FILES.iter().all(|f| dir.join(f).exists())
}
pub fn read_container(dir: &Path) -> Result<(Option<String>, ContainerCerts)> {
    if !dir.join("header.key").exists() {
        bail!(
            "{}: нет header.key — это не папка контейнера",
            dir.display()
        );
    }
    let name = std::fs::read(dir.join("name.key"))
        .ok()
        .and_then(|d| parse_name_key(&d));
    let header = std::fs::read(dir.join("header.key"))?;
    Ok((name, header_certs(&header)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_dir_name_prefers_container_name() {
        assert_eq!(
            container_dir_name(Some("d7c17f03-4cc5-41f1-a847-42f21306db7a"), 0x0A00),
            "d7c17f03-4cc5-41f1-a847-42f21306db7a"
        );
        assert_eq!(
            container_dir_name(Some("ООО \"Ромашка\"/тест"), 0x0A00),
            "ООО \"Ромашка\"_тест"
        );
        assert_eq!(container_dir_name(None, 0x0B00), "0b00");
        assert_eq!(container_dir_name(Some("   "), 0x0C00), "0c00");
    }

    #[test]
    fn roles_match_container_files() {
        let mut from_roles: Vec<&str> = CONTAINER_ROLES.iter().map(|(_, name)| *name).collect();
        let mut from_files = CONTAINER_FILES.to_vec();
        from_roles.sort_unstable();
        from_files.sort_unstable();
        assert_eq!(from_roles, from_files);
        assert_eq!(file_name_by_role(3), Some("header.key"));
        assert_eq!(file_name_by_role(6), Some("name.key"));
        assert_eq!(file_name_by_role(7), None);
    }

    #[test]
    fn cp1251_decodes_full_cyrillic_alphabet() {
        let upper: Vec<u8> = (0xC0..=0xDF).collect();
        let lower: Vec<u8> = (0xE0..=0xFF).collect();
        assert_eq!(cp1251_to_string(&upper), "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
        assert_eq!(cp1251_to_string(&lower), "абвгдежзийклмнопрстуфхцчшщъыьэюя");
    }

    #[test]
    fn cp1251_decodes_punctuation_and_specials() {
        assert_eq!(
            cp1251_to_string(&[0xA8, 0xB8, 0xB9, 0xAB, 0xBB, 0x96, 0x97, 0x88, 0x98, 0x41]),
            "Ёё№«»–—€?A"
        );
    }

    #[test]
    fn name_key_round_trip() {
        let data = build_name_key(&[0xC0, 0xE1, 0xB8]);
        assert_eq!(parse_name_key(&data).as_deref(), Some("Абё"));
    }

    #[test]
    fn tlv_content_survives_malformed_length() {
        assert_eq!(
            tlv_content(&[0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            &[][..]
        );
        assert_eq!(tlv_content(&[0x30, 0x82, 0xFF, 0xFF, 0x01]), &[0x01][..]);
    }

    #[test]
    fn parse_tlv_sequence_supports_long_lengths() {
        assert_eq!(
            parse_tlv_sequence(&[0x01, 0x02, 0xaa, 0xbb, 0x02, 0x81, 0x01, 0xcc]),
            vec![(0x01, vec![0xaa, 0xbb]), (0x02, vec![0xcc])]
        );
    }
}
