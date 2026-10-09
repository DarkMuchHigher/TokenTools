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
pub fn cp1251_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0xC0..=0xD6 => char::from_u32(0x0410 + (b as u32 - 0xC0)).unwrap_or('?'),
            0xD8..=0xDF => char::from_u32(0x0428 + (b as u32 - 0xD8)).unwrap_or('?'),
            0xE0..=0xF6 => char::from_u32(0x0430 + (b as u32 - 0xE0)).unwrap_or('?'),
            0xF8..=0xFF => char::from_u32(0x0448 + (b as u32 - 0xF8)).unwrap_or('?'),
            0xA8 => 'Ё',
            0xB8 => 'ё',
            0xA1 => 'Ў',
            0xA2 => 'ў',
            0xA3 => 'Ј',
            0xA5 => 'Ґ',
            0xA6 => '¦',
            0xA9 => '©',
            0xAA => 'Є',
            0xAB => '«',
            0xAC => '¬',
            0xAD => '\u{00AD}',
            0xAE => '®',
            0xAF => 'Ї',
            0xB0 => '°',
            0xB1 => '±',
            0xB2 => 'І',
            0xB3 => 'і',
            0xB4 => 'ґ',
            0xB5 => 'µ',
            0xB6 => '¶',
            0xB7 => '·',
            0xB9 => '№',
            0xBA => 'є',
            0xBB => '»',
            0xBC => 'ј',
            0xBD => 'Ѕ',
            0xBE => 'ѕ',
            0xBF => 'ї',
            0xD7 => '×',
            0xF7 => '÷',
            0x20..=0x7E => b as char,
            b'\t' | b'\n' | b'\r' => b as char,
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
    fn cp1251_maps_special_bytes() {
        assert_eq!(cp1251_to_string(&[0xC0, 0xD7, 0xF7, 0xF8]), "А×÷ш");
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
