use anyhow::{Result, bail};

use crate::parse_tlv_sequence;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

pub fn parse_cert(der: &[u8]) -> Result<CertInfo> {
    let outer = parse_tlv_sequence(der);
    let Some((outer_tag, certificate_body)) = outer.first() else {
        bail!("не похоже на X.509-сертификат");
    };
    if *outer_tag != 0x30 {
        bail!("не похоже на X.509-сертификат");
    }
    let certificate = parse_tlv_sequence(certificate_body);
    if certificate.len() < 3 || certificate[0].0 != 0x30 {
        bail!("не разобрана структура Certificate");
    }
    let tbs = parse_tlv_sequence(&certificate[0].1);
    let offset = usize::from(tbs.first().is_some_and(|(tag, _)| *tag == 0xA0));
    let (serial, issuer, validity, subject) = match (
        tbs.get(offset),
        tbs.get(offset + 2),
        tbs.get(offset + 3),
        tbs.get(offset + 4),
    ) {
        (Some(serial), Some(issuer), Some(validity), Some(subject))
            if serial.0 == 0x02 && issuer.0 == 0x30 && validity.0 == 0x30 && subject.0 == 0x30 =>
        {
            (serial, issuer, validity, subject)
        }
        _ => bail!("не разобрана структура tbsCertificate"),
    };
    let times = parse_tlv_sequence(&validity.1);
    let not_before = times
        .first()
        .and_then(|(tag, value)| format_time(*tag, value));
    let not_after = times
        .get(1)
        .and_then(|(tag, value)| format_time(*tag, value));
    Ok(CertInfo {
        subject_cn: name_cn(&subject.1),
        issuer_cn: name_cn(&issuer.1),
        serial_hex: hex_upper(&serial.1),
        not_before,
        not_after,
        sha1: sha1(der),
        sha256: sha256(der),
    })
}

pub fn to_pem(der: &[u8]) -> String {
    let encoded = base64(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn name_cn(name: &[u8]) -> Option<String> {
    for (tag, rdn) in parse_tlv_sequence(name) {
        if tag != 0x31 {
            continue;
        }
        for (atv_tag, atv) in parse_tlv_sequence(&rdn) {
            if atv_tag != 0x30 {
                continue;
            }
            let parts = parse_tlv_sequence(&atv);
            let (oid, value) = match (parts.first(), parts.get(1)) {
                (Some(oid), Some(value)) if oid.0 == 0x06 => (oid, value),
                _ => continue,
            };
            if oid.1 == [0x55, 0x04, 0x03] {
                return Some(String::from_utf8_lossy(&value.1).into_owned());
            }
        }
    }
    None
}

fn format_time(tag: u8, value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?.trim();
    let digits = text.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if digits.len() == 12 => {
            let year: u32 = digits.get(..2)?.parse().ok()?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            (year, digits.get(2..)?)
        }
        0x18 if digits.len() == 14 => (digits.get(..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    if rest.len() != 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let month = rest.get(0..2)?;
    let day = rest.get(2..4)?;
    let hour = rest.get(4..6)?;
    let minute = rest.get(6..8)?;
    let second = rest.get(8..10)?;
    Some(format!(
        "{year:04}-{month}-{day} {hour}:{minute}:{second} UTC"
    ))
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    for chunk in padded(data).chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *state = state.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    for chunk in padded(data).chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for (i, word) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(*word);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *state = state.wrapping_add(value);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn padded(data: &[u8]) -> Vec<u8> {
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_lower as hex;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn parses_minimal_certificate() {
        let name = |cn: &str| {
            let oid = tlv(0x06, &[0x55, 0x04, 0x03]);
            let value = tlv(0x0C, cn.as_bytes());
            let mut atv = oid;
            atv.extend_from_slice(&value);
            let atv = tlv(0x30, &atv);
            let rdn = tlv(0x31, &atv);
            tlv(0x30, &rdn)
        };
        let serial = tlv(0x02, &[0x01, 0x02, 0x03]);
        let sigalg = tlv(0x30, &[]);
        let issuer = name("Issuer CN");
        let mut validity_body = tlv(0x17, b"260101000000Z");
        validity_body.extend_from_slice(&tlv(0x17, b"270101000000Z"));
        let validity = tlv(0x30, &validity_body);
        let subject = name("Subject CN");
        let spki = tlv(0x30, &[]);
        let mut tbs_body = serial;
        tbs_body.extend_from_slice(&sigalg);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(&spki);
        let tbs = tlv(0x30, &tbs_body);
        let signature = tlv(0x03, &[0x00, 0x01]);
        let mut cert_body = tbs;
        cert_body.extend_from_slice(&sigalg);
        cert_body.extend_from_slice(&signature);
        let cert = tlv(0x30, &cert_body);

        let info = parse_cert(&cert).expect("сертификат разобран");
        assert_eq!(info.subject_cn.as_deref(), Some("Subject CN"));
        assert_eq!(info.issuer_cn.as_deref(), Some("Issuer CN"));
        assert_eq!(info.serial_hex, "010203");
        assert_eq!(info.not_before.as_deref(), Some("2026-01-01 00:00:00 UTC"));
        assert_eq!(info.not_after.as_deref(), Some("2027-01-01 00:00:00 UTC"));
        assert_eq!(info.sha1, sha1(&cert));
        assert_eq!(info.sha256, sha256(&cert));
    }

    #[test]
    fn pem_wraps_base64() {
        let pem = to_pem(&[0x30, 0x00]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert!(pem.contains("MAA="));
    }
}
