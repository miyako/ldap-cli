//! Active Directory value helpers: SID / GUID / FILETIME decoding and unicodePwd encoding.

/// Attributes whose values are binary in AD and other common schemas.
pub fn is_binary_attr(name: &str) -> bool {
    let n = name.split(';').next().unwrap_or(name).to_ascii_lowercase();
    name.to_ascii_lowercase().contains(";binary")
        || matches!(
            n.as_str(),
            "objectguid"
                | "objectsid"
                | "sidhistory"
                | "tokengroups"
                | "tokengroupsglobalanduniversal"
                | "tokengroupsnogcacceptable"
                | "msexchmailboxguid"
                | "msds-generationid"
                | "ntsecuritydescriptor"
                | "usercertificate"
                | "cacertificate"
                | "certificaterevocationlist"
                | "authorityrevocationlist"
                | "crosscertificatepair"
                | "jpegphoto"
                | "thumbnailphoto"
                | "photo"
                | "audio"
                | "usersmimecertificate"
                | "userpkcs12"
                | "logonhours"
                | "msds-mailboxguid"
                | "schemaidguid"
                | "attributesecurityguid"
                | "invocationid"
                | "objectguid;binary"
        )
}

fn is_sid_attr(n: &str) -> bool {
    matches!(
        n,
        "objectsid"
            | "sidhistory"
            | "tokengroups"
            | "tokengroupsglobalanduniversal"
            | "tokengroupsnogcacceptable"
    )
}

fn is_guid_attr(n: &str) -> bool {
    matches!(
        n,
        "objectguid"
            | "msexchmailboxguid"
            | "schemaidguid"
            | "attributesecurityguid"
            | "invocationid"
            | "msds-mailboxguid"
    )
}

fn is_filetime_attr(n: &str) -> bool {
    matches!(
        n,
        "pwdlastset"
            | "lastlogon"
            | "lastlogontimestamp"
            | "lastlogoff"
            | "badpasswordtime"
            | "accountexpires"
            | "lockouttime"
            | "msds-userpasswordexpirytimecomputed"
            | "msds-lastsuccessfulinteractivelogontime"
    )
}

/// Decode a value into a readable string for `--binary decode`, if the attribute is known.
pub fn decode(attr: &str, v: &[u8]) -> Option<String> {
    let n = attr.split(';').next().unwrap_or(attr).to_ascii_lowercase();
    if is_sid_attr(&n) {
        sid_to_string(v)
    } else if is_guid_attr(&n) {
        guid_to_string(v)
    } else if is_filetime_attr(&n) {
        filetime_to_string(std::str::from_utf8(v).ok()?)
    } else {
        None
    }
}

pub fn sid_to_string(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let rev = b[0];
    let count = b[1] as usize;
    if b.len() != 8 + 4 * count {
        return None;
    }
    let auth = b[2..8].iter().fold(0u64, |a, x| a << 8 | *x as u64);
    let mut s = format!("S-{rev}-{auth}");
    for i in 0..count {
        let o = 8 + 4 * i;
        s.push_str(&format!(
            "-{}",
            u32::from_le_bytes(b[o..o + 4].try_into().ok()?)
        ));
    }
    Some(s)
}

pub fn guid_to_string(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes(b[0..4].try_into().ok()?),
        u16::from_le_bytes(b[4..6].try_into().ok()?),
        u16::from_le_bytes(b[6..8].try_into().ok()?),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    ))
}

/// FILETIME (100-ns ticks since 1601-01-01 UTC) as ISO 8601, or "never".
pub fn filetime_to_string(s: &str) -> Option<String> {
    let t: i64 = s.trim().parse().ok()?;
    if t == 0 || t == i64::MAX {
        return Some("never".into());
    }
    let secs = t / 10_000_000 - 11_644_473_600;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// AD `unicodePwd` value: the password in double quotes, encoded as UTF-16LE.
pub fn unicode_pwd(password: &str) -> Vec<u8> {
    format!("\"{password}\"")
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid() {
        let b = [
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xf4, 1, 0, 0,
        ];
        assert_eq!(sid_to_string(&b).unwrap(), "S-1-5-21-1-2-3-500");
        assert!(sid_to_string(&b[..10]).is_none());
    }

    #[test]
    fn guid() {
        let b = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        assert_eq!(
            guid_to_string(&b).unwrap(),
            "12345678-1234-5678-9abc-def012345678"
        );
    }

    #[test]
    fn filetime() {
        assert_eq!(
            filetime_to_string("116444736000000000").unwrap(),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            filetime_to_string("133500000000000000").unwrap(),
            "2024-01-17T21:20:00Z"
        );
        assert_eq!(filetime_to_string("0").unwrap(), "never");
        assert_eq!(filetime_to_string("9223372036854775807").unwrap(), "never");
    }

    #[test]
    fn unicodepwd() {
        assert_eq!(unicode_pwd("a"), [b'"', 0, b'a', 0, b'"', 0]);
    }
}
