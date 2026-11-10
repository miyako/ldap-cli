//! Escaping helpers for LDAP filters (RFC 4515) and distinguished names (RFC 4514).

use crate::error::{Error, Result};

/// Escape an assertion value for use inside a search filter (RFC 4515 §3).
/// `*` `(` `)` `\` and NUL become `\2a` `\28` `\29` `\5c` `\00`.
pub fn filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape an attribute value for use inside a DN (RFC 4514 §2.4).
pub fn dn_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let last = chars.len().saturating_sub(1);
    let mut out = String::with_capacity(value.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            '#' if i == 0 => out.push_str("\\#"),
            _ => out.push(c),
        }
    }
    out
}

/// Reverse RFC 4514 escaping of a single attribute value (`\XX` hex pairs and `\<special>`).
pub fn dn_unescape(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let next = bytes
                .get(i + 1)
                .ok_or_else(|| Error::usage("DN value ends with a lone '\\'"))?;
            if next.is_ascii_hexdigit() {
                let hi = hex(*next);
                let lo = bytes
                    .get(i + 2)
                    .filter(|b| b.is_ascii_hexdigit())
                    .map(|b| hex(*b))
                    .ok_or_else(|| Error::usage("DN value has an incomplete \\XX hex escape"))?;
                out.push(hi << 4 | lo);
                i += 3;
            } else {
                out.push(*next);
                i += 2;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::usage("unescaped DN value is not valid UTF-8"))
}

fn hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// One attribute-type-and-value of an RDN, with the value unescaped.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Ava {
    #[serde(rename = "type")]
    pub attr: String,
    pub value: String,
}

/// Parse a DN string into RDNs (each a list of AVAs for multi-valued RDNs).
pub fn parse_dn(dn: &str) -> Result<Vec<Vec<Ava>>> {
    let mut rdns = Vec::new();
    if dn.trim().is_empty() {
        return Ok(rdns);
    }
    let mut rdn = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    let mut in_quotes = false;
    let push_ava = |raw: &str, rdn: &mut Vec<Ava>| -> Result<()> {
        let (t, v) = raw
            .split_once('=')
            .ok_or_else(|| Error::usage(format!("RDN component '{raw}' has no '='")))?;
        let t = t.trim();
        if t.is_empty()
            || !t
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::usage(format!("invalid attribute type '{t}' in DN")));
        }
        let v = v.trim_start();
        let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            v[1..v.len() - 1].replace("\\\"", "\"")
        } else {
            // Trailing unescaped spaces are insignificant; escaped ones ("\ ") are kept.
            let mut s = v.to_string();
            while s.ends_with(' ') && !s.ends_with("\\ ") {
                s.pop();
            }
            dn_unescape(&s)?
        };
        rdn.push(Ava {
            attr: t.to_string(),
            value: v,
        });
        Ok(())
    };
    for c in dn.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                cur.push(c);
                in_quotes = !in_quotes;
            }
            '+' if !in_quotes => {
                push_ava(&cur, &mut rdn)?;
                cur.clear();
            }
            ',' | ';' if !in_quotes => {
                push_ava(&cur, &mut rdn)?;
                cur.clear();
                rdns.push(std::mem::take(&mut rdn));
            }
            _ => cur.push(c),
        }
    }
    if escaped || in_quotes {
        return Err(Error::usage("DN ends inside an escape or quoted value"));
    }
    push_ava(&cur, &mut rdn)?;
    rdns.push(rdn);
    Ok(rdns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_escaping_rfc4515() {
        assert_eq!(filter_value("a*b(c)d\\e\0f"), "a\\2ab\\28c\\29d\\5ce\\00f");
        assert_eq!(filter_value("Lučić"), "Lučić");
        assert_eq!(
            filter_value("*)(uid=*))(|(uid=*"),
            "\\2a\\29\\28uid=\\2a\\29\\29\\28|\\28uid=\\2a"
        );
    }

    #[test]
    fn dn_escaping_rfc4514() {
        assert_eq!(dn_value("Smith, John"), "Smith\\, John");
        assert_eq!(dn_value("#hash"), "\\#hash");
        assert_eq!(dn_value(" lead and trail "), "\\ lead and trail\\ ");
        assert_eq!(dn_value("a+b;c<d>e\"f\\g"), "a\\+b\\;c\\<d\\>e\\\"f\\\\g");
        assert_eq!(dn_value("nul\0"), "nul\\00");
        assert_eq!(dn_value("mid#dle = ok"), "mid#dle = ok");
        assert_eq!(dn_value(" "), "\\ ");
    }

    #[test]
    fn dn_round_trip() {
        for v in ["Smith, John", "#x", " a ", "a+b", "x\\y", "ü,é", "\"q\""] {
            assert_eq!(dn_unescape(&dn_value(v)).unwrap(), v);
        }
        assert_eq!(dn_unescape("\\4C\\C3\\BC").unwrap(), "Lü");
        assert!(dn_unescape("bad\\").is_err());
        assert!(dn_unescape("bad\\4").is_err());
    }

    #[test]
    fn parse_dn_components() {
        let p = parse_dn("CN=Smith\\, John+uid=js,OU=Users , DC=corp,DC=example").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[0][0].value, "Smith, John");
        assert_eq!(
            p[0][1],
            Ava {
                attr: "uid".into(),
                value: "js".into()
            }
        );
        assert_eq!(p[1][0].value, "Users");
        assert_eq!(parse_dn("cn=\"a,b\",dc=x").unwrap()[0][0].value, "a,b");
        assert!(parse_dn("nonsense").is_err());
        assert!(parse_dn("").unwrap().is_empty());
    }
}
