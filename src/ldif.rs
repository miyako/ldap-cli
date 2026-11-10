//! LDIF (RFC 2849) reading for add/modify input and writing for search output.

use crate::error::{Error, Result};
use crate::model::{Entry, ModOp, Modification};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

#[derive(Debug, Clone)]
pub enum Change {
    Add {
        dn: String,
        attrs: Vec<(String, Vec<Vec<u8>>)>,
    },
    Modify {
        dn: String,
        mods: Vec<Modification>,
    },
    Delete {
        dn: String,
    },
    ModRdn {
        dn: String,
        new_rdn: String,
        delete_old: bool,
        new_superior: Option<String>,
    },
}

impl Change {
    pub fn dn(&self) -> &str {
        match self {
            Change::Add { dn, .. }
            | Change::Modify { dn, .. }
            | Change::Delete { dn }
            | Change::ModRdn { dn, .. } => dn,
        }
    }
}

struct Line {
    no: usize,
    attr: String,
    value: Option<Vec<u8>>, // None for the "-" separator
}

/// Parse LDIF text. Content records (no changetype) become `Add` when `content_is_add`.
pub fn parse(text: &str, content_is_add: bool) -> Result<Vec<Change>> {
    let mut changes = Vec::new();
    for record in records(text)? {
        if let Some(c) = parse_record(record, content_is_add)? {
            changes.push(c);
        }
    }
    Ok(changes)
}

fn records(text: &str) -> Result<Vec<Vec<Line>>> {
    // Unfold continuation lines, drop comments, split on blank lines.
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut blank_before = true;
    for (i, raw) in text.lines().enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(cont) = raw.strip_prefix(' ') {
            match logical.last_mut() {
                Some((_, l)) if !blank_before => l.push_str(cont),
                _ => {
                    return Err(Error::usage(format!(
                        "LDIF line {}: continuation without a preceding line",
                        i + 1
                    )));
                }
            }
            continue;
        }
        if raw.is_empty() {
            logical.push((i + 1, String::new()));
            blank_before = true;
            continue;
        }
        blank_before = false;
        logical.push((i + 1, raw.to_string()));
    }
    let mut out = Vec::new();
    let mut cur: Vec<Line> = Vec::new();
    for (no, l) in logical {
        if l.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        if l == "-" {
            cur.push(Line {
                no,
                attr: "-".into(),
                value: None,
            });
            continue;
        }
        let (attr, rest) = l
            .split_once(':')
            .ok_or_else(|| Error::usage(format!("LDIF line {no}: expected 'attribute: value'")))?;
        let value = if let Some(b) = rest.strip_prefix(':') {
            B64.decode(b.trim())
                .map_err(|e| Error::usage(format!("LDIF line {no}: invalid base64: {e}")))?
        } else if rest.starts_with('<') {
            return Err(Error::usage(format!(
                "LDIF line {no}: URL values (':<') are not supported; inline the value with '::' base64"
            )));
        } else {
            rest.trim_start_matches(' ').as_bytes().to_vec()
        };
        cur.push(Line {
            no,
            attr: attr.to_string(),
            value: Some(value),
        });
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn text(l: &Line) -> Result<String> {
    String::from_utf8(l.value.clone().unwrap_or_default())
        .map_err(|_| Error::usage(format!("LDIF line {}: value is not UTF-8", l.no)))
}

fn parse_record(lines: Vec<Line>, content_is_add: bool) -> Result<Option<Change>> {
    let mut it = lines.into_iter().peekable();
    // A leading "version: 1" line may stand alone or precede the first record.
    if it
        .peek()
        .is_some_and(|l| l.attr.eq_ignore_ascii_case("version"))
    {
        it.next();
        if it.peek().is_none() {
            return Ok(None);
        }
    }
    let first = it.next().unwrap();
    if !first.attr.eq_ignore_ascii_case("dn") {
        return Err(Error::usage(format!(
            "LDIF line {}: record must start with 'dn:'",
            first.no
        )));
    }
    let dn = text(&first)?;
    let mut changetype = None;
    if let Some(l) = it.peek() {
        if l.attr.eq_ignore_ascii_case("control") {
            return Err(Error::usage(format!(
                "LDIF line {}: 'control:' lines are not supported; use --control",
                l.no
            )));
        }
        if l.attr.eq_ignore_ascii_case("changetype") {
            changetype = Some(text(l)?.to_ascii_lowercase());
            it.next();
        }
    }
    let rest: Vec<Line> = it.collect();
    match changetype.as_deref() {
        None if !content_is_add => Err(Error::usage(format!(
            "LDIF record '{dn}' has no changetype (use 'ldap add' for content records)"
        ))),
        None | Some("add") => {
            let mut attrs: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
            for l in rest {
                let v = l
                    .value
                    .ok_or_else(|| Error::usage(format!("LDIF line {}: unexpected '-'", l.no)))?;
                match attrs
                    .iter_mut()
                    .find(|(a, _)| a.eq_ignore_ascii_case(&l.attr))
                {
                    Some((_, vs)) => vs.push(v),
                    None => attrs.push((l.attr, vec![v])),
                }
            }
            Ok(Some(Change::Add { dn, attrs }))
        }
        Some("delete") => {
            if let Some(l) = rest.first() {
                return Err(Error::usage(format!(
                    "LDIF line {}: delete records take no attributes",
                    l.no
                )));
            }
            Ok(Some(Change::Delete { dn }))
        }
        Some("modrdn") | Some("moddn") => {
            let (mut new_rdn, mut delete_old, mut new_superior) = (None, None, None);
            for l in &rest {
                match l.attr.to_ascii_lowercase().as_str() {
                    "newrdn" => new_rdn = Some(text(l)?),
                    "deleteoldrdn" => delete_old = Some(text(l)? == "1"),
                    "newsuperior" => new_superior = Some(text(l)?),
                    _ => {
                        return Err(Error::usage(format!(
                            "LDIF line {}: unexpected '{}' in modrdn",
                            l.no, l.attr
                        )));
                    }
                }
            }
            Ok(Some(Change::ModRdn {
                dn,
                new_rdn: new_rdn.ok_or_else(|| Error::usage("modrdn record without newrdn"))?,
                delete_old: delete_old.unwrap_or(true),
                new_superior,
            }))
        }
        Some("modify") => {
            let mut mods = Vec::new();
            let mut cur: Option<Modification> = None;
            for l in rest {
                match (&mut cur, l.value) {
                    (None, Some(v)) => {
                        let op = match l.attr.to_ascii_lowercase().as_str() {
                            "add" => ModOp::Add,
                            "delete" => ModOp::Delete,
                            "replace" => ModOp::Replace,
                            "increment" => ModOp::Increment,
                            other => {
                                return Err(Error::usage(format!(
                                    "LDIF line {}: unknown modify operation '{other}'",
                                    l.no
                                )));
                            }
                        };
                        let attr = String::from_utf8(v)
                            .map_err(|_| Error::usage("attribute name is not UTF-8"))?;
                        cur = Some(Modification {
                            op,
                            attr,
                            values: Vec::new(),
                        });
                    }
                    (Some(m), Some(v)) => {
                        if !l.attr.eq_ignore_ascii_case(&m.attr) {
                            return Err(Error::usage(format!(
                                "LDIF line {}: '{}' inside a modification of '{}' (missing '-'?)",
                                l.no, l.attr, m.attr
                            )));
                        }
                        m.values.push(v);
                    }
                    (Some(_), None) => mods.push(cur.take().unwrap()),
                    (None, None) => {
                        return Err(Error::usage(format!("LDIF line {}: unexpected '-'", l.no)));
                    }
                }
            }
            if let Some(m) = cur {
                mods.push(m);
            }
            Ok(Some(Change::Modify { dn, mods }))
        }
        Some(other) => Err(Error::usage(format!("unknown changetype '{other}'"))),
    }
}

// ---------------- writing ----------------

/// RFC 2849 SAFE-STRING check; anything else is written base64-encoded.
pub fn is_safe(v: &[u8]) -> bool {
    match v.first() {
        None => true,
        Some(b' ' | b':' | b'<') => false,
        Some(_) => {
            v.iter()
                .all(|b| (1..0x80).contains(b) && *b != b'\n' && *b != b'\r')
                && v.last() != Some(&b' ')
        }
    }
}

pub fn write_line(out: &mut String, attr: &str, v: &[u8], wrap: usize) {
    let line = if is_safe(v) {
        format!("{attr}: {}", std::str::from_utf8(v).unwrap())
    } else {
        format!("{attr}:: {}", B64.encode(v))
    };
    if wrap == 0 || line.len() <= wrap {
        out.push_str(&line);
        out.push('\n');
        return;
    }
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut first = true;
    while start < bytes.len() {
        let width = if first { wrap } else { wrap - 1 };
        let mut end = (start + width).min(bytes.len());
        while end < bytes.len() && !line.is_char_boundary(end) {
            end -= 1;
        }
        if !first {
            out.push(' ');
        }
        out.push_str(&line[start..end]);
        out.push('\n');
        start = end;
        first = false;
    }
}

pub fn write_entry(
    e: &Entry,
    wrap: usize,
    annotate: impl Fn(&str, &[u8]) -> Option<String>,
) -> String {
    let mut s = String::new();
    write_line(&mut s, "dn", e.dn.as_bytes(), wrap);
    for (a, vs) in &e.attrs {
        for v in vs {
            write_line(&mut s, a, v, wrap);
            if let Some(note) = annotate(a, v) {
                s.push_str(&format!("# {a}: {note}\n"));
            }
        }
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_and_changes() {
        let text = "version: 1\n\n# comment\ndn: cn=a,dc=x\nobjectClass: top\nobjectClass: person\ncn: a\ndescription:: w6k=\n\ndn: cn=b,dc=x\nchangetype: modify\nreplace: mail\nmail: b@x\n-\nadd: description\ndescription: one\ndescription: two\n-\ndelete: telephoneNumber\n-\n\ndn: cn=c,dc=x\nchangetype: delete\n\ndn: cn=d,dc=x\nchangetype: modrdn\nnewrdn: cn=e\ndeleteoldrdn: 0\nnewsuperior: ou=y,dc=x\n";
        let c = parse(text, true).unwrap();
        assert_eq!(c.len(), 4);
        match &c[0] {
            Change::Add { attrs, .. } => {
                assert_eq!(attrs[0].1.len(), 2);
                assert_eq!(attrs[2].1[0], "é".as_bytes());
            }
            _ => panic!(),
        }
        match &c[1] {
            Change::Modify { mods, .. } => {
                assert_eq!(mods.len(), 3);
                assert_eq!(mods[1].values.len(), 2);
                assert_eq!(mods[2].op, ModOp::Delete);
                assert!(mods[2].values.is_empty());
            }
            _ => panic!(),
        }
        assert!(matches!(
            &c[3],
            Change::ModRdn {
                delete_old: false,
                new_superior: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn folding() {
        let c = parse("dn: cn=lo\n ng,dc=x\ncn: lo\n ng\n", true).unwrap();
        assert_eq!(c[0].dn(), "cn=long,dc=x");
    }

    #[test]
    fn errors() {
        assert!(parse("cn: x\n", true).is_err());
        assert!(parse("dn: cn=x\ncn: y\n", false).is_err());
        assert!(parse("dn: cn=x\njpegPhoto:< file:///etc/passwd\n", true).is_err());
        assert!(parse("dn: cn=x\nchangetype: modify\nreplace: a\nb: 1\n", true).is_err());
    }

    #[test]
    fn writer() {
        assert!(is_safe(b"hello world"));
        assert!(!is_safe(b" lead"));
        assert!(!is_safe(b"trail "));
        assert!(!is_safe("é".as_bytes()));
        assert!(!is_safe(b":x"));
        let e = Entry {
            dn: "cn=a".into(),
            attrs: vec![("x".into(), vec![vec![0, 1]])],
        };
        assert_eq!(write_entry(&e, 0, |_, _| None), "dn: cn=a\nx:: AAE=\n\n");
        let mut s = String::new();
        write_line(&mut s, "description", &[b'a'; 100], 76);
        assert!(s.lines().all(|l| l.len() <= 76));
        assert_eq!(parse(&format!("dn: cn=a\n{s}"), true).unwrap().len(), 1);
    }
}
