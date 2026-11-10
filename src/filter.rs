//! Syntax check for RFC 4515 search filters.
//!
//! Template values are escaped before substitution, so this check exists to catch
//! malformed templates (and, with --raw-filter, user-supplied filters) before they
//! reach the server.

use crate::error::{Error, Result};

/// Validate a filter and return it in canonical parenthesised form.
/// A bare item such as `uid=jdoe` is wrapped as `(uid=jdoe)`.
pub fn normalize(filter: &str) -> Result<String> {
    let f = filter.trim();
    let f = if f.starts_with('(') {
        f.to_string()
    } else {
        format!("({f})")
    };
    let mut p = Parser {
        s: f.as_bytes(),
        i: 0,
    };
    p.filter()?;
    if p.i != p.s.len() {
        return Err(p.err("unexpected text after the end of the filter"));
    }
    Ok(f)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, m: &str) -> Error {
        Error::usage(format!("invalid filter at offset {}: {m}", self.i))
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn expect(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    fn filter(&mut self) -> Result<()> {
        self.expect(b'(')?;
        match self.peek() {
            Some(b'&') | Some(b'|') => {
                self.i += 1;
                let mut n = 0;
                while self.peek() == Some(b'(') {
                    self.filter()?;
                    n += 1;
                }
                if n == 0 {
                    // RFC 4526 absolute true/false "(&)" / "(|)" is allowed.
                }
            }
            Some(b'!') => {
                self.i += 1;
                self.filter()?;
            }
            Some(_) => self.item()?,
            None => return Err(self.err("unterminated filter")),
        }
        self.expect(b')')
    }

    fn item(&mut self) -> Result<()> {
        // attr [":dn"] [":" matchingrule] ( "=" | "~=" | ">=" | "<=" | ":=" ) value
        let start = self.i;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b';' | b':') {
                self.i += 1;
            } else {
                break;
            }
        }
        let attr = &self.s[start..self.i];
        let extensible = attr.ends_with(b":");
        match self.peek() {
            Some(b'=') if extensible || !attr.is_empty() => self.i += 1,
            Some(b'~' | b'>' | b'<') if !attr.is_empty() && !extensible => {
                self.i += 1;
                self.expect(b'=')?;
            }
            _ => return Err(self.err("expected an attribute description followed by an operator")),
        }
        if attr.is_empty() || attr == b":" {
            return Err(self.err("missing attribute description"));
        }
        // value: anything but unescaped '(' ')' NUL; '\' must be followed by two hex digits
        while let Some(c) = self.peek() {
            match c {
                b')' => return Ok(()),
                b'(' | 0 => return Err(self.err("unescaped '(' or NUL in value")),
                b'\\' => {
                    let ok = self
                        .s
                        .get(self.i + 1)
                        .is_some_and(|b| b.is_ascii_hexdigit())
                        && self
                            .s
                            .get(self.i + 2)
                            .is_some_and(|b| b.is_ascii_hexdigit());
                    if !ok {
                        return Err(self.err("'\\' must be followed by two hex digits"));
                    }
                    self.i += 3;
                }
                _ => self.i += 1,
            }
        }
        Err(self.err("unterminated filter"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid() {
        for f in [
            "(objectClass=*)",
            "uid=jdoe",
            "(&(objectClass=user)(sAMAccountName=j\\2adoe))",
            "(|(cn=a*)(!(mail=*@x.com)))",
            "(cn~=smith)",
            "(uSNChanged>=100)",
            "(userAccountControl:1.2.840.113556.1.4.803:=2)",
            "(cn:dn:2.5.13.5:=John)",
            "(&)",
            "(cn=Lučić)",
        ] {
            assert!(normalize(f).is_ok(), "{f}");
        }
        assert_eq!(normalize("uid=x").unwrap(), "(uid=x)");
    }

    #[test]
    fn rejects_invalid() {
        for f in [
            "(cn=a",
            "(cn=a))",
            "(cn=a(b)",
            "(=x)",
            "(cn=\\zz)",
            "(cn=\\5)",
            "cn",
            "(&(cn=a)",
            "(cn=a)(cn=b)",
        ] {
            assert!(normalize(f).is_err(), "{f}");
        }
    }
}
