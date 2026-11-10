//! Minimal BER encoding/decoding for control and extended-operation values.
//! Only what the CLI needs: SEQUENCE, INTEGER, OCTET STRING, BOOLEAN, context tags.

use crate::error::{Error, Result};

pub const SEQUENCE: u8 = 0x30;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn integer(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    tlv(INTEGER, &bytes)
}

pub fn octets(v: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, v)
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A decoded TLV element borrowing from the input.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
}

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn next(&mut self) -> Result<Tlv<'a>> {
        let bad = || Error::usage("malformed BER value");
        let tag = *self.buf.first().ok_or_else(bad)?;
        let l0 = *self.buf.get(1).ok_or_else(bad)?;
        let (len, hdr) = if l0 < 0x80 {
            (l0 as usize, 2)
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(bad());
            }
            let mut len = 0usize;
            for i in 0..n {
                len = len << 8 | *self.buf.get(2 + i).ok_or_else(bad)? as usize;
            }
            (len, 2 + n)
        };
        let content = self.buf.get(hdr..hdr + len).ok_or_else(bad)?;
        self.buf = &self.buf[hdr + len..];
        Ok(Tlv { tag, content })
    }
}

pub fn as_integer(t: Tlv) -> Result<i64> {
    if t.tag != INTEGER || t.content.is_empty() || t.content.len() > 8 {
        return Err(Error::usage("expected BER INTEGER"));
    }
    let mut v: i64 = if t.content[0] & 0x80 != 0 { -1 } else { 0 };
    for b in t.content {
        v = v << 8 | *b as i64;
    }
    Ok(v)
}

// ---- Controls and extended operations built on BER ----

pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";
pub const OID_SORT_REQUEST: &str = "1.2.840.113556.1.4.473";
pub const OID_TREE_DELETE: &str = "1.2.840.113556.1.4.805";
pub const OID_WHOAMI: &str = "1.3.6.1.4.1.4203.1.11.3";
pub const OID_PASSWD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";
pub const OID_CANCEL: &str = "1.3.6.1.1.8";
pub const OID_REFRESH: &str = "1.3.6.1.4.1.1466.101.119.1";
pub const OID_AD_CAPABILITY: &str = "1.2.840.113556.1.4.800";

/// RFC 2696 paged results request value.
pub fn paged_request(size: u32, cookie: &[u8]) -> Vec<u8> {
    sequence(&[integer(size as i64), octets(cookie)])
}

/// Parse a paged results response value, returning the cookie (empty = last page).
pub fn paged_response(v: &[u8]) -> Result<Vec<u8>> {
    let seq = Reader::new(v).next()?;
    let mut r = Reader::new(seq.content);
    let _size = as_integer(r.next()?)?;
    let cookie = r.next()?;
    Ok(cookie.content.to_vec())
}

/// RFC 2891 sort request value. Keys are `[-]attr[:orderingRule]`.
pub fn sort_request(keys: &[String]) -> Result<Vec<u8>> {
    let mut parts = Vec::new();
    for k in keys {
        let (reverse, k) = match k.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, k.as_str()),
        };
        let (attr, rule) = match k.split_once(':') {
            Some((a, r)) => (a, Some(r)),
            None => (k, None),
        };
        if attr.is_empty() {
            return Err(Error::usage("empty sort key"));
        }
        let mut key = vec![octets(attr.as_bytes())];
        if let Some(r) = rule {
            key.push(tlv(0x80, r.as_bytes()));
        }
        if reverse {
            key.push(tlv(0x81, &[0xff]));
        }
        parts.push(sequence(&key));
    }
    Ok(sequence(&parts))
}

/// RFC 3062 password modify request value.
pub fn passwd_request(user: Option<&str>, old: Option<&[u8]>, new: Option<&[u8]>) -> Vec<u8> {
    let mut parts = Vec::new();
    if let Some(u) = user {
        parts.push(tlv(0x80, u.as_bytes()));
    }
    if let Some(o) = old {
        parts.push(tlv(0x81, o));
    }
    if let Some(n) = new {
        parts.push(tlv(0x82, n));
    }
    sequence(&parts)
}

/// RFC 3062 response: optional [0] genPasswd.
pub fn passwd_response(v: &[u8]) -> Result<Option<Vec<u8>>> {
    if v.is_empty() {
        return Ok(None);
    }
    let seq = Reader::new(v).next()?;
    let mut r = Reader::new(seq.content);
    while !r.is_empty() {
        let t = r.next()?;
        if t.tag == 0x80 {
            return Ok(Some(t.content.to_vec()));
        }
    }
    Ok(None)
}

/// RFC 3909 cancel request value.
pub fn cancel_request(msgid: i64) -> Vec<u8> {
    sequence(&[integer(msgid)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(integer(0), [2, 1, 0]);
        assert_eq!(integer(127), [2, 1, 0x7f]);
        assert_eq!(integer(128), [2, 2, 0, 0x80]);
        assert_eq!(integer(500), [2, 2, 1, 0xf4]);
        assert_eq!(integer(-1), [2, 1, 0xff]);
        for v in [
            0,
            1,
            127,
            128,
            255,
            256,
            65535,
            -1,
            -128,
            -129,
            i32::MAX as i64,
        ] {
            assert_eq!(
                as_integer(Reader::new(&integer(v)).next().unwrap()).unwrap(),
                v
            );
        }
    }

    #[test]
    fn long_lengths() {
        let big = vec![7u8; 300];
        let enc = octets(&big);
        assert_eq!(&enc[..4], &[4, 0x82, 1, 44]);
        assert_eq!(Reader::new(&enc).next().unwrap().content, &big[..]);
    }

    #[test]
    fn paging_round_trip() {
        let req = paged_request(500, b"");
        assert_eq!(req, [0x30, 0x06, 0x02, 0x02, 0x01, 0xf4, 0x04, 0x00]);
        let resp = sequence(&[integer(0), octets(b"cookie")]);
        assert_eq!(paged_response(&resp).unwrap(), b"cookie");
    }

    #[test]
    fn sort_keys() {
        let v = sort_request(&["-cn".into(), "sn:2.5.13.3".into()]).unwrap();
        assert_eq!(
            v,
            sequence(&[
                sequence(&[octets(b"cn"), tlv(0x81, &[0xff])]),
                sequence(&[octets(b"sn"), tlv(0x80, b"2.5.13.3")]),
            ])
        );
    }

    #[test]
    fn passwd() {
        let v = passwd_request(Some("uid=a"), None, Some(b"pw"));
        assert_eq!(
            v,
            [
                0x30, 0x0b, 0x80, 5, b'u', b'i', b'd', b'=', b'a', 0x82, 2, b'p', b'w'
            ]
        );
        assert_eq!(
            passwd_response(&sequence(&[tlv(0x80, b"gen")])).unwrap(),
            Some(b"gen".to_vec())
        );
        assert_eq!(passwd_response(&[]).unwrap(), None);
    }

    #[test]
    fn malformed() {
        assert!(Reader::new(&[0x30]).next().is_err());
        assert!(Reader::new(&[0x30, 5, 1]).next().is_err());
        assert!(paged_response(&[0x30, 0]).is_err());
    }
}
