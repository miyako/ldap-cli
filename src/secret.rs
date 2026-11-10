//! Secrets (passwords, PKCS#12 blobs) that are zeroed on drop and never printed.

use crate::error::{Error, Result};
use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Secret {
    pub fn new(v: Vec<u8>) -> Self {
        Secret(Zeroizing::new(v))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|_| Error::usage("secret is not valid UTF-8"))
    }
}

/// Where a secret comes from. Command-line values are deliberately not supported.
#[derive(Debug, Clone)]
pub enum Source {
    File(String),
    Env(String),
    Stdin,
    Prompt(String),
}

/// Ensures at most one option consumes stdin.
#[derive(Default)]
pub struct StdinGuard(Option<&'static str>);

impl StdinGuard {
    pub fn claim(&mut self, who: &'static str) -> Result<()> {
        if let Some(prev) = self.0 {
            return Err(Error::usage(format!(
                "both {prev} and {who} want to read stdin; only one may"
            )));
        }
        self.0 = Some(who);
        Ok(())
    }
}

pub fn read(src: &Source) -> Result<Secret> {
    let mut v = match src {
        Source::File(p) => {
            std::fs::read(p).map_err(|e| Error::usage(format!("cannot read {p}: {e}")))?
        }
        Source::Env(var) => std::env::var_os(var)
            .ok_or_else(|| Error::usage(format!("environment variable {var} is not set")))?
            .into_encoded_bytes(),
        Source::Stdin => {
            let mut v = Vec::new();
            std::io::stdin().read_to_end(&mut v)?;
            v
        }
        Source::Prompt(p) => {
            if !std::io::stdin().is_terminal() {
                return Err(Error::usage(format!(
                    "{p}: no terminal to prompt on; use --password-env, --password-stdin or --password-file"
                )));
            }
            rpassword::prompt_password(format!("{p}: "))?.into_bytes()
        }
    };
    // Strip one trailing newline (files and stdin usually end with one).
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    Ok(Secret::new(v))
}

/// Read a password and reject empty values. An empty password with a non-empty DN is an
/// "unauthenticated bind" (RFC 4513 §5.1.2) that many servers report as success.
pub fn read_password(src: &Source) -> Result<Secret> {
    let s = read(src)?;
    if s.is_empty() {
        return Err(Error::usage(
            "empty password rejected: an empty simple-bind password is an unauthenticated bind (RFC 4513 §5.1.2)",
        ));
    }
    if s.bytes().contains(&0) {
        return Err(Error::usage("password contains a NUL byte"));
    }
    Ok(s)
}

/// Decode base64 that may be a pasted PEM block, base64url, or contain whitespace.
pub fn decode_base64_lenient(s: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    let text = String::from_utf8_lossy(s);
    let body: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let body = body.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(body)
        .map_err(|e| Error::usage(format!("invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_base64() {
        assert_eq!(decode_base64_lenient(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(
            decode_base64_lenient(b"-----BEGIN X-----\naGVs\nbG8=\n-----END X-----\n").unwrap(),
            b"hello"
        );
        assert_eq!(decode_base64_lenient(b"__8").unwrap(), [0xff, 0xff]);
        assert!(decode_base64_lenient(b"!!").is_err());
    }

    #[test]
    fn empty_password_rejected() {
        unsafe { std::env::set_var("LDAP_CLI_TEST_EMPTY", "") };
        assert!(read_password(&Source::Env("LDAP_CLI_TEST_EMPTY".into())).is_err());
        unsafe { std::env::set_var("LDAP_CLI_TEST_PW", "s3cret\n") };
        assert_eq!(
            read_password(&Source::Env("LDAP_CLI_TEST_PW".into()))
                .unwrap()
                .bytes(),
            b"s3cret"
        );
    }

    #[test]
    fn stdin_single_consumer() {
        let mut g = StdinGuard::default();
        g.claim("--password-stdin").unwrap();
        assert!(g.claim("--file -").is_err());
    }

    #[test]
    fn debug_redacts() {
        assert_eq!(format!("{:?}", Secret::new(b"x".to_vec())), "Secret(***)");
    }
}
