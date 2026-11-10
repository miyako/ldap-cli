//! Platform backends behind one interface.
//!
//! Windows: Wldap32 + SSPI + Schannel. macOS: OpenLDAP 2.6 + Cyrus SASL (system) +
//! OpenSSL with Security.framework as the trust authority.

use crate::discovery::Srv;
use crate::error::{Error, Result};
use crate::model::*;

#[cfg(target_os = "macos")]
mod openldap;
#[cfg(target_os = "macos")]
use openldap as platform;

#[cfg(windows)]
mod winldap;
#[cfg(windows)]
use winldap as platform;

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("ldap-cli supports only Windows and macOS");

pub type Attrs = [(String, Vec<Vec<u8>>)];

pub trait Session {
    fn info(&self) -> SessionInfo;

    /// Run one search request (one page); entries and references are delivered as they arrive.
    fn search(
        &mut self,
        req: &SearchRequest,
        controls: &[Control],
        on_entry: &mut dyn FnMut(Entry) -> Result<()>,
        on_reference: &mut dyn FnMut(Vec<String>) -> Result<()>,
    ) -> Result<OpResult>;
    fn add(&mut self, dn: &str, attrs: &Attrs, controls: &[Control]) -> Result<OpResult>;
    fn modify(&mut self, dn: &str, mods: &[Modification], controls: &[Control])
    -> Result<OpResult>;
    fn delete(&mut self, dn: &str, controls: &[Control]) -> Result<OpResult>;
    fn rename(
        &mut self,
        dn: &str,
        new_rdn: &str,
        new_superior: Option<&str>,
        delete_old: bool,
        controls: &[Control],
    ) -> Result<OpResult>;
    /// Returns the raw result; code 6 = compareTrue, 5 = compareFalse.
    fn compare(
        &mut self,
        dn: &str,
        attr: &str,
        value: &[u8],
        controls: &[Control],
    ) -> Result<OpResult>;
    fn extended(
        &mut self,
        oid: &str,
        value: Option<&[u8]>,
        controls: &[Control],
    ) -> Result<ExtResult>;
}

/// Connect and bind, trying each target in order. Connection/TLS failures move on to the
/// next target; authentication failures stop immediately (no credential spraying).
pub fn connect(opts: &ConnectOptions) -> Result<Box<dyn Session>> {
    let mut last = None;
    for t in &opts.targets {
        if opts.verbose {
            eprintln!("connecting to {}:{} ({:?})", t.host, t.port, opts.tls.mode);
        }
        match platform::connect(opts, t) {
            Ok(s) => return Ok(s),
            Err(e @ Error::Connect(_)) => {
                if opts.targets.len() > 1 {
                    eprintln!("{}:{}: {e}", t.host, t.port);
                }
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::connect("no targets")))
}

pub fn query_srv(name: &str) -> Result<Vec<Srv>> {
    platform::query_srv(name)
}

/// The platform's own DC locator, if any (Windows: DsGetDcName).
pub fn preferred_dc(domain: &str, site: Option<&str>, gc: bool) -> Option<String> {
    platform::preferred_dc(domain, site, gc)
}
