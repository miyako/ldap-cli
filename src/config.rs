//! Profiles from ~/.config/ldap/config.toml (macOS) or %APPDATA%\ldap\config.toml (Windows).
//!
//! ```toml
//! default_profile = "corp"
//! [profile.corp]
//! domain = "corp.example"
//! mech = "gssapi"
//! base = "DC=corp,DC=example"
//! ca_certs = ["MIIB…"]
//! ```
//! Private keys and passwords are not accepted in profiles.

use crate::cli::Referrals;
use crate::error::{Error, Result};
use crate::model::*;
use crate::output::{Binary, Format};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profile: BTreeMap<String, Profile>,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub uri: Option<Vec<String>>,
    pub domain: Option<String>,
    pub site: Option<String>,
    pub gc: Option<bool>,
    pub tls: Option<TlsMode>,
    pub connect_timeout: Option<u32>,
    pub timeout: Option<u32>,
    pub referrals: Option<Referrals>,
    pub ca_certs: Option<Vec<String>>,
    pub tls_server_name: Option<String>,
    pub tls_min: Option<TlsMin>,
    pub revocation: Option<Revocation>,
    /// Store selector only (sha256/…, subject:…, auto, env:VAR).
    pub client_cert: Option<String>,
    pub cert_store: Option<StoreLocation>,
    pub mech: Option<Mech>,
    pub bind_dn: Option<String>,
    pub user: Option<String>,
    pub realm: Option<String>,
    pub sasl_qos: Option<Qos>,
    pub channel_binding: Option<ChannelBinding>,
    pub allow_ntlm: Option<bool>,
    pub password_env: Option<String>,
    pub base: Option<String>,
    pub scope: Option<Scope>,
    pub page_size: Option<u32>,
    pub format: Option<Format>,
    pub binary: Option<Binary>,
}

pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LDAP_CONFIG") {
        return Some(PathBuf::from(p));
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("ldap").join("config.toml"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("ldap").join("config.toml"))
    }
}

/// Load the selected profile (explicit name, or default_profile). Missing file → empty profile.
pub fn load(name: Option<&str>) -> Result<Profile> {
    let Some(p) = path() else {
        return Ok(Profile::default());
    };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return match name {
                Some(n) => Err(Error::usage(format!(
                    "profile '{n}' requested but {} does not exist",
                    p.display()
                ))),
                None => Ok(Profile::default()),
            };
        }
        Err(e) => return Err(e.into()),
    };
    let cfg: ConfigFile = toml::from_str(&text)
        .map_err(|e| Error::usage(format!("{}: {}", p.display(), e.message())))?;
    let name = name.map(str::to_string).or(cfg.default_profile.clone());
    match name {
        None => Ok(Profile::default()),
        Some(n) => cfg
            .profile
            .get(&n)
            .cloned()
            .ok_or_else(|| Error::usage(format!("profile '{n}' not found in {}", p.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_profile() {
        let c: ConfigFile = toml::from_str(
            "default_profile = \"corp\"\n[profile.corp]\ndomain = \"corp.example\"\nmech = \"gssapi\"\ntls_min = \"1.3\"\nca_certs = [\"AAAA\"]\n",
        )
        .unwrap();
        let p = &c.profile["corp"];
        assert_eq!(p.mech, Some(Mech::Gssapi));
        assert_eq!(p.tls_min, Some(TlsMin::V1_3));
        assert!(toml::from_str::<ConfigFile>("[profile.x]\npassword = \"no\"\n").is_err());
    }
}
