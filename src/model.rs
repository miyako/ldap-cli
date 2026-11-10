//! Backend-neutral types shared by the core and the platform backends.

use crate::secret::Secret;

#[derive(Debug, Clone)]
pub struct Control {
    pub oid: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<Vec<u8>>)>,
}

impl Entry {
    pub fn get(&self, name: &str) -> Option<&Vec<Vec<u8>>> {
        self.attrs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
    pub fn get_str(&self, name: &str) -> Vec<String> {
        self.get(name)
            .map(|vs| {
                vs.iter()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Base,
    One,
    Sub,
    Children,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Deref {
    Never,
    Search,
    Find,
    Always,
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    pub attrs: Vec<String>,
    pub types_only: bool,
    pub size_limit: u32,
    pub time_limit: u32,
    pub deref: Deref,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModOp {
    Add,
    Delete,
    Replace,
    Increment,
}

#[derive(Debug, Clone)]
pub struct Modification {
    pub op: ModOp,
    pub attr: String,
    pub values: Vec<Vec<u8>>,
}

/// Outcome of one LDAP operation as reported by the server.
#[derive(Debug, Clone, Default)]
pub struct OpResult {
    pub code: i32,
    pub matched: String,
    pub message: String,
    pub controls: Vec<Control>,
    pub referrals: Vec<String>,
}

impl OpResult {
    pub fn control(&self, oid: &str) -> Option<&Control> {
        self.controls.iter().find(|c| c.oid == oid)
    }
    pub fn into_result(self) -> crate::error::Result<OpResult> {
        if self.code == 0 {
            Ok(self)
        } else {
            let mut message = self.message;
            if !self.referrals.is_empty() {
                message = format!("{message} (referral to {})", self.referrals.join(" "))
                    .trim()
                    .to_string();
            }
            Err(crate::error::Error::ldap(self.code, message, self.matched))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExtResult {
    pub result: OpResult,
    pub oid: Option<String>,
    pub value: Option<Vec<u8>>,
}

// ---------------- connection options ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Ldaps,
    Starttls,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mech {
    Anonymous,
    Simple,
    Gssapi,
    Spnego,
    Ntlm,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Qos {
    Auto,
    Auth,
    Sign,
    Seal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelBinding {
    Auto,
    Require,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Revocation {
    Off,
    Soft,
    Hard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreLocation {
    User,
    Machine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
pub enum TlsMin {
    #[value(name = "1.2")]
    #[serde(rename = "1.2")]
    V1_2,
    #[value(name = "1.3")]
    #[serde(rename = "1.3")]
    V1_3,
}

/// How to choose a client certificate.
#[derive(Debug, Clone)]
pub enum ClientIdentity {
    None,
    /// SHA-256 thumbprint (hex) in the OS store / Keychain.
    Thumbprint(Vec<u8>),
    /// Subject DN substring match, restricted to Client Authentication EKU.
    Subject(String),
    /// Let the platform choose from the server's acceptable CA list.
    Auto,
    /// Inline PKCS#12 (from an environment variable or stdin).
    Pkcs12 {
        der: Secret,
        password: Secret,
    },
}

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub mode: TlsMode,
    /// Extra trust anchors (DER) added to the OS trust store.
    pub ca_certs: Vec<Vec<u8>>,
    pub server_name: Option<String>,
    pub min: TlsMin,
    pub revocation: Revocation,
    pub insecure_skip_verify: bool,
    pub client: ClientIdentity,
    pub store: StoreLocation,
    /// Record the server chain for `probe`.
    pub capture_chain: bool,
}

#[derive(Debug, Clone)]
pub struct AuthOptions {
    pub mech: Mech,
    pub bind_dn: Option<String>,
    pub user: Option<String>,
    pub realm: Option<String>,
    #[cfg_attr(windows, allow(dead_code))]
    pub authzid: Option<String>,
    pub password: Option<Secret>,
    #[cfg_attr(windows, allow(dead_code))]
    pub ccache: Option<String>,
    /// Already resolved from `auto`.
    pub qos: Qos,
    #[cfg_attr(windows, allow(dead_code))]
    pub channel_binding: ChannelBinding,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub allow_ntlm: bool,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub targets: Vec<Target>,
    pub tls: TlsOptions,
    pub auth: AuthOptions,
    pub connect_timeout: u32,
    pub timeout: u32,
    pub referrals: bool,
    pub verbose: bool,
}

/// Information about an established session.
#[derive(Debug, Clone, Default)]
pub struct SessionInfo {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub tls_version: Option<String>,
    /// Server certificate chain as presented (leaf first): DER and subject summary.
    pub peer_chain: Vec<(Vec<u8>, String)>,
}
