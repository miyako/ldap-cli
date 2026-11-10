//! Command-line definition.

use crate::model::*;
use crate::output::{Binary, Format};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ldap",
    version,
    about = "LDAP client with native backends (Wldap32/SSPI/Schannel on Windows; OpenLDAP/GSSAPI/Security.framework on macOS)",
    after_help = "Exit codes: 0 success, 1 compare false, 2 usage, 3 connection/TLS, 4 authentication, 10+N LDAP result code N.\n\
                  Passwords are never accepted on the command line: use --password-env, --password-stdin, --password-file or the prompt."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Global {
    // ---------------- connection ----------------
    /// Server URI (ldaps://host[:636] or ldap://host[:389]); repeat for failover
    #[arg(short = 'H', long = "uri", global = true, help_heading = "Connection")]
    pub uri: Vec<String>,
    /// Find domain controllers via DNS SRV records instead of --uri
    #[arg(long, global = true, help_heading = "Connection")]
    pub domain: Option<String>,
    /// AD site to prefer when using --domain
    #[arg(long, global = true, help_heading = "Connection")]
    pub site: Option<String>,
    /// Locate Global Catalog servers (ports 3268/3269) with --domain
    #[arg(long, global = true, help_heading = "Connection")]
    pub gc: bool,
    /// Accept SRV targets outside the domain given with --domain
    #[arg(long, global = true, help_heading = "Connection")]
    pub allow_foreign_dc: bool,
    /// Transport security [default: from URI scheme; ldap:// means starttls]
    #[arg(long, global = true, value_enum, help_heading = "Connection")]
    pub tls: Option<TlsMode>,
    /// Required for --tls none
    #[arg(long, global = true, help_heading = "Connection")]
    pub allow_plaintext: bool,
    /// Connection timeout in seconds
    #[arg(long, global = true, help_heading = "Connection")]
    pub connect_timeout: Option<u32>,
    /// Per-operation timeout in seconds
    #[arg(long, global = true, help_heading = "Connection")]
    pub timeout: Option<u32>,
    /// Follow referrals (re-binds with the same mechanism; never resends a simple-bind password)
    #[arg(long, global = true, value_enum, help_heading = "Connection")]
    pub referrals: Option<Referrals>,
    /// Named profile from the config file
    #[arg(long, global = true, env = "LDAP_PROFILE", help_heading = "Connection")]
    pub profile: Option<String>,

    // ---------------- TLS ----------------
    /// Extra trust anchor (base64 DER or pasted PEM), added to the OS trust store; repeatable
    #[arg(long = "ca-cert", global = true, help_heading = "TLS")]
    pub ca_cert: Vec<String>,
    /// Name used for certificate hostname verification
    #[arg(long, global = true, help_heading = "TLS")]
    pub tls_server_name: Option<String>,
    /// Minimum TLS version
    #[arg(long, global = true, value_enum, help_heading = "TLS")]
    pub tls_min: Option<TlsMin>,
    /// Certificate revocation checking
    #[arg(long, global = true, value_enum, help_heading = "TLS")]
    pub revocation: Option<Revocation>,
    /// Client certificate: sha256/HEX | subject:"CN=…" | auto | env:VAR | stdin
    #[arg(long, global = true, help_heading = "TLS")]
    pub client_cert: Option<String>,
    /// Environment variable holding the PKCS#12 password
    #[arg(long, global = true, help_heading = "TLS")]
    pub client_cert_password_env: Option<String>,
    /// Read the PKCS#12 password from stdin
    #[arg(long, global = true, help_heading = "TLS")]
    pub client_cert_password_stdin: bool,
    /// Certificate store / keychain to search
    #[arg(long, global = true, value_enum, help_heading = "TLS")]
    pub cert_store: Option<StoreLocation>,
    /// Do not verify the server certificate (prints a warning on every run)
    #[arg(long, global = true, help_heading = "TLS")]
    pub insecure_skip_verify: bool,

    // ---------------- authentication ----------------
    /// Bind mechanism [default: simple with -D, otherwise anonymous]
    #[arg(
        short = 'M',
        long,
        global = true,
        value_enum,
        help_heading = "Authentication"
    )]
    pub mech: Option<Mech>,
    /// Bind DN for simple bind
    #[arg(short = 'D', long, global = true, help_heading = "Authentication")]
    pub bind_dn: Option<String>,
    /// SASL/NTLM identity (user@REALM, DOMAIN\user); omit to use the logged-in user
    #[arg(short = 'U', long, global = true, help_heading = "Authentication")]
    pub user: Option<String>,
    #[arg(long, global = true, help_heading = "Authentication")]
    pub realm: Option<String>,
    /// SASL authorization identity (dn:… or u:…)
    #[arg(long, global = true, help_heading = "Authentication")]
    pub authzid: Option<String>,
    #[arg(long, global = true, help_heading = "Authentication")]
    pub password_file: Option<String>,
    #[arg(long, global = true, help_heading = "Authentication")]
    pub password_stdin: bool,
    #[arg(long, global = true, help_heading = "Authentication")]
    pub password_env: Option<String>,
    /// Kerberos credential cache (macOS)
    #[arg(long, global = true, help_heading = "Authentication")]
    pub ccache: Option<String>,
    /// SASL security layer [auto: auth over TLS, seal over plaintext]
    #[arg(long, global = true, value_enum, help_heading = "Authentication")]
    pub sasl_qos: Option<Qos>,
    /// TLS channel binding for SASL binds (tls-endpoint)
    #[arg(long, global = true, value_enum, help_heading = "Authentication")]
    pub channel_binding: Option<ChannelBinding>,
    /// Allow Negotiate/SPNEGO to fall back to NTLM (Windows)
    #[arg(long, global = true, help_heading = "Authentication")]
    pub allow_ntlm: bool,

    // ---------------- output ----------------
    /// Output format [default: ldif on a terminal, jsonl when piped]
    #[arg(short = 'o', long, global = true, value_enum, help_heading = "Output")]
    pub format: Option<Format>,
    /// Rendering of binary values
    #[arg(long, global = true, value_enum, help_heading = "Output")]
    pub binary: Option<Binary>,
    /// Wrap LDIF lines at this width (0 = no wrapping)
    #[arg(long, global = true, help_heading = "Output")]
    pub ldif_wrap: Option<usize>,
    #[arg(short = 'v', long, global = true, help_heading = "Output")]
    pub verbose: bool,
    /// Write commands: print the operations, send nothing
    #[arg(long, global = true, help_heading = "Output")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Referrals {
    Off,
    Follow,
}

/// Template arguments shared by commands that take DN or filter templates.
#[derive(Args, Debug, Clone, Default)]
pub struct TemplateArgs {
    /// Template value: name=VALUE (escaped for where {name} appears)
    #[arg(long = "arg", short = 'a', value_name = "NAME=VALUE")]
    pub arg: Vec<String>,
    /// Template value read from a file: name=PATH
    #[arg(long = "arg-file", value_name = "NAME=PATH")]
    pub arg_file: Vec<String>,
    /// Extra request control: OID[!][=b64:VALUE] (! = critical); repeatable
    #[arg(long = "control", value_name = "OID")]
    pub control: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Search the directory
    Search(SearchArgs),
    /// Add entries (from --dn/--attr or LDIF)
    Add(AddArgs),
    /// Modify entries (from --dn and operations, or LDIF)
    Modify(ModifyArgs),
    /// Delete entries
    Delete(DeleteArgs),
    /// Rename or move an entry
    Modrdn(ModrdnArgs),
    /// Compare an attribute value (exit 0 = true, 1 = false)
    Compare(CompareArgs),
    /// Send an extended operation
    Exop(ExopArgs),
    /// Show the identity the server sees for this bind
    Whoami(TemplateArgs),
    /// Change or reset a password (RFC 3062 or AD unicodePwd)
    Passwd(PasswdArgs),
    /// Escape a value for a filter or DN (no connection)
    #[command(subcommand)]
    Escape(EscapeCmd),
    /// Parse or build DNs (no connection)
    #[command(subcommand)]
    Dn(DnCmd),
    /// Show TLS details, the server chain and the RootDSE
    Probe(ProbeArgs),
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Search base (template)
    #[arg(short = 'b', long)]
    pub base: Option<String>,
    #[arg(short = 's', long, value_enum)]
    pub scope: Option<Scope>,
    /// Filter template
    #[arg(short = 'f', long, default_value = "(objectClass=*)")]
    pub filter: String,
    /// Skip filter syntax checking (placeholders are still escaped)
    #[arg(long)]
    pub raw_filter: bool,
    /// Attributes to return
    pub attrs: Vec<String>,
    #[arg(long, default_value_t = 0)]
    pub size_limit: u32,
    #[arg(long, default_value_t = 0)]
    pub time_limit: u32,
    /// Page size (0 disables paging)
    #[arg(long)]
    pub page_size: Option<u32>,
    /// Server-side sort: [-]attr[:rule][,…]
    #[arg(long, value_delimiter = ',')]
    pub sort: Vec<String>,
    #[arg(long, value_enum, default_value = "never")]
    pub deref: Deref,
    #[arg(long)]
    pub types_only: bool,
    /// AD range retrieval for large multi-valued attributes
    #[arg(long, value_enum, default_value = "auto")]
    pub range: RangeMode,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RangeMode {
    Auto,
    Off,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// DN template of the entry to add
    #[arg(long)]
    pub dn: Option<String>,
    /// Attribute as name=value (repeatable); name:=b64:VALUE for binary
    #[arg(long = "attr")]
    pub attrs: Vec<String>,
    /// LDIF input ('-' for stdin)
    #[arg(long)]
    pub file: Option<String>,
    #[arg(short = 'c', long)]
    pub continue_on_error: bool,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct ModifyArgs {
    /// DN template of the entry to modify
    #[arg(long)]
    pub dn: Option<String>,
    #[arg(long = "add", value_name = "ATTR=VALUE")]
    pub add: Vec<String>,
    #[arg(long = "replace", value_name = "ATTR=VALUE")]
    pub replace: Vec<String>,
    /// ATTR (all values) or ATTR=VALUE
    #[arg(long = "delete", value_name = "ATTR[=VALUE]")]
    pub delete: Vec<String>,
    #[arg(long = "increment", value_name = "ATTR=N")]
    pub increment: Vec<String>,
    /// LDIF input ('-' for stdin)
    #[arg(long)]
    pub file: Option<String>,
    #[arg(short = 'c', long)]
    pub continue_on_error: bool,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// DNs to delete (literal)
    pub dns: Vec<String>,
    /// DN template
    #[arg(long)]
    pub dn: Option<String>,
    /// Read DNs, one per line ('-' for stdin)
    #[arg(long)]
    pub file: Option<String>,
    /// Delete the whole subtree
    #[arg(long)]
    pub subtree: bool,
    #[arg(short = 'c', long)]
    pub continue_on_error: bool,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct ModrdnArgs {
    #[arg(long)]
    pub dn: String,
    /// New RDN template, e.g. 'CN={cn}'
    #[arg(long)]
    pub new_rdn: String,
    #[arg(long)]
    pub new_superior: Option<String>,
    #[arg(long)]
    pub keep_old_rdn: bool,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    #[arg(long)]
    pub dn: String,
    #[arg(long)]
    pub attr: String,
    /// Value to compare (b64:… for binary)
    #[arg(long)]
    pub value: String,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct ExopArgs {
    /// OID, or whoami | cancel | refresh
    pub op: String,
    /// Request value: b64:… (or a message ID for cancel, DN for refresh)
    #[arg(long)]
    pub value: Option<String>,
    /// TTL in seconds for refresh
    #[arg(long)]
    pub ttl: Option<u32>,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// Target DN template (default: the bound identity)
    #[arg(long)]
    pub dn: Option<String>,
    #[arg(long)]
    pub new_password_file: Option<String>,
    #[arg(long)]
    pub new_password_env: Option<String>,
    #[arg(long)]
    pub new_password_stdin: bool,
    /// Generate a random password of this length and print it
    #[arg(long)]
    pub generate: Option<usize>,
    /// Old password (makes this a user change rather than an admin reset)
    #[arg(long)]
    pub old_password_file: Option<String>,
    #[arg(long)]
    pub old_password_env: Option<String>,
    /// Prompt for the old password
    #[arg(long)]
    pub old_password_prompt: bool,
    #[arg(long, value_enum, default_value = "auto")]
    pub method: PasswdMethod,
    #[command(flatten)]
    pub t: TemplateArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PasswdMethod {
    Auto,
    Exop,
    Ad,
    Replace,
}

#[derive(Subcommand, Debug)]
pub enum EscapeCmd {
    /// RFC 4515 filter value escaping
    Filter { value: String },
    /// RFC 4514 DN value escaping
    Dn { value: String },
    /// Reverse RFC 4514 escaping
    UnescapeDn { value: String },
}

#[derive(Subcommand, Debug)]
pub enum DnCmd {
    /// Print the RDNs of a DN as JSON
    Parse { dn: String },
    /// Build a DN from a template with escaped values
    Build {
        template: String,
        #[command(flatten)]
        t: TemplateArgs,
    },
}

#[derive(Args, Debug)]
pub struct ProbeArgs {
    /// Print the top certificate of the server chain as base64 (for --ca-cert)
    #[arg(long)]
    pub print_ca: bool,
}
