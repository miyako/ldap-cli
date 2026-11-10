//! Turns command-line options and profile settings into validated connection options.
//! All security rules that do not depend on the platform live here.

use crate::cli::{Global, Referrals};
use crate::config::Profile;
use crate::discovery;
use crate::error::{Error, Result};
use crate::model::*;
use crate::secret::{self, Secret, Source, StdinGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUri {
    pub secure: bool,
    pub host: String,
    pub port: Option<u16>,
}

pub fn parse_uri(uri: &str) -> Result<ParsedUri> {
    let (secure, rest) = if let Some(r) = uri.strip_prefix("ldaps://") {
        (true, r)
    } else if let Some(r) = uri.strip_prefix("ldap://") {
        (false, r)
    } else {
        return Err(Error::usage(format!(
            "'{uri}': URI must start with ldap:// or ldaps://"
        )));
    };
    let hostport = rest.split('/').next().unwrap_or("");
    if rest.len() > hostport.len() + 1 {
        return Err(Error::usage(format!(
            "'{uri}': DNs in URIs are not supported; use --base"
        )));
    }
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, after) = h
            .split_once(']')
            .ok_or_else(|| Error::usage(format!("'{uri}': unclosed '['")))?;
        (h.to_string(), after.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(Error::usage(format!("'{uri}': missing host")));
    }
    let port = match port {
        Some(p) => Some(
            p.parse::<u16>()
                .map_err(|_| Error::usage(format!("'{uri}': invalid port")))?,
        ),
        None => None,
    };
    Ok(ParsedUri { secure, host, port })
}

/// Resolve the bind mechanism's security layer and check the combination.
pub fn resolve_qos(mech: Mech, tls: TlsMode, requested: Qos) -> Result<Qos> {
    let sasl = matches!(mech, Mech::Gssapi | Mech::Spnego | Mech::Ntlm);
    match (requested, tls) {
        (Qos::Auto, TlsMode::None) if sasl => Ok(Qos::Seal),
        (Qos::Auto, _) => Ok(Qos::Auth),
        (Qos::Sign | Qos::Seal, TlsMode::Ldaps | TlsMode::Starttls) => Err(Error::usage(
            "--sasl-qos sign/seal cannot be combined with TLS (Active Directory rejects a SASL layer on a TLS connection, and TLS already protects the session); use --sasl-qos auto",
        )),
        (Qos::Sign | Qos::Seal, TlsMode::None) if !sasl => Err(Error::usage(
            "--sasl-qos sign/seal applies only to gssapi, spnego and ntlm",
        )),
        (q, _) => Ok(q),
    }
}

pub struct Resolved {
    pub connect: ConnectOptions,
}

/// Build connection options. `need_password_prompt` is false for commands that
/// never bind (none today; kept for clarity).
pub fn resolve(g: &Global, p: &Profile, stdin: &mut StdinGuard) -> Result<Resolved> {
    // ---- TLS mode and targets ----
    let uris: Vec<String> = if !g.uri.is_empty() {
        g.uri.clone()
    } else {
        p.uri.clone().unwrap_or_default()
    };
    let domain = g.domain.clone().or(p.domain.clone());
    let parsed: Vec<ParsedUri> = uris.iter().map(|u| parse_uri(u)).collect::<Result<_>>()?;
    let scheme_mode = match parsed
        .iter()
        .map(|u| u.secure)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
    {
        0 => None,
        1 => Some(if parsed[0].secure {
            TlsMode::Ldaps
        } else {
            TlsMode::Starttls
        }),
        _ => {
            return Err(Error::usage(
                "mixing ldap:// and ldaps:// URIs is not supported",
            ));
        }
    };
    let tls_mode = match (g.tls.or(p.tls), scheme_mode) {
        (Some(TlsMode::Ldaps), Some(TlsMode::Starttls)) => {
            return Err(Error::usage(
                "--tls ldaps conflicts with an ldap:// URI; use ldaps://",
            ));
        }
        (Some(TlsMode::Starttls | TlsMode::None), Some(TlsMode::Ldaps)) => {
            return Err(Error::usage(
                "--tls starttls/none conflicts with an ldaps:// URI; use ldap://",
            ));
        }
        (Some(m), _) => m,
        (None, Some(m)) => m,
        (None, None) => TlsMode::Ldaps,
    };
    if tls_mode == TlsMode::None && !g.allow_plaintext {
        return Err(Error::usage("--tls none requires --allow-plaintext"));
    }
    let gc = g.gc || p.gc.unwrap_or(false);
    let default_port = match (tls_mode, gc) {
        (TlsMode::Ldaps, false) => 636,
        (TlsMode::Ldaps, true) => 3269,
        (_, false) => 389,
        (_, true) => 3268,
    };
    let targets = if !parsed.is_empty() {
        if g.domain.is_some() {
            return Err(Error::usage("use either --uri or --domain, not both"));
        }
        parsed
            .iter()
            .map(|u| Target {
                host: u.host.clone(),
                port: u.port.unwrap_or(default_port),
            })
            .collect()
    } else if let Some(d) = &domain {
        let site = g.site.clone().or(p.site.clone());
        discovery::locate(d, site.as_deref(), gc, default_port, g.allow_foreign_dc)?
    } else {
        return Err(Error::usage(
            "no server given: use --uri, --domain or a profile",
        ));
    };

    // ---- trust ----
    let mut ca_certs = Vec::new();
    let mut ca_src: Vec<String> = g.ca_cert.clone();
    if ca_src.is_empty() {
        ca_src = p.ca_certs.clone().unwrap_or_default();
    }
    if let Ok(env) = std::env::var("LDAP_CA_CERTS") {
        ca_src.extend(env.split_whitespace().map(str::to_string));
    }
    for c in &ca_src {
        let der = secret::decode_base64_lenient(c.as_bytes())?;
        if der.first() != Some(&0x30) || der.len() < 64 {
            return Err(Error::usage(
                "--ca-cert value does not look like a DER certificate",
            ));
        }
        ca_certs.push(der);
    }
    if g.insecure_skip_verify {
        eprintln!(
            "WARNING: --insecure-skip-verify: the server certificate is NOT verified; credentials can be intercepted"
        );
    }

    // ---- client identity ----
    let client = match g.client_cert.clone().or(p.client_cert.clone()) {
        None => ClientIdentity::None,
        Some(sel) => parse_client_cert(&sel, g, stdin)?,
    };

    // ---- authentication ----
    let bind_dn = g.bind_dn.clone().or(p.bind_dn.clone());
    let user = g.user.clone().or(p.user.clone());
    let mech = g.mech.or(p.mech).unwrap_or(if bind_dn.is_some() {
        Mech::Simple
    } else {
        Mech::Anonymous
    });
    let qos = resolve_qos(
        mech,
        tls_mode,
        g.sasl_qos.or(p.sasl_qos).unwrap_or(Qos::Auto),
    )?;
    let channel_binding = g
        .channel_binding
        .or(p.channel_binding)
        .unwrap_or(ChannelBinding::Auto);
    let referrals = g.referrals.or(p.referrals).unwrap_or(Referrals::Off) == Referrals::Follow;

    if channel_binding == ChannelBinding::Require && tls_mode == TlsMode::None {
        return Err(Error::usage("--channel-binding require needs TLS"));
    }
    if cfg!(windows) && (g.ccache.is_some() || g.authzid.is_some()) {
        return Err(Error::usage(
            "--ccache and --authzid are not used on Windows (SSPI uses your logon session or --user)",
        ));
    }
    let pw_source = password_source(g, p, stdin)?;
    let password = match mech {
        Mech::Anonymous => {
            if bind_dn.is_some() || pw_source.is_some() {
                return Err(Error::usage("anonymous bind takes no bind DN or password"));
            }
            None
        }
        Mech::Simple => {
            if tls_mode == TlsMode::None {
                return Err(Error::usage(
                    "simple bind over a plaintext connection is refused; use ldaps:// or StartTLS",
                ));
            }
            if referrals {
                return Err(Error::usage(
                    "--referrals follow is not allowed with simple bind (it would resend the password)",
                ));
            }
            let dn = bind_dn
                .as_deref()
                .ok_or_else(|| Error::usage("simple bind needs --bind-dn"))?;
            if dn.is_empty() {
                return Err(Error::usage("empty bind DN; use --mech anonymous"));
            }
            Some(secret::read_password(
                &pw_source.unwrap_or(Source::Prompt(format!("Password for {dn}"))),
            )?)
        }
        Mech::Gssapi | Mech::Spnego | Mech::Ntlm => {
            if mech == Mech::Ntlm && !cfg!(windows) {
                return Err(Error::usage("--mech ntlm is only supported on Windows"));
            }
            if bind_dn.is_some() {
                return Err(Error::usage(
                    "--bind-dn is for simple bind; use --user for SASL/NTLM identities",
                ));
            }
            if cfg!(windows) {
                match (&user, pw_source) {
                    (Some(u), src) => Some(secret::read_password(
                        &src.unwrap_or(Source::Prompt(format!("Password for {u}"))),
                    )?),
                    (None, Some(_)) => return Err(Error::usage("a password needs --user")),
                    (None, None) => None, // logged-in user via SSPI
                }
            } else {
                if pw_source.is_some() {
                    return Err(Error::usage(
                        "on macOS, GSSAPI uses your Kerberos tickets; run 'kinit user@REALM' instead of passing a password",
                    ));
                }
                None
            }
        }
        Mech::External => {
            if tls_mode == TlsMode::None {
                return Err(Error::usage("--mech external needs TLS"));
            }
            if matches!(client, ClientIdentity::None) {
                return Err(Error::usage("--mech external needs --client-cert"));
            }
            if pw_source.is_some() || bind_dn.is_some() {
                return Err(Error::usage("--mech external takes no bind DN or password"));
            }
            None
        }
    };

    let connect = ConnectOptions {
        targets,
        tls: TlsOptions {
            mode: tls_mode,
            ca_certs,
            server_name: g.tls_server_name.clone().or(p.tls_server_name.clone()),
            min: g.tls_min.or(p.tls_min).unwrap_or(TlsMin::V1_2),
            revocation: g.revocation.or(p.revocation).unwrap_or(Revocation::Soft),
            insecure_skip_verify: g.insecure_skip_verify,
            client,
            store: g.cert_store.or(p.cert_store).unwrap_or(StoreLocation::User),
            capture_chain: false,
        },
        auth: AuthOptions {
            mech,
            bind_dn,
            user,
            realm: g.realm.clone().or(p.realm.clone()),
            authzid: g.authzid.clone(),
            password,
            ccache: g.ccache.clone(),
            qos,
            channel_binding,
            allow_ntlm: g.allow_ntlm || p.allow_ntlm.unwrap_or(false),
        },
        connect_timeout: g.connect_timeout.or(p.connect_timeout).unwrap_or(10),
        timeout: g.timeout.or(p.timeout).unwrap_or(60),
        referrals,
        verbose: g.verbose,
    };
    Ok(Resolved { connect })
}

fn password_source(g: &Global, p: &Profile, stdin: &mut StdinGuard) -> Result<Option<Source>> {
    let n = [
        g.password_file.is_some(),
        g.password_stdin,
        g.password_env.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if n > 1 {
        return Err(Error::usage(
            "give at most one of --password-file, --password-stdin, --password-env",
        ));
    }
    Ok(if let Some(f) = &g.password_file {
        Some(Source::File(f.clone()))
    } else if g.password_stdin {
        stdin.claim("--password-stdin")?;
        Some(Source::Stdin)
    } else if let Some(v) = g.password_env.clone().or(p.password_env.clone()) {
        Some(Source::Env(v))
    } else {
        None
    })
}

fn parse_client_cert(sel: &str, g: &Global, stdin: &mut StdinGuard) -> Result<ClientIdentity> {
    let pkcs12 = |src: Source, stdin: &mut StdinGuard| -> Result<ClientIdentity> {
        let raw = secret::read(&src)?;
        let der = Secret::new(secret::decode_base64_lenient(raw.bytes())?);
        let password = if let Some(v) = &g.client_cert_password_env {
            secret::read(&Source::Env(v.clone()))?
        } else if g.client_cert_password_stdin {
            stdin.claim("--client-cert-password-stdin")?;
            secret::read(&Source::Stdin)?
        } else {
            Secret::new(Vec::new())
        };
        Ok(ClientIdentity::Pkcs12 { der, password })
    };
    if let Some(hex) = sel.strip_prefix("sha256/") {
        let hex: String = hex.chars().filter(|c| *c != ':').collect();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::usage("--client-cert sha256/ needs 64 hex digits"));
        }
        let bytes = (0..32)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        Ok(ClientIdentity::Thumbprint(bytes))
    } else if let Some(s) = sel.strip_prefix("subject:") {
        Ok(ClientIdentity::Subject(s.to_string()))
    } else if sel == "auto" {
        Ok(ClientIdentity::Auto)
    } else if let Some(var) = sel.strip_prefix("env:") {
        pkcs12(Source::Env(var.to_string()), stdin)
    } else if sel == "stdin" {
        stdin.claim("--client-cert stdin")?;
        pkcs12(Source::Stdin, stdin)
    } else if sel.starts_with("file:") || std::path::Path::new(sel).exists() {
        Err(Error::usage(
            "certificate files are not supported; use the OS store/Keychain, env:VAR or stdin",
        ))
    } else {
        Err(Error::usage(format!(
            "invalid --client-cert '{sel}': use sha256/HEX, subject:…, auto, env:VAR or stdin"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> Global {
        Global {
            uri: vec!["ldaps://dc1.corp.example".into()],
            ..Default::default()
        }
    }
    fn run(g: &Global) -> Result<Resolved> {
        resolve(g, &Profile::default(), &mut StdinGuard::default())
    }

    #[test]
    fn uris() {
        assert_eq!(
            parse_uri("ldaps://h").unwrap(),
            ParsedUri {
                secure: true,
                host: "h".into(),
                port: None
            }
        );
        assert_eq!(parse_uri("ldap://[::1]:3389").unwrap().port, Some(3389));
        assert_eq!(parse_uri("ldap://[::1]").unwrap().host, "::1");
        assert!(parse_uri("http://h").is_err());
        assert!(parse_uri("ldap://h/dc=x").is_err());
        assert!(parse_uri("ldap://h:x").is_err());
    }

    #[test]
    fn defaults_and_ports() {
        let r = run(&g()).unwrap();
        assert_eq!(r.connect.tls.mode, TlsMode::Ldaps);
        assert_eq!(r.connect.targets[0].port, 636);
        assert_eq!(r.connect.auth.mech, Mech::Anonymous);
        let mut x = g();
        x.uri = vec!["ldap://h".into()];
        let r = run(&x).unwrap();
        assert_eq!(
            (r.connect.tls.mode, r.connect.targets[0].port),
            (TlsMode::Starttls, 389)
        );
    }

    #[test]
    fn plaintext_rules() {
        let mut x = g();
        x.uri = vec!["ldap://h".into()];
        x.tls = Some(TlsMode::None);
        assert!(run(&x).is_err(), "needs --allow-plaintext");
        x.allow_plaintext = true;
        assert!(run(&x).is_ok());
        x.bind_dn = Some("cn=a".into());
        unsafe { std::env::set_var("LDAP_CLI_T_PW", "pw") };
        x.password_env = Some("LDAP_CLI_T_PW".into());
        assert!(run(&x).is_err(), "simple over plaintext refused");
    }

    #[test]
    fn simple_bind_password_rules() {
        let mut x = g();
        x.bind_dn = Some("cn=a,dc=x".into());
        unsafe { std::env::set_var("LDAP_CLI_T_EMPTY", "") };
        x.password_env = Some("LDAP_CLI_T_EMPTY".into());
        assert!(run(&x).is_err(), "empty password rejected");
        unsafe { std::env::set_var("LDAP_CLI_T_PW2", "pw") };
        x.password_env = Some("LDAP_CLI_T_PW2".into());
        let r = run(&x).unwrap();
        assert_eq!(r.connect.auth.mech, Mech::Simple);
        x.referrals = Some(Referrals::Follow);
        assert!(run(&x).is_err(), "no referral chasing with simple bind");
    }

    #[test]
    fn qos() {
        assert_eq!(
            resolve_qos(Mech::Gssapi, TlsMode::Ldaps, Qos::Auto).unwrap(),
            Qos::Auth
        );
        assert_eq!(
            resolve_qos(Mech::Gssapi, TlsMode::None, Qos::Auto).unwrap(),
            Qos::Seal
        );
        assert!(resolve_qos(Mech::Gssapi, TlsMode::Starttls, Qos::Seal).is_err());
        assert!(resolve_qos(Mech::Simple, TlsMode::None, Qos::Sign).is_err());
        assert_eq!(
            resolve_qos(Mech::Spnego, TlsMode::None, Qos::Sign).unwrap(),
            Qos::Sign
        );
    }

    #[test]
    fn mismatched_tls_and_scheme() {
        let mut x = g();
        x.tls = Some(TlsMode::Starttls);
        assert!(run(&x).is_err());
        x.uri = vec!["ldaps://a".into(), "ldap://b".into()];
        x.tls = None;
        assert!(run(&x).is_err());
    }

    #[test]
    fn client_cert_selectors() {
        let mut x = g();
        x.client_cert = Some(format!("sha256/{}", "ab".repeat(32)));
        assert!(matches!(
            run(&x).unwrap().connect.tls.client,
            ClientIdentity::Thumbprint(_)
        ));
        x.client_cert = Some("/etc/hosts".into());
        assert!(run(&x).is_err(), "files rejected");
        x.client_cert = Some("sha256/xyz".into());
        assert!(run(&x).is_err());
        x.client_cert = None;
        x.mech = Some(Mech::External);
        assert!(run(&x).is_err(), "external needs a client cert");
    }

    #[test]
    fn ntlm_platform() {
        let mut x = g();
        x.mech = Some(Mech::Ntlm);
        assert_eq!(run(&x).is_ok(), cfg!(windows));
    }

    #[test]
    fn ca_cert_validation() {
        let mut x = g();
        x.ca_cert = vec!["aGVsbG8=".into()];
        assert!(run(&x).is_err());
    }
}
