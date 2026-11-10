//! Client certificates on macOS: inline PKCS#12, or a Keychain identity exported in memory.
//!
//! Non-exportable Keychain keys (Secure Enclave, smart cards, many MDM-issued identities)
//! need a Security.framework-backed OpenSSL provider, planned for v2.

use super::ffi::*;
use crate::error::{Error, Result};
use crate::model::{ClientIdentity, StoreLocation};
use crate::secret::Secret;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use sha2::Digest;
use std::ffi::{CString, c_long};
use std::sync::Once;

pub fn configure(
    ctx: *mut SSL_CTX,
    id: &ClientIdentity,
    store: StoreLocation,
    host: &str,
) -> Result<()> {
    match id {
        ClientIdentity::None => Ok(()),
        ClientIdentity::Pkcs12 { der, password } => unsafe {
            use_pkcs12(ctx, der.bytes(), password)
        },
        other => {
            let identity = find_identity(other, store, host)?;
            let (der, pass) = export(&identity)?;
            unsafe { use_pkcs12(ctx, der.bytes(), &pass) }
        }
    }
}

fn openssl_error() -> String {
    unsafe {
        let e = ERR_get_error();
        let mut buf = [0i8; 256];
        ERR_error_string_n(e, buf.as_mut_ptr(), buf.len());
        ERR_clear_error();
        std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

static LEGACY: Once = Once::new();

unsafe fn use_pkcs12(ctx: *mut SSL_CTX, der: &[u8], password: &Secret) -> Result<()> {
    let pass = CString::new(password.bytes().to_vec())
        .map_err(|_| Error::usage("PKCS#12 password contains NUL"))?;
    let parse = || unsafe {
        let mut p = der.as_ptr();
        let p12 = d2i_PKCS12(std::ptr::null_mut(), &mut p, der.len() as c_long);
        if p12.is_null() {
            return Err(Error::usage(format!(
                "client certificate is not valid PKCS#12: {}",
                openssl_error()
            )));
        }
        let (mut key, mut cert, mut ca) = (
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let ok = PKCS12_parse(p12, pass.as_ptr(), &mut key, &mut cert, &mut ca);
        PKCS12_free(p12);
        if ok != 1 || key.is_null() || cert.is_null() {
            return Err(Error::usage(format!(
                "cannot decrypt PKCS#12 (wrong password?): {}",
                openssl_error()
            )));
        }
        Ok((key, cert, ca))
    };
    let (key, cert, ca) = match parse() {
        Ok(v) => v,
        Err(_) => {
            // Older PKCS#12 files use RC2/3DES from the legacy provider.
            LEGACY.call_once(|| unsafe {
                OSSL_PROVIDER_load(std::ptr::null_mut(), c"legacy".as_ptr());
                OSSL_PROVIDER_load(std::ptr::null_mut(), c"default".as_ptr());
            });
            parse()?
        }
    };
    unsafe {
        let ok = SSL_CTX_use_certificate(ctx, cert) == 1
            && SSL_CTX_use_PrivateKey(ctx, key) == 1
            && SSL_CTX_check_private_key(ctx) == 1;
        if !ca.is_null() {
            for i in 0..OPENSSL_sk_num(ca) {
                // SSL_CTX_add1_chain_cert takes its own reference.
                SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, OPENSSL_sk_value(ca, i));
                X509_free(OPENSSL_sk_value(ca, i) as *mut X509);
            }
            OPENSSL_sk_free(ca);
        }
        X509_free(cert);
        EVP_PKEY_free(key);
        if !ok {
            return Err(Error::usage(format!(
                "client certificate and key do not match: {}",
                openssl_error()
            )));
        }
    }
    Ok(())
}

fn find_identity(sel: &ClientIdentity, store: StoreLocation, host: &str) -> Result<SecIdentity> {
    if let ClientIdentity::Auto = sel {
        // Identity preference set with: security set-identity-preference -s ldaps://host -c <name>
        for name in [format!("ldaps://{host}"), host.to_string()] {
            let cf = CFString::new(&name);
            let p = unsafe {
                SecIdentityCopyPreferred(
                    cf.as_concrete_TypeRef() as *const _,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            if !p.is_null() {
                return Ok(unsafe { SecIdentity::wrap_under_create_rule(p as *mut _) });
            }
        }
    }
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All);
    let system;
    if store == StoreLocation::Machine {
        system = security_framework::os::macos::keychain::SecKeychain::open(
            "/Library/Keychains/System.keychain",
        )
        .map_err(|e| Error::usage(format!("cannot open the System keychain: {e}")))?;
        opts.keychains(std::slice::from_ref(&system));
    }
    let found = opts.search().unwrap_or_default();
    let mut matches = Vec::new();
    for r in found {
        if let SearchResult::Ref(Reference::Identity(id)) = r {
            let Ok(cert) = id.certificate() else { continue };
            let ok = match sel {
                ClientIdentity::Thumbprint(t) => {
                    sha2::Sha256::digest(cert.to_der()).as_slice() == t.as_slice()
                }
                ClientIdentity::Subject(s) => cert
                    .subject_summary()
                    .to_lowercase()
                    .contains(&s.to_lowercase()),
                ClientIdentity::Auto => true,
                _ => false,
            };
            if ok {
                matches.push((id, cert.subject_summary()));
            }
        }
    }
    match matches.len() {
        0 => Err(Error::usage("no matching client identity in the Keychain")),
        1 => Ok(matches.pop().unwrap().0),
        _ if matches!(sel, ClientIdentity::Thumbprint(_)) => Ok(matches.pop().unwrap().0),
        _ => Err(Error::usage(format!(
            "{} Keychain identities match ({}); use --client-cert sha256/… to pick one",
            matches.len(),
            matches
                .iter()
                .map(|m| m.1.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Export an identity to PKCS#12 in memory under a random passphrase.
fn export(id: &SecIdentity) -> Result<(Secret, Secret)> {
    let mut raw = [0u8; 24];
    getrandom::fill(&mut raw).map_err(|e| Error::usage(format!("random: {e}")))?;
    let pass: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let cf_pass = CFString::new(&pass);
    let params = SecItemImportExportKeyParameters {
        version: 0,
        flags: 0,
        passphrase: cf_pass.as_concrete_TypeRef() as *const _,
        alert_title: std::ptr::null(),
        alert_prompt: std::ptr::null(),
        access_ref: std::ptr::null(),
        key_usage: std::ptr::null(),
        key_attributes: std::ptr::null(),
    };
    let mut out: *const std::ffi::c_void = std::ptr::null();
    let status = unsafe {
        SecItemExport(
            id.as_concrete_TypeRef() as *const _,
            K_SEC_FORMAT_PKCS12,
            0,
            &params,
            &mut out,
        )
    };
    if status != 0 || out.is_null() {
        return Err(Error::usage(format!(
            "cannot use this Keychain identity (OSStatus {status}): its private key is probably not exportable; \
             non-exportable keys are planned for v2 — meanwhile use --client-cert env:VAR with a PKCS#12"
        )));
    }
    let data = unsafe { CFData::wrap_under_create_rule(out as *const _) };
    Ok((
        Secret::new(data.bytes().to_vec()),
        Secret::new(pass.into_bytes()),
    ))
}
