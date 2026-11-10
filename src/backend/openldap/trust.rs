//! Server certificate verification: OpenSSL hands the presented chain to us, and
//! Security.framework (SecTrust) decides using the system trust settings, the hostname,
//! revocation policy and any inline --ca-cert anchors. Returning 0 aborts the handshake.

use super::ffi::*;
use crate::model::{Revocation, TlsOptions};
use security_framework::certificate::SecCertificate;
use security_framework::policy::{RevocationPolicy, SecPolicy};
use security_framework::secure_transport::SslProtocolSide;
use security_framework::trust::SecTrust;
use std::ffi::{c_int, c_void};

pub struct VerifyState {
    pub hostname: String,
    pub anchors: Vec<SecCertificate>,
    pub revocation: Revocation,
    pub skip: bool,
    pub capture: bool,
    /// Filled by the callback.
    pub chain: Vec<(Vec<u8>, String)>,
    pub error: Option<String>,
}

impl VerifyState {
    pub fn new(tls: &TlsOptions, hostname: &str) -> crate::error::Result<Self> {
        let anchors = tls
            .ca_certs
            .iter()
            .map(|d| {
                SecCertificate::from_der(d).map_err(|e| {
                    crate::error::Error::usage(format!("--ca-cert is not a valid certificate: {e}"))
                })
            })
            .collect::<crate::error::Result<Vec<_>>>()?;
        Ok(VerifyState {
            hostname: tls
                .server_name
                .clone()
                .unwrap_or_else(|| hostname.to_string()),
            anchors,
            revocation: tls.revocation,
            skip: tls.insecure_skip_verify,
            capture: tls.capture_chain,
            chain: Vec::new(),
            error: None,
        })
    }
}

unsafe fn der(x: *const X509) -> Option<Vec<u8>> {
    unsafe {
        let n = i2d_X509(x, std::ptr::null_mut());
        if n <= 0 {
            return None;
        }
        let mut buf = vec![0u8; n as usize];
        let mut p = buf.as_mut_ptr();
        if i2d_X509(x, &mut p) != n {
            return None;
        }
        Some(buf)
    }
}

pub unsafe extern "C" fn verify_cb(ctx: *mut X509_STORE_CTX, arg: *mut c_void) -> c_int {
    let st = unsafe { &mut *(arg as *mut VerifyState) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        evaluate(ctx, st)
    }));
    match result {
        Ok(Ok(())) => 1,
        Ok(Err(msg)) => {
            st.error = Some(msg);
            unsafe { X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION) };
            0
        }
        Err(_) => {
            st.error = Some("internal error during certificate verification".into());
            unsafe { X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION) };
            0
        }
    }
}

unsafe fn evaluate(ctx: *mut X509_STORE_CTX, st: &mut VerifyState) -> Result<(), String> {
    // Collect the presented chain, leaf first, without duplicates.
    let mut ders: Vec<Vec<u8>> = Vec::new();
    unsafe {
        let leaf = X509_STORE_CTX_get0_cert(ctx);
        if leaf.is_null() {
            return Err("server presented no certificate".into());
        }
        ders.push(der(leaf).ok_or("cannot encode server certificate")?);
        let untrusted = X509_STORE_CTX_get0_untrusted(ctx);
        if !untrusted.is_null() {
            for i in 0..OPENSSL_sk_num(untrusted) {
                let x = OPENSSL_sk_value(untrusted, i) as *const X509;
                if let Some(d) = der(x) {
                    if !ders.contains(&d) {
                        ders.push(d);
                    }
                }
            }
        }
    }
    let certs: Vec<SecCertificate> = ders
        .iter()
        .map(|d| {
            SecCertificate::from_der(d).map_err(|e| format!("cannot parse server certificate: {e}"))
        })
        .collect::<Result<_, _>>()?;
    if st.capture {
        st.chain = ders
            .iter()
            .cloned()
            .zip(certs.iter().map(|c| c.subject_summary()))
            .collect();
    }
    if st.skip {
        return Ok(());
    }
    let mut policies = vec![SecPolicy::create_ssl(
        SslProtocolSide::SERVER,
        Some(&st.hostname),
    )];
    match st.revocation {
        Revocation::Off => {}
        Revocation::Soft => policies.push(
            SecPolicy::create_revocation(RevocationPolicy::USE_ANY_METHOD_AVAILABLE)
                .map_err(|e| format!("revocation policy: {e}"))?,
        ),
        Revocation::Hard => policies.push(
            SecPolicy::create_revocation(
                RevocationPolicy::USE_ANY_METHOD_AVAILABLE
                    | RevocationPolicy::REQUIRE_POSITIVE_RESPONSE,
            )
            .map_err(|e| format!("revocation policy: {e}"))?,
        ),
    }
    let mut trust = SecTrust::create_with_certificates(&certs, &policies)
        .map_err(|e| format!("SecTrust: {e}"))?;
    if !st.anchors.is_empty() {
        trust
            .set_anchor_certificates(&st.anchors)
            .map_err(|e| format!("SecTrust anchors: {e}"))?;
        // Keep the system anchors as well: --ca-cert adds trust, it does not replace it.
        trust
            .set_trust_anchor_certificates_only(false)
            .map_err(|e| format!("SecTrust anchors: {e}"))?;
    }
    trust.evaluate_with_error().map_err(|e| {
        format!(
            "certificate for '{}' rejected: {}",
            st.hostname,
            e.description()
        )
    })
}

/// Install the verifier on a fresh SSL_CTX. Peer certificates are mandatory regardless
/// of OpenLDAP's require_cert setting.
pub unsafe fn install(ctx: *mut SSL_CTX, st: *mut VerifyState) {
    unsafe {
        SSL_CTX_set_verify(
            ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            std::ptr::null(),
        );
        SSL_CTX_set_cert_verify_callback(ctx, verify_cb, st as *mut c_void);
    }
}
