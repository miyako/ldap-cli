//! Server certificate verification for Wldap32, used only when the default Schannel
//! decision must be changed: inline --ca-cert anchors, --revocation off/hard,
//! --insecure-skip-verify, or chain capture for `probe`. The callback owns the decision,
//! so it repeats chain building, the SSL policy (with hostname) and revocation checks.

use crate::model::{Revocation, TlsOptions};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::*;

pub struct VerifyState {
    pub hostname: String,
    pub anchors: Vec<Vec<u8>>,
    pub revocation: Revocation,
    pub skip: bool,
    pub chain: Vec<(Vec<u8>, String)>,
    pub error: Option<String>,
}

impl VerifyState {
    pub fn new(tls: &TlsOptions, host: &str) -> Self {
        VerifyState {
            hostname: tls.server_name.clone().unwrap_or_else(|| host.to_string()),
            anchors: tls.ca_certs.clone(),
            revocation: tls.revocation,
            skip: tls.insecure_skip_verify,
            chain: Vec::new(),
            error: None,
        }
    }
}

/// Whether the default Schannel verification is enough.
pub fn needed(tls: &TlsOptions) -> bool {
    !tls.ca_certs.is_empty()
        || tls.insecure_skip_verify
        || tls.capture_chain
        || tls.revocation != Revocation::Soft
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub unsafe fn cert_der(c: *const CERT_CONTEXT) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((*c).pbCertEncoded, (*c).cbCertEncoded as usize).to_vec() }
}

pub unsafe fn cert_subject(c: *const CERT_CONTEXT) -> String {
    unsafe {
        let n = CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), null_mut(), 0);
        let mut buf = vec![0u16; n as usize];
        CertGetNameStringW(
            c,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            buf.as_mut_ptr(),
            n,
        );
        String::from_utf16_lossy(&buf[..buf.len().saturating_sub(1)])
    }
}

/// Evaluate the server certificate. Returns Ok(()) to accept.
pub unsafe fn evaluate(cert: *const CERT_CONTEXT, st: &mut VerifyState) -> Result<(), String> {
    unsafe {
        // Extra store: the certificates the server sent plus inline anchors.
        let extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, null());
        if extra.is_null() {
            return Err("cannot create certificate store".into());
        }
        let mut c = CertEnumCertificatesInStore((*cert).hCertStore, null());
        while !c.is_null() {
            CertAddCertificateContextToStore(extra, c, CERT_STORE_ADD_USE_EXISTING, null_mut());
            c = CertEnumCertificatesInStore((*cert).hCertStore, c);
        }
        for a in &st.anchors {
            CertAddEncodedCertificateToStore(
                extra,
                X509_ASN_ENCODING,
                a.as_ptr(),
                a.len() as u32,
                CERT_STORE_ADD_USE_EXISTING,
                null_mut(),
            );
        }

        let mut server_auth = szOID_PKIX_KP_SERVER_AUTH as *mut u8;
        let mut para: CERT_CHAIN_PARA = std::mem::zeroed();
        para.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = &mut server_auth;
        let flags = match st.revocation {
            Revocation::Off => 0,
            _ => CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        };
        let mut chain: *mut CERT_CHAIN_CONTEXT = null_mut();
        let ok = CertGetCertificateChain(
            null_mut(),
            cert,
            null(),
            extra,
            &para,
            flags,
            null(),
            &mut chain as *mut _ as *mut *mut CERT_CHAIN_CONTEXT,
        );
        let result = if ok == 0 || chain.is_null() {
            Err("cannot build the certificate chain".to_string())
        } else {
            let r = check_chain(chain, st);
            CertFreeCertificateChain(chain);
            r
        };
        CertCloseStore(extra, 0);
        result
    }
}

unsafe fn check_chain(
    chain: *const CERT_CHAIN_CONTEXT,
    st: &mut VerifyState,
) -> Result<(), String> {
    unsafe {
        let simple = *(*chain).rgpChain;
        let n = (*simple).cElement as usize;
        st.chain.clear();
        for i in 0..n {
            let el = *(*simple).rgpElement.add(i);
            let cc = (*el).pCertContext;
            st.chain.push((cert_der(cc), cert_subject(cc)));
        }
        if st.skip {
            return Ok(());
        }
        let status = (*chain).TrustStatus.dwErrorStatus;
        let mut checks = 0u32;
        if status & CERT_TRUST_IS_UNTRUSTED_ROOT != 0 {
            // Accept an untrusted root only if it is byte-identical to an inline anchor
            // and nothing else is wrong with the chain.
            let root = &st.chain.last().ok_or("empty chain")?.0;
            let others = status
                & !(CERT_TRUST_IS_UNTRUSTED_ROOT
                    | CERT_TRUST_REVOCATION_STATUS_UNKNOWN
                    | CERT_TRUST_IS_OFFLINE_REVOCATION);
            if st.anchors.iter().any(|a| a == root) && others == 0 {
                checks |= 0x100; // SECURITY_FLAG_IGNORE_UNKNOWN_CA
            } else {
                return Err(format!(
                    "certificate for '{}' chains to an untrusted root",
                    st.hostname
                ));
            }
        }
        let mut name = wide(&st.hostname);
        let mut ssl: HTTPSPolicyCallbackData = std::mem::zeroed();
        ssl.Anonymous.cbSize = std::mem::size_of::<HTTPSPolicyCallbackData>() as u32;
        ssl.dwAuthType = 2; // AUTHTYPE_SERVER
        ssl.fdwChecks = checks;
        ssl.pwszServerName = name.as_mut_ptr();
        let mut pp: CERT_CHAIN_POLICY_PARA = std::mem::zeroed();
        pp.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
        pp.dwFlags = match st.revocation {
            Revocation::Soft => CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS,
            _ => 0,
        };
        pp.pvExtraPolicyPara = &mut ssl as *mut _ as *mut c_void;
        let mut ps: CERT_CHAIN_POLICY_STATUS = std::mem::zeroed();
        ps.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
        if CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &mut ps) == 0 {
            return Err("certificate policy check failed".into());
        }
        if ps.dwError != 0 {
            return Err(format!(
                "certificate for '{}' rejected (0x{:08X}: {})",
                st.hostname,
                ps.dwError,
                describe(ps.dwError)
            ));
        }
        Ok(())
    }
}

fn describe(e: u32) -> &'static str {
    match e {
        0x800B010F => "name mismatch",
        0x800B0101 => "expired or not yet valid",
        0x800B0109 => "untrusted root",
        0x800B010C => "revoked",
        0x80092012 | 0x80092013 => "revocation status unknown",
        0x800B0110 => "wrong certificate usage",
        _ => "see Windows certificate error codes",
    }
}
