//! Client certificates on Windows: the CurrentUser/LocalMachine "MY" store (CNG, smart
//! cards and TPM keys work natively through Schannel) or an inline PKCS#12 imported with
//! a non-persisted key.

use crate::error::{Error, Result};
use crate::model::{ClientIdentity, StoreLocation};
use sha2::Digest;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::*;

pub struct ClientCerts {
    store: HCERTSTORE,
    /// Candidates (owned contexts); `auto` picks among them using the server's CA list.
    pub candidates: Vec<*const CERT_CONTEXT>,
}

impl Drop for ClientCerts {
    fn drop(&mut self) {
        unsafe {
            for c in &self.candidates {
                CertFreeCertificateContext(*c);
            }
            if !self.store.is_null() {
                CertCloseStore(self.store, 0);
            }
        }
    }
}

const KEY_PROPS: [u32; 3] = [
    CERT_KEY_PROV_INFO_PROP_ID,
    CERT_KEY_CONTEXT_PROP_ID,
    CERT_NCRYPT_KEY_HANDLE_PROP_ID,
];

unsafe fn has_private_key(c: *const CERT_CONTEXT) -> bool {
    KEY_PROPS.iter().any(|p| {
        let mut n = 0u32;
        unsafe { CertGetCertificateContextProperty(c, *p, null_mut(), &mut n) != 0 }
    })
}

unsafe fn client_auth_usable(c: *const CERT_CONTEXT) -> bool {
    unsafe {
        let mut n = 0u32;
        if CertGetEnhancedKeyUsage(c, 0, null_mut(), &mut n) == 0 {
            return true; // no EKU extension: any usage
        }
        let mut buf = vec![0u8; n as usize];
        let u = buf.as_mut_ptr() as *mut CTL_USAGE;
        if CertGetEnhancedKeyUsage(c, 0, u, &mut n) == 0 {
            return false;
        }
        if (*u).cUsageIdentifier == 0 {
            return true;
        }
        (0..(*u).cUsageIdentifier as usize).any(|i| {
            let oid = std::ffi::CStr::from_ptr(*(*u).rgpszUsageIdentifier.add(i) as *const i8);
            oid.to_bytes() == b"1.3.6.1.5.5.7.3.2"
        })
    }
}

pub fn load(id: &ClientIdentity, location: StoreLocation) -> Result<Option<ClientCerts>> {
    unsafe {
        match id {
            ClientIdentity::None => Ok(None),
            ClientIdentity::Pkcs12 { der, password } => {
                let mut blob = CRYPT_INTEGER_BLOB {
                    cbData: der.bytes().len() as u32,
                    pbData: der.bytes().as_ptr() as *mut u8,
                };
                let pw: Vec<u16> = password
                    .as_str()?
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                // PKCS12_NO_PERSIST_KEY keeps the key in memory only.
                let store = PFXImportCertStore(
                    &mut blob,
                    pw.as_ptr(),
                    PKCS12_NO_PERSIST_KEY | CRYPT_USER_KEYSET,
                );
                let mut pw = pw;
                zeroize::Zeroize::zeroize(&mut pw);
                if store.is_null() {
                    return Err(Error::usage(
                        "cannot import the PKCS#12 (wrong password or invalid data)",
                    ));
                }
                let mut certs = ClientCerts {
                    store,
                    candidates: Vec::new(),
                };
                let mut c = CertEnumCertificatesInStore(store, null());
                while !c.is_null() {
                    if has_private_key(c) {
                        certs.candidates.push(CertDuplicateCertificateContext(c));
                    }
                    c = CertEnumCertificatesInStore(store, c);
                }
                if certs.candidates.is_empty() {
                    return Err(Error::usage(
                        "the PKCS#12 contains no certificate with a private key",
                    ));
                }
                Ok(Some(certs))
            }
            sel => {
                let loc = match location {
                    StoreLocation::User => CERT_SYSTEM_STORE_CURRENT_USER,
                    StoreLocation::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
                };
                let name: Vec<u16> = "MY\0".encode_utf16().collect();
                let store = CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    loc | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                    name.as_ptr() as *const _,
                );
                if store.is_null() {
                    return Err(Error::usage("cannot open the personal certificate store"));
                }
                let mut certs = ClientCerts {
                    store,
                    candidates: Vec::new(),
                };
                let mut c = CertEnumCertificatesInStore(store, null());
                while !c.is_null() {
                    let der = super::trust::cert_der(c);
                    let ok = has_private_key(c)
                        && match sel {
                            ClientIdentity::Thumbprint(t) => {
                                sha2::Sha256::digest(&der).as_slice() == t.as_slice()
                            }
                            ClientIdentity::Subject(s) => {
                                client_auth_usable(c)
                                    && super::trust::cert_subject(c)
                                        .to_lowercase()
                                        .contains(&s.to_lowercase())
                            }
                            ClientIdentity::Auto => client_auth_usable(c),
                            _ => false,
                        };
                    if ok {
                        certs.candidates.push(CertDuplicateCertificateContext(c));
                    }
                    c = CertEnumCertificatesInStore(store, c);
                }
                if certs.candidates.is_empty() {
                    return Err(Error::usage(
                        "no matching client certificate with a private key in the store",
                    ));
                }
                if matches!(sel, ClientIdentity::Subject(_)) && certs.candidates.len() > 1 {
                    let names: Vec<String> = certs
                        .candidates
                        .iter()
                        .map(|c| super::trust::cert_subject(*c))
                        .collect();
                    return Err(Error::usage(format!(
                        "{} certificates match ({}); use --client-cert sha256/…",
                        names.len(),
                        names.join(", ")
                    )));
                }
                Ok(Some(certs))
            }
        }
    }
}

/// Pick a candidate, preferring one issued by a CA the server asked for.
pub unsafe fn choose(certs: &ClientCerts, issuers: &[Vec<u8>]) -> Option<*const CERT_CONTEXT> {
    unsafe {
        if !issuers.is_empty() {
            for c in &certs.candidates {
                let iss = &(*(**c).pCertInfo).Issuer;
                let bytes = std::slice::from_raw_parts(iss.pbData, iss.cbData as usize);
                if issuers.iter().any(|i| i == bytes) {
                    return Some(*c);
                }
            }
        }
        certs.candidates.first().copied()
    }
}
