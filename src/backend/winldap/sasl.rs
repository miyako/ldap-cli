//! Strict TLS SASL: supply CBT to SSPI ourselves rather than relying on
//! Wldap32's implicit channel-binding behaviour.

use super::{WinSession, connect_error, from_w, is_transport_error, w};
use crate::error::{Error, Result};
use crate::model::{AuthOptions, Mech};
use std::ffi::{CStr, c_void};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Networking::Ldap::*;
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::Security::Cryptography::*;
use zeroize::Zeroizing;

struct Context {
    cred: SecHandle,
    context: SecHandle,
    have_cred: bool,
    have_context: bool,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if self.have_context {
                DeleteSecurityContext(&self.context);
            }
            if self.have_cred {
                FreeCredentialsHandle(&self.cred);
            }
        }
    }
}

struct Token(*mut c_void);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeContextBuffer(self.0) };
        }
    }
}

fn sspi_error(stage: &str, status: i32) -> Error {
    let hint = match status as u32 {
        0x80090346 => " (channel binding rejected)",
        0x8009030c => " (logon denied; check credentials and account policy)",
        0x80090302 => " (authentication function unsupported)",
        _ => "",
    };
    Error::auth(format!("{stage}: SSPI 0x{:08x}{hint}", status as u32))
}

fn endpoint(der: &[u8]) -> Result<Vec<u8>> {
    let cert =
        unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as u32) };
    if cert.is_null() {
        return Err(Error::auth("channel binding: invalid TLS certificate"));
    }
    let oid = unsafe { CStr::from_ptr((*(*cert).pCertInfo).SignatureAlgorithm.pszObjId.cast()) };
    // RFC 5929 substitutes SHA-256 for MD5/SHA-1. Unknown algorithms
    // (including RSA-PSS parameters) fail closed, never guess a digest.
    let algorithm = match oid.to_bytes() {
        b"1.2.840.113549.1.1.4"
        | b"1.2.840.113549.1.1.5"
        | b"1.2.840.10045.4.1"
        | b"1.2.840.10040.4.3"
        | b"1.2.840.113549.1.1.11"
        | b"1.2.840.10045.4.3.2"
        | b"2.16.840.1.101.3.4.3.2" => Some("SHA256"),
        b"1.2.840.113549.1.1.12" | b"1.2.840.10045.4.3.3" => Some("SHA384"),
        b"1.2.840.113549.1.1.13" | b"1.2.840.10045.4.3.4" => Some("SHA512"),
        _ => None,
    };
    unsafe { CertFreeCertificateContext(cert) };
    let algorithm = w(algorithm
        .ok_or_else(|| Error::auth("channel binding: unsupported certificate signature digest"))?);
    let mut digest = [0u8; 64];
    let mut size = digest.len() as u32;
    if unsafe {
        CryptHashCertificate2(
            algorithm.as_ptr(),
            0,
            null(),
            der.as_ptr(),
            der.len() as u32,
            digest.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        return Err(Error::auth("channel binding: certificate digest failed"));
    }
    let mut application = b"tls-server-end-point:".to_vec();
    application.extend_from_slice(&digest[..size as usize]);
    // SEC_CHANNEL_BINDINGS is eight ULONGs followed by the application data.
    // Serializing each field avoids casting potentially unaligned byte storage.
    let fields = [0u32, 0, 0, 0, 0, 0, application.len() as u32, 32];
    let mut binding = Vec::with_capacity(32 + application.len());
    for field in fields {
        binding.extend_from_slice(&field.to_ne_bytes());
    }
    binding.extend_from_slice(&application);
    Ok(binding)
}

fn check_package(context: &Context, auth: &AuthOptions) -> Result<()> {
    let mut info = SecPkgContext_NegotiationInfoW::default();
    let status = unsafe {
        QueryContextAttributesW(
            &context.context,
            SECPKG_ATTR_NEGOTIATION_INFO,
            &mut info as *mut _ as *mut c_void,
        )
    };
    if status != 0 {
        return Err(sspi_error(
            "verify negotiated authentication package",
            status,
        ));
    }
    if info.PackageInfo.is_null() {
        return Err(Error::auth("SSPI did not report an authentication package"));
    }
    let package = unsafe { from_w((*info.PackageInfo).Name) };
    unsafe { FreeContextBuffer(info.PackageInfo.cast()) };
    let allowed = match auth.mech {
        Mech::Gssapi => package.eq_ignore_ascii_case("Kerberos"),
        Mech::Ntlm => package.eq_ignore_ascii_case("NTLM"),
        Mech::Spnego => {
            package.eq_ignore_ascii_case("Kerberos")
                || (auth.allow_ntlm && package.eq_ignore_ascii_case("NTLM"))
        }
        _ => false,
    };
    if !allowed {
        return Err(Error::auth(format!(
            "SSPI negotiated {package}, outside the configured authentication policy"
        )));
    }
    if package.eq_ignore_ascii_case("Kerberos") {
        let mut flags = SecPkgContext_Flags::default();
        let status = unsafe {
            QueryContextAttributesW(
                &context.context,
                SECPKG_ATTR_FLAGS,
                &mut flags as *mut _ as *mut c_void,
            )
        };
        if status != 0 {
            return Err(sspi_error("verify Kerberos mutual authentication", status));
        }
        if flags.Flags & ISC_RET_MUTUAL_AUTH == 0 {
            return Err(Error::auth(
                "SSPI did not negotiate Kerberos mutual authentication",
            ));
        }
    }
    Ok(())
}

pub(super) fn bind(session: &WinSession, auth: &AuthOptions) -> Result<()> {
    let der = &session
        .info
        .peer_chain
        .first()
        .ok_or_else(|| Error::auth("channel binding: verified TLS certificate unavailable"))?
        .0;
    let mut binding = endpoint(der)?;
    let mut context = Context {
        cred: unsafe { std::mem::zeroed() },
        context: unsafe { std::mem::zeroed() },
        have_cred: false,
        have_context: false,
    };
    let (mut user, mut domain) = match auth.user.as_deref() {
        Some(u) => match u.split_once('\\') {
            Some((d, u)) => (w(u), w(d)),
            None => (w(u), w(auth.realm.as_deref().unwrap_or(""))),
        },
        None => (Vec::new(), Vec::new()),
    };
    let mut password = Zeroizing::new(match &auth.password {
        Some(p) => w(p.as_str()?),
        None => Vec::new(),
    });
    let mut packages = w(super::packages(auth));
    let mut identity = SEC_WINNT_AUTH_IDENTITY_EXW {
        Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
        Length: std::mem::size_of::<SEC_WINNT_AUTH_IDENTITY_EXW>() as u32,
        User: if user.is_empty() {
            null_mut()
        } else {
            user.as_mut_ptr()
        },
        UserLength: user.len().saturating_sub(1) as u32,
        Domain: if domain.is_empty() {
            null_mut()
        } else {
            domain.as_mut_ptr()
        },
        DomainLength: domain.len().saturating_sub(1) as u32,
        Password: if password.is_empty() {
            null_mut()
        } else {
            password.as_mut_ptr()
        },
        PasswordLength: password.len().saturating_sub(1) as u32,
        Flags: 2,
        PackageList: packages.as_mut_ptr(),
        PackageListLength: packages.len().saturating_sub(1) as u32,
    };
    let package = w("Negotiate");
    let status = unsafe {
        AcquireCredentialsHandleW(
            null(),
            package.as_ptr(),
            SECPKG_CRED_OUTBOUND,
            null(),
            &mut identity as *mut _ as *mut c_void,
            None,
            null(),
            &mut context.cred,
            null_mut(),
        )
    };
    if status != 0 {
        return Err(sspi_error("acquire credentials", status));
    }
    context.have_cred = true;
    let target = w(&format!("ldap/{}", session.info.host));
    let mechanism = w("GSS-SPNEGO");
    let mut server = Vec::<u8>::new();
    let mut ldap_complete = false;
    for _ in 0..16 {
        let mut inputs = [
            SecBuffer {
                cbBuffer: binding.len() as u32,
                BufferType: SECBUFFER_CHANNEL_BINDINGS,
                pvBuffer: binding.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: server.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: server.as_mut_ptr().cast(),
            },
        ];
        let input = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: if server.is_empty() { 1 } else { 2 },
            pBuffers: inputs.as_mut_ptr(),
        };
        let mut output = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: null_mut(),
        };
        let mut outputs = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output,
        };
        let mut attributes = 0;
        let status = unsafe {
            InitializeSecurityContextW(
                &context.cred,
                if context.have_context {
                    &context.context
                } else {
                    null()
                },
                target.as_ptr(),
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONNECTION,
                0,
                SECURITY_NETWORK_DREP,
                &input,
                0,
                &mut context.context,
                &mut outputs,
                &mut attributes,
                null_mut(),
            )
        };
        let _token = Token(output.pvBuffer);
        context.have_context |= context.context.dwLower != 0 || context.context.dwUpper != 0;
        if status != 0 && status as u32 != 0x00090312 {
            return Err(sspi_error("SASL token exchange", status));
        }
        context.have_context = true;
        if ldap_complete {
            if status == 0 && output.cbBuffer == 0 {
                return check_package(&context, auth);
            }
            return Err(Error::auth(
                "server completed before SSPI authentication completed",
            ));
        }
        let token = LDAP_BERVAL {
            bv_len: output.cbBuffer,
            bv_val: output.pvBuffer.cast(),
        };
        let mut reply: *mut LDAP_BERVAL = null_mut();
        let rc = unsafe {
            ldap_sasl_bind_sW(
                session.ld,
                null(),
                mechanism.as_ptr(),
                &token,
                null_mut(),
                null_mut(),
                &mut reply,
            )
        } as u32;
        server.clear();
        if !reply.is_null() {
            unsafe {
                if (*reply).bv_len > 0 && !(*reply).bv_val.is_null() {
                    server.extend_from_slice(std::slice::from_raw_parts(
                        (*reply).bv_val,
                        (*reply).bv_len as usize,
                    ));
                }
                ber_bvfree(reply);
            }
        }
        if is_transport_error(rc) {
            return Err(connect_error(session, rc));
        }
        if rc != 0 && rc != 14 {
            return Err(Error::auth(format!(
                "{} ({rc}): {}",
                super::err_string(rc),
                session.server_error()
            )));
        }
        if rc == 0 {
            if status == 0 && server.is_empty() {
                return check_package(&context, auth);
            }
            ldap_complete = true;
        }
    }
    Err(Error::auth("SASL token exchange exceeded 16 steps"))
}
