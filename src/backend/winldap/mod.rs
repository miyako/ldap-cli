//! Windows backend: Wldap32 for the protocol, SSPI (Negotiate / Kerberos / NTLM) for
//! binds, Schannel for TLS, CryptoAPI for certificate decisions and client identities.

mod identity;
mod sasl;
mod trust;

use super::Session;
use crate::discovery::Srv;
use crate::error::{Error, Result};
use crate::model::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Networking::Ldap::*;
use windows_sys::Win32::Security::Authentication::Identity::{
    SEC_WINNT_AUTH_IDENTITY_EXW, SEC_WINNT_AUTH_IDENTITY_VERSION, SecPkgContext_ConnectionInfo,
    SecPkgContext_IssuerListInfoEx,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CertDuplicateCertificateContext, CertFreeCertificateContext,
};

const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 2;
const LDAP_OPT_ON: u32 = 1;
const LDAP_OPT_OFF: u32 = 0;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn from_w(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

unsafe fn take_w(p: *mut u16) -> String {
    let s = unsafe { from_w(p) };
    if !p.is_null() {
        unsafe { ldap_memfreeW(p) };
    }
    s
}

fn err_string(code: u32) -> String {
    unsafe { from_w(ldap_err2stringW(code)) }
}

fn is_transport_error(code: u32) -> bool {
    // LDAP_SERVER_DOWN, LDAP_TIMEOUT, LDAP_CONNECT_ERROR
    matches!(code, 0x51 | 0x55 | 0x5b)
}

// ---------------- per-connection state reachable from Wldap32 callbacks ----------------

struct CallbackState {
    verify: Option<trust::VerifyState>,
    client: Option<identity::ClientCerts>,
}

// Raw CERT_CONTEXT pointers are only used on the connecting thread.
unsafe impl Send for CallbackState {}

fn registry() -> &'static Mutex<HashMap<usize, Box<CallbackState>>> {
    static R: OnceLock<Mutex<HashMap<usize, Box<CallbackState>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

unsafe extern "system" fn verify_server(ld: *mut LDAP, pcert: *mut *mut CERT_CONTEXT) -> bool {
    let cert = unsafe { *pcert };
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let ok = match reg.get_mut(&(ld as usize)).and_then(|s| s.verify.as_mut()) {
        Some(st) => match unsafe { trust::evaluate(cert, st) } {
            Ok(()) => true,
            Err(e) => {
                st.error = Some(e);
                false
            }
        },
        None => false,
    };
    // The callback owns the certificate context.
    unsafe { CertFreeCertificateContext(cert) };
    ok
}

unsafe extern "system" fn query_client_cert(
    ld: *mut LDAP,
    cas: *mut SecPkgContext_IssuerListInfoEx,
    out: *mut *mut CERT_CONTEXT,
) -> bool {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(certs) = reg.get(&(ld as usize)).and_then(|s| s.client.as_ref()) else {
        return false;
    };
    let mut issuers = Vec::new();
    unsafe {
        if !cas.is_null() && !(*cas).aIssuers.is_null() {
            for i in 0..(*cas).cIssuers as usize {
                let b = &*(*cas).aIssuers.add(i);
                issuers.push(std::slice::from_raw_parts(b.pbData, b.cbData as usize).to_vec());
            }
        }
        match identity::choose(certs, &issuers) {
            Some(c) => {
                *out = CertDuplicateCertificateContext(c) as *mut _;
                true
            }
            None => false,
        }
    }
}

// ---------------- session ----------------

pub struct WinSession {
    ld: *mut LDAP,
    info: SessionInfo,
    timeout: u32,
}

impl Drop for WinSession {
    fn drop(&mut self) {
        unsafe { ldap_unbind(self.ld) };
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(self.ld as usize));
    }
}

impl WinSession {
    fn server_error(&self) -> String {
        let mut p: *mut u16 = null_mut();
        unsafe {
            ldap_get_optionW(
                self.ld,
                LDAP_OPT_SERVER_ERROR as i32,
                &mut p as *mut _ as *mut c_void,
            );
            take_w(p)
        }
    }

    fn result(&self, code: u32) -> Result<OpResult> {
        if is_transport_error(code) {
            return Err(Error::connect(
                format!("{} {}", err_string(code), self.server_error())
                    .trim()
                    .to_string(),
            ));
        }
        let message = if code == 0 {
            String::new()
        } else {
            self.server_error()
        };
        Ok(OpResult {
            code: code as i32,
            message,
            ..Default::default()
        })
    }

    fn tv(&self) -> LDAP_TIMEVAL {
        LDAP_TIMEVAL {
            tv_sec: self.timeout as i32,
            tv_usec: 0,
        }
    }

    fn set_u32(&self, opt: u32, v: u32) -> u32 {
        unsafe { ldap_set_optionW(self.ld, opt as i32, &v as *const u32 as *const c_void) }
    }

    fn verify_error(&self) -> Option<String> {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.get(&(self.ld as usize))
            .and_then(|s| s.verify.as_ref())
            .and_then(|v| v.error.clone())
    }
}

struct Ctrls {
    _oids: Vec<Vec<u16>>,
    _vals: Vec<Vec<u8>>,
    ctrls: Vec<LDAPControlW>,
    ptrs: Vec<*mut LDAPControlW>,
}

impl Ctrls {
    fn new(cs: &[Control]) -> Self {
        let mut oids: Vec<Vec<u16>> = cs.iter().map(|c| w(&c.oid)).collect();
        let mut vals: Vec<Vec<u8>> = cs
            .iter()
            .map(|c| c.value.clone().unwrap_or_default())
            .collect();
        let mut ctrls: Vec<LDAPControlW> = cs
            .iter()
            .enumerate()
            .map(|(i, c)| LDAPControlW {
                ldctl_oid: oids[i].as_mut_ptr(),
                ldctl_value: if c.value.is_some() {
                    LDAP_BERVAL {
                        bv_len: vals[i].len() as u32,
                        bv_val: vals[i].as_mut_ptr(),
                    }
                } else {
                    LDAP_BERVAL {
                        bv_len: 0,
                        bv_val: null_mut(),
                    }
                },
                ldctl_iscritical: c.critical,
            })
            .collect();
        let mut ptrs: Vec<*mut LDAPControlW> = ctrls.iter_mut().map(|c| c as *mut _).collect();
        ptrs.push(null_mut());
        Ctrls {
            _oids: oids,
            _vals: vals,
            ctrls,
            ptrs,
        }
    }
    fn ptr(&mut self) -> *mut *mut LDAPControlW {
        if self.ctrls.is_empty() {
            null_mut()
        } else {
            self.ptrs.as_mut_ptr()
        }
    }
}

unsafe fn take_controls(p: *mut *mut LDAPControlW) -> Vec<Control> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    unsafe {
        let mut i = 0;
        while !(*p.add(i)).is_null() {
            let c = &**p.add(i);
            out.push(Control {
                oid: from_w(c.ldctl_oid),
                critical: c.ldctl_iscritical,
                value: if c.ldctl_value.bv_val.is_null() {
                    None
                } else {
                    Some(
                        std::slice::from_raw_parts(
                            c.ldctl_value.bv_val,
                            c.ldctl_value.bv_len as usize,
                        )
                        .to_vec(),
                    )
                },
            });
            i += 1;
        }
        ldap_controls_freeW(p);
    }
    out
}

unsafe fn take_w_array(p: *mut *mut u16) -> Vec<String> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    unsafe {
        let mut i = 0;
        while !(*p.add(i)).is_null() {
            out.push(from_w(*p.add(i)));
            i += 1;
        }
        ldap_value_freeW(p as *const *const u16);
    }
    out
}

pub fn connect(opts: &ConnectOptions, t: &Target) -> Result<Box<dyn Session>> {
    let host = w(&t.host);
    let secure = (opts.tls.mode == TlsMode::Ldaps) as i32;
    let ld = unsafe { ldap_sslinitW(host.as_ptr(), t.port as u32, secure) };
    if ld.is_null() {
        return Err(Error::connect(format!(
            "ldap_sslinit: {}",
            err_string(unsafe { LdapGetLastError() })
        )));
    }
    let mut s = WinSession {
        ld,
        info: SessionInfo {
            host: t.host.clone(),
            port: t.port,
            ..Default::default()
        },
        timeout: opts.timeout,
    };
    s.set_u32(LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3);
    s.set_u32(
        LDAP_OPT_REFERRALS,
        if opts.referrals {
            LDAP_OPT_ON
        } else {
            LDAP_OPT_OFF
        },
    );

    // Callback state must exist before the TLS handshake.
    let strict = opts.auth.channel_binding == ChannelBinding::Require;
    let verify = if opts.tls.mode != TlsMode::None && (trust::needed(&opts.tls) || strict) {
        Some(trust::VerifyState::new(&opts.tls, &t.host))
    } else {
        None
    };
    let client = if opts.tls.mode != TlsMode::None {
        identity::load(&opts.tls.client, opts.tls.store)?
    } else {
        None
    };
    let (has_verify, has_client) = (verify.is_some(), client.is_some());
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(ld as usize, Box::new(CallbackState { verify, client }));
    unsafe {
        if has_verify {
            let cb: VERIFYSERVERCERT = Some(verify_server);
            let rc = ldap_set_optionW(
                ld,
                LDAP_OPT_SERVER_CERTIFICATE as i32,
                cb.map_or(null(), |f| f as *const c_void),
            );
            if rc != 0 {
                return Err(Error::connect(
                    "cannot install server certificate verification",
                ));
            }
        }
        if strict {
            for (option, value) in [
                (LDAP_OPT_AUTO_RECONNECT, LDAP_OPT_OFF),
                (LDAP_OPT_PROMPT_CREDENTIALS, LDAP_OPT_OFF),
            ] {
                if s.set_u32(option, value) != 0 {
                    return Err(Error::auth("strict SASL session options unavailable"));
                }
            }
        }
        if has_client {
            let cb: QUERYCLIENTCERT = Some(query_client_cert);
            ldap_set_optionW(
                ld,
                LDAP_OPT_CLIENT_CERTIFICATE as i32,
                cb.map_or(null(), |f| f as *const c_void),
            );
        }
    }
    match opts.auth.qos {
        Qos::Sign => {
            s.set_u32(LDAP_OPT_SIGN, LDAP_OPT_ON);
        }
        Qos::Seal => {
            s.set_u32(LDAP_OPT_SIGN, LDAP_OPT_ON);
            s.set_u32(LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
        }
        _ => {}
    }

    let mut ctv = LDAP_TIMEVAL {
        tv_sec: opts.connect_timeout as i32,
        tv_usec: 0,
    };
    let rc = unsafe { ldap_connect(ld, &mut ctv) };
    if rc != 0 {
        return Err(connect_error(&s, rc));
    }
    if opts.tls.mode == TlsMode::Starttls {
        let mut server_rc = 0u32;
        let mut res: *mut LDAPMessage = null_mut();
        let rc = unsafe { ldap_start_tls_sW(ld, &mut server_rc, &mut res, null_mut(), null_mut()) };
        if !res.is_null() {
            unsafe { ldap_msgfree(res) };
        }
        if rc != 0 {
            return Err(connect_error(
                &s,
                if server_rc != 0 { server_rc } else { rc },
            ));
        }
    }
    if opts.tls.mode != TlsMode::None {
        s.info.tls = true;
        let mut ci: SecPkgContext_ConnectionInfo = unsafe { std::mem::zeroed() };
        if unsafe {
            ldap_get_optionW(
                ld,
                LDAP_OPT_SSL_INFO as i32,
                &mut ci as *mut _ as *mut c_void,
            )
        } == 0
        {
            let v = match ci.dwProtocol {
                p if p & 0x2000 != 0 => Some("TLSv1.3"),
                p if p & 0x0800 != 0 => Some("TLSv1.2"),
                p if p & 0x0200 != 0 => Some("TLSv1.1"),
                p if p & 0x0080 != 0 => Some("TLSv1"),
                _ => None,
            };
            s.info.tls_version = v.map(str::to_string);
            let too_old = match (opts.tls.min, v) {
                (TlsMin::V1_3, Some(x)) => x != "TLSv1.3",
                (TlsMin::V1_2, Some(x)) => x == "TLSv1.1" || x == "TLSv1",
                _ => false,
            };
            if too_old {
                return Err(Error::connect(format!(
                    "server negotiated {} below --tls-min",
                    v.unwrap_or("?")
                )));
            }
        }
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = reg.get(&(ld as usize)).and_then(|x| x.verify.as_ref()) {
            s.info.peer_chain = v.chain.clone();
        }
    }
    bind(&mut s, opts)?;
    Ok(Box::new(s))
}

fn connect_error(s: &WinSession, rc: u32) -> Error {
    let mut msg = format!("{}:{}: {}", s.info.host, s.info.port, err_string(rc));
    if let Some(v) = s.verify_error() {
        msg = format!("{msg}: {v}");
    } else {
        let d = s.server_error();
        if !d.is_empty() {
            msg = format!("{msg}: {d}");
        }
    }
    Error::connect(msg)
}

fn packages(auth: &AuthOptions) -> &'static str {
    match (auth.mech, auth.allow_ntlm) {
        (Mech::Ntlm, _) => "NTLM",
        (Mech::Spnego, true) => "Kerberos,NTLM",
        _ => "Kerberos,!NTLM",
    }
}

fn bind(s: &mut WinSession, opts: &ConnectOptions) -> Result<()> {
    let a = &opts.auth;
    if a.channel_binding == ChannelBinding::Require {
        return sasl::bind(s, a);
    }
    let rc = match a.mech {
        Mech::Anonymous => return Ok(()),
        Mech::Simple => {
            let dn = w(a.bind_dn.as_deref().unwrap_or(""));
            let pw = a
                .password
                .as_ref()
                .ok_or_else(|| Error::usage("simple bind needs a password"))?;
            let mut pw = w(pw.as_str()?);
            let rc =
                unsafe { ldap_bind_sW(s.ld, dn.as_ptr(), pw.as_ptr(), LDAP_AUTH_SIMPLE as u32) };
            zeroize::Zeroize::zeroize(&mut pw);
            rc
        }
        Mech::Gssapi | Mech::Spnego | Mech::Ntlm => {
            // Package list: Kerberos only unless NTLM is requested or allowed.
            let mut pkg = w(packages(a));
            let (mut user, mut domain) = match a.user.as_deref() {
                Some(u) => match u.split_once('\\') {
                    Some((d, u)) => (w(u), w(d)),
                    None => (w(u), w(a.realm.as_deref().unwrap_or(""))),
                },
                None => (Vec::new(), Vec::new()),
            };
            let mut pw = match &a.password {
                Some(p) => w(p.as_str()?),
                None => Vec::new(),
            };
            let len = |v: &Vec<u16>| v.len().saturating_sub(1) as u32;
            let ptr = |v: &mut Vec<u16>| {
                if v.is_empty() {
                    null_mut()
                } else {
                    v.as_mut_ptr()
                }
            };
            let mut id = SEC_WINNT_AUTH_IDENTITY_EXW {
                Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
                Length: std::mem::size_of::<SEC_WINNT_AUTH_IDENTITY_EXW>() as u32,
                User: ptr(&mut user),
                UserLength: len(&user),
                Domain: ptr(&mut domain),
                DomainLength: len(&domain),
                Password: ptr(&mut pw),
                PasswordLength: len(&pw),
                Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
                PackageList: pkg.as_mut_ptr(),
                PackageListLength: len(&pkg),
            };
            let rc = unsafe {
                ldap_bind_sW(
                    s.ld,
                    null(),
                    &mut id as *mut _ as *const u16,
                    LDAP_AUTH_NEGOTIATE,
                )
            };
            zeroize::Zeroize::zeroize(&mut pw);
            rc
        }
        Mech::External => {
            let mech = w("EXTERNAL");
            let empty = w("");
            let cred = LDAP_BERVAL {
                bv_len: 0,
                bv_val: null_mut(),
            };
            let mut server: *mut LDAP_BERVAL = null_mut();
            let rc = unsafe {
                ldap_sasl_bind_sW(
                    s.ld,
                    empty.as_ptr(),
                    mech.as_ptr(),
                    &cred,
                    null_mut(),
                    null_mut(),
                    &mut server,
                )
            };
            if !server.is_null() {
                unsafe { ber_bvfree(server) };
            }
            rc as u32
        }
    };
    if rc == 0 {
        return Ok(());
    }
    if is_transport_error(rc) {
        return Err(connect_error(s, rc));
    }
    let diag = s.server_error();
    let mut msg = format!("{} ({rc})", err_string(rc));
    if !diag.is_empty() {
        msg = format!("{msg}: {diag}");
    }
    if rc == 8 {
        msg.push_str(" — the server requires signing or TLS (try ldaps:// or --sasl-qos sign)");
    }
    Err(Error::auth(msg))
}

struct Mods {
    _types: Vec<Vec<u16>>,
    _vals: Vec<Vec<Vec<u8>>>,
    _bvs: Vec<Vec<LDAP_BERVAL>>,
    _bvp: Vec<Vec<*mut LDAP_BERVAL>>,
    _mods: Vec<LDAPModW>,
    ptrs: Vec<*mut LDAPModW>,
}

impl Mods {
    fn new(items: &[(u32, &str, &[Vec<u8>])]) -> Self {
        let mut types: Vec<Vec<u16>> = items.iter().map(|(_, t, _)| w(t)).collect();
        let mut vals: Vec<Vec<Vec<u8>>> = items.iter().map(|(_, _, v)| v.to_vec()).collect();
        let mut bvs: Vec<Vec<LDAP_BERVAL>> = vals
            .iter_mut()
            .map(|vs| {
                vs.iter_mut()
                    .map(|v| LDAP_BERVAL {
                        bv_len: v.len() as u32,
                        bv_val: v.as_mut_ptr(),
                    })
                    .collect()
            })
            .collect();
        let mut bvp: Vec<Vec<*mut LDAP_BERVAL>> = bvs
            .iter_mut()
            .map(|b| {
                let mut p: Vec<*mut LDAP_BERVAL> = b.iter_mut().map(|x| x as *mut _).collect();
                p.push(null_mut());
                p
            })
            .collect();
        let mut mods: Vec<LDAPModW> = items
            .iter()
            .enumerate()
            .map(|(i, (op, _, v))| LDAPModW {
                mod_op: op | LDAP_MOD_BVALUES,
                mod_type: types[i].as_mut_ptr(),
                mod_vals: LDAPModW_0 {
                    modv_bvals: if v.is_empty() && *op == LDAP_MOD_DELETE {
                        null_mut()
                    } else {
                        bvp[i].as_mut_ptr()
                    },
                },
            })
            .collect();
        let mut ptrs: Vec<*mut LDAPModW> = mods.iter_mut().map(|m| m as *mut _).collect();
        ptrs.push(null_mut());
        Mods {
            _types: types,
            _vals: vals,
            _bvs: bvs,
            _bvp: bvp,
            _mods: mods,
            ptrs,
        }
    }
}

impl Session for WinSession {
    fn info(&self) -> SessionInfo {
        self.info.clone()
    }

    fn search(
        &mut self,
        req: &SearchRequest,
        controls: &[Control],
        on_entry: &mut dyn FnMut(Entry) -> Result<()>,
        on_reference: &mut dyn FnMut(Vec<String>) -> Result<()>,
    ) -> Result<OpResult> {
        let base = w(&req.base);
        let filter = w(&req.filter);
        let attr_w: Vec<Vec<u16>> = req.attrs.iter().map(|a| w(a)).collect();
        let mut attr_p: Vec<*const u16> = attr_w.iter().map(|a| a.as_ptr()).collect();
        attr_p.push(null());
        let mut ctrls = Ctrls::new(controls);
        let scope = match req.scope {
            Scope::Base => LDAP_SCOPE_BASE,
            Scope::One => LDAP_SCOPE_ONELEVEL,
            Scope::Sub => LDAP_SCOPE_SUBTREE,
            Scope::Children => 3,
        };
        self.set_u32(LDAP_OPT_DEREF, req.deref as u32);
        let mut tv = if req.time_limit > 0 {
            LDAP_TIMEVAL {
                tv_sec: req.time_limit as i32,
                tv_usec: 0,
            }
        } else {
            self.tv()
        };
        let mut res: *mut LDAPMessage = null_mut();
        let rc = unsafe {
            ldap_search_ext_sW(
                self.ld,
                base.as_ptr(),
                scope,
                filter.as_ptr(),
                if req.attrs.is_empty() {
                    null()
                } else {
                    attr_p.as_ptr()
                },
                req.types_only as u32,
                ctrls.ptr() as *const *const LDAPControlW,
                null(),
                &mut tv,
                req.size_limit,
                &mut res,
            )
        };
        if res.is_null() {
            return self.result(rc);
        }
        let out = (|| -> Result<OpResult> {
            unsafe {
                let mut e = ldap_first_entry(self.ld, res);
                while !e.is_null() {
                    on_entry(read_entry(self.ld, e))?;
                    e = ldap_next_entry(self.ld, e);
                }
                let mut r = ldap_first_reference(self.ld, res);
                while !r.is_null() {
                    let mut refs: *mut *mut u16 = null_mut();
                    ldap_parse_referenceW(self.ld, r, &mut refs);
                    on_reference(take_w_array(refs))?;
                    r = ldap_next_reference(self.ld, r);
                }
                let (mut code, mut matched, mut msg, mut refs, mut sctrls) =
                    (0u32, null_mut(), null_mut(), null_mut(), null_mut());
                let prc = ldap_parse_resultW(
                    self.ld,
                    res,
                    &mut code,
                    &mut matched,
                    &mut msg,
                    &mut refs,
                    &mut sctrls,
                    false,
                );
                if prc != 0 {
                    return self.result(if rc != 0 { rc } else { prc });
                }
                Ok(OpResult {
                    code: code as i32,
                    matched: take_w(matched),
                    message: take_w(msg),
                    controls: take_controls(sctrls),
                    referrals: take_w_array(refs),
                })
            }
        })();
        unsafe { ldap_msgfree(res) };
        out
    }

    fn add(&mut self, dn: &str, attrs: &super::Attrs, controls: &[Control]) -> Result<OpResult> {
        let dn = w(dn);
        let items: Vec<(u32, &str, &[Vec<u8>])> = attrs
            .iter()
            .map(|(a, v)| (LDAP_MOD_ADD, a.as_str(), v.as_slice()))
            .collect();
        let mut m = Mods::new(&items);
        let mut c = Ctrls::new(controls);
        let rc = unsafe {
            ldap_add_ext_sW(
                self.ld,
                dn.as_ptr(),
                m.ptrs.as_mut_ptr(),
                c.ptr(),
                null_mut(),
            )
        };
        self.result(rc)
    }

    fn modify(
        &mut self,
        dn: &str,
        mods: &[Modification],
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = w(dn);
        let items: Vec<(u32, &str, &[Vec<u8>])> = mods
            .iter()
            .map(|m| {
                let op = match m.op {
                    ModOp::Add => LDAP_MOD_ADD,
                    ModOp::Delete => LDAP_MOD_DELETE,
                    ModOp::Replace => LDAP_MOD_REPLACE,
                    ModOp::Increment => 3,
                };
                (op, m.attr.as_str(), m.values.as_slice())
            })
            .collect();
        let mut m = Mods::new(&items);
        let mut c = Ctrls::new(controls);
        let rc = unsafe {
            ldap_modify_ext_sW(
                self.ld,
                dn.as_ptr(),
                m.ptrs.as_mut_ptr(),
                c.ptr(),
                null_mut(),
            )
        };
        self.result(rc)
    }

    fn delete(&mut self, dn: &str, controls: &[Control]) -> Result<OpResult> {
        let dn = w(dn);
        let mut c = Ctrls::new(controls);
        let rc = unsafe { ldap_delete_ext_sW(self.ld, dn.as_ptr(), c.ptr(), null_mut()) };
        self.result(rc)
    }

    fn rename(
        &mut self,
        dn: &str,
        new_rdn: &str,
        new_superior: Option<&str>,
        delete_old: bool,
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = w(dn);
        let rdn = w(new_rdn);
        let sup = new_superior.map(w);
        let mut c = Ctrls::new(controls);
        let rc = unsafe {
            ldap_rename_ext_sW(
                self.ld,
                dn.as_ptr(),
                rdn.as_ptr(),
                sup.as_ref().map_or(null(), |s| s.as_ptr()),
                delete_old as i32,
                c.ptr(),
                null_mut(),
            )
        };
        self.result(rc)
    }

    fn compare(
        &mut self,
        dn: &str,
        attr: &str,
        value: &[u8],
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = w(dn);
        let attr = w(attr);
        let mut v = value.to_vec();
        let bv = LDAP_BERVAL {
            bv_len: v.len() as u32,
            bv_val: v.as_mut_ptr(),
        };
        let mut c = Ctrls::new(controls);
        let rc = unsafe {
            ldap_compare_ext_sW(
                self.ld,
                dn.as_ptr(),
                attr.as_ptr(),
                null(),
                &bv,
                c.ptr(),
                null_mut(),
            )
        };
        if rc == 5 || rc == 6 {
            return Ok(OpResult {
                code: rc as i32,
                ..Default::default()
            });
        }
        self.result(rc)
    }

    fn extended(
        &mut self,
        oid: &str,
        value: Option<&[u8]>,
        controls: &[Control],
    ) -> Result<ExtResult> {
        let oid = w(oid);
        let mut v = value.map(|v| v.to_vec());
        let mut bv = v.as_mut().map(|v| LDAP_BERVAL {
            bv_len: v.len() as u32,
            bv_val: v.as_mut_ptr(),
        });
        let mut c = Ctrls::new(controls);
        let mut retoid: *mut u16 = null_mut();
        let mut retdata: *mut LDAP_BERVAL = null_mut();
        let rc = unsafe {
            ldap_extended_operation_sW(
                self.ld,
                oid.as_ptr(),
                bv.as_mut().map_or(null_mut(), |b| b as *mut _),
                c.ptr(),
                null_mut(),
                &mut retoid,
                &mut retdata,
            )
        };
        let result = self.result(rc)?;
        let oid = if retoid.is_null() {
            None
        } else {
            Some(unsafe { take_w(retoid) })
        };
        let value = if retdata.is_null() {
            None
        } else {
            unsafe {
                let b = &*retdata;
                let v = if b.bv_val.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(b.bv_val, b.bv_len as usize).to_vec()
                };
                ber_bvfree(retdata);
                Some(v)
            }
        };
        Ok(ExtResult { result, oid, value })
    }
}

unsafe fn read_entry(ld: *mut LDAP, e: *mut LDAPMessage) -> Entry {
    unsafe {
        let dn = take_w(ldap_get_dnW(ld, e));
        let mut attrs = Vec::new();
        let mut ber: *mut BerElement = null_mut();
        let mut a = ldap_first_attributeW(ld, e, &mut ber);
        while !a.is_null() {
            let name = from_w(a);
            let vals = ldap_get_values_lenW(ld, e, a);
            let mut vs = Vec::new();
            if !vals.is_null() {
                let mut i = 0;
                while !(*vals.add(i)).is_null() {
                    let b = &**vals.add(i);
                    vs.push(if b.bv_val.is_null() {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(b.bv_val, b.bv_len as usize).to_vec()
                    });
                    i += 1;
                }
                ldap_value_free_len(vals);
            }
            attrs.push((name, vs));
            ldap_memfreeW(a);
            a = ldap_next_attributeW(ld, e, ber);
        }
        if !ber.is_null() {
            ber_free(ber, 0);
        }
        Entry { dn, attrs }
    }
}

// ---------------- discovery ----------------

pub fn query_srv(name: &str) -> Result<Vec<Srv>> {
    use windows_sys::Win32::NetworkManagement::Dns::*;
    let n = w(name);
    let mut rec: *mut DNS_RECORDW = null_mut();
    let rc = unsafe {
        DnsQuery_W(
            n.as_ptr(),
            DNS_TYPE_SRV,
            DNS_QUERY_STANDARD,
            null_mut(),
            &mut rec as *mut _ as *mut *mut DNS_RECORDA,
            null_mut(),
        )
    };
    if rc != 0 {
        return Ok(Vec::new()); // NXDOMAIN / no records: not an error for discovery
    }
    let mut out = Vec::new();
    let mut p = rec;
    unsafe {
        while !p.is_null() {
            if (*p).wType == DNS_TYPE_SRV {
                let srv = &(*p).Data.SRV;
                out.push(Srv {
                    priority: srv.wPriority,
                    weight: srv.wWeight,
                    port: srv.wPort,
                    target: from_w(srv.pNameTarget),
                });
            }
            p = (*p).pNext;
        }
        DnsFree(rec as *const c_void, DnsFreeRecordList);
    }
    Ok(out)
}

pub fn preferred_dc(domain: &str, site: Option<&str>, gc: bool) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
    use windows_sys::Win32::Networking::ActiveDirectory::*;
    let d = w(domain);
    let s = site.map(w);
    let mut flags = DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME | DS_TRY_NEXTCLOSEST_SITE;
    if gc {
        flags |= DS_GC_SERVER_REQUIRED;
    }
    let mut info: *mut DOMAIN_CONTROLLER_INFOW = null_mut();
    let rc = unsafe {
        DsGetDcNameW(
            null(),
            d.as_ptr(),
            null(),
            s.as_ref().map_or(null(), |x| x.as_ptr()),
            flags,
            &mut info,
        )
    };
    if rc != 0 || info.is_null() {
        return None;
    }
    let name = unsafe { from_w((*info).DomainControllerName) };
    unsafe { NetApiBufferFree(info as *const c_void) };
    Some(name.trim_start_matches('\\').to_string())
}
