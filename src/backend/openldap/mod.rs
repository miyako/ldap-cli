//! macOS backend: OpenLDAP 2.6 (vendored, static) + system Cyrus SASL (GSSAPI via
//! GSS.framework) + OpenSSL 3 for the TLS channel, with Security.framework deciding trust.

mod ffi;
mod identity;
mod trust;

use super::Session;
use crate::discovery::Srv;
use crate::error::{Error, Result};
use crate::model::*;
use ffi::*;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr::{null, null_mut};

pub struct OlSession {
    ld: *mut LDAP,
    _verify: Box<trust::VerifyState>,
    info: SessionInfo,
    timeout: u32,
}

impl Drop for OlSession {
    fn drop(&mut self) {
        unsafe { ldap_unbind_ext_s(self.ld, null_mut(), null_mut()) };
    }
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::usage(format!("'{s}' contains a NUL character")))
}

unsafe fn take_string(p: *mut c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { ldap_memfree(p as *mut c_void) };
    s
}

fn err_string(code: c_int) -> String {
    unsafe { CStr::from_ptr(ldap_err2string(code)) }
        .to_string_lossy()
        .into_owned()
}

impl OlSession {
    fn diag(&self) -> (String, String) {
        unsafe {
            let mut d: *mut c_char = null_mut();
            let mut m: *mut c_char = null_mut();
            ldap_get_option(
                self.ld,
                LDAP_OPT_DIAGNOSTIC_MESSAGE,
                &mut d as *mut _ as *mut c_void,
            );
            ldap_get_option(
                self.ld,
                LDAP_OPT_MATCHED_DN,
                &mut m as *mut _ as *mut c_void,
            );
            (take_string(d), take_string(m))
        }
    }

    fn sync_result(&self, code: c_int) -> Result<OpResult> {
        if is_transport_error(code) {
            return Err(Error::connect(
                format!("{} {}", err_string(code), self.diag().0)
                    .trim()
                    .to_string(),
            ));
        }
        let (message, matched) = if code == 0 {
            (String::new(), String::new())
        } else {
            self.diag()
        };
        Ok(OpResult {
            code,
            message,
            matched,
            ..Default::default()
        })
    }

    fn tv(&self) -> libc::timeval {
        libc::timeval {
            tv_sec: self.timeout as _,
            tv_usec: 0,
        }
    }
}

fn is_transport_error(code: c_int) -> bool {
    matches!(code, LDAP_SERVER_DOWN | LDAP_CONNECT_ERROR | LDAP_TIMEOUT)
}

// ---------------- controls ----------------

struct CtrlArray {
    _oids: Vec<CString>,
    _vals: Vec<Vec<u8>>,
    ctrls: Vec<LDAPControl>,
    ptrs: Vec<*mut LDAPControl>,
}

impl CtrlArray {
    fn new(controls: &[Control]) -> Result<Self> {
        let oids: Vec<CString> = controls
            .iter()
            .map(|c| cstr(&c.oid))
            .collect::<Result<_>>()?;
        let mut vals: Vec<Vec<u8>> = controls
            .iter()
            .map(|c| c.value.clone().unwrap_or_default())
            .collect();
        let mut ctrls: Vec<LDAPControl> = controls
            .iter()
            .enumerate()
            .map(|(i, c)| LDAPControl {
                ldctl_oid: oids[i].as_ptr() as *mut c_char,
                ldctl_value: if c.value.is_some() {
                    berval {
                        bv_len: vals[i].len() as _,
                        bv_val: vals[i].as_mut_ptr() as *mut c_char,
                    }
                } else {
                    berval {
                        bv_len: 0,
                        bv_val: null_mut(),
                    }
                },
                ldctl_iscritical: c.critical as c_char,
            })
            .collect();
        let mut ptrs: Vec<*mut LDAPControl> = ctrls.iter_mut().map(|c| c as *mut _).collect();
        ptrs.push(null_mut());
        Ok(CtrlArray {
            _oids: oids,
            _vals: vals,
            ctrls,
            ptrs,
        })
    }
    fn as_ptr(&mut self) -> *mut *mut LDAPControl {
        if self.ctrls.is_empty() {
            null_mut()
        } else {
            self.ptrs.as_mut_ptr()
        }
    }
}

unsafe fn take_controls(p: *mut *mut LDAPControl) -> Vec<Control> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    unsafe {
        let mut i = 0;
        while !(*p.add(i)).is_null() {
            let c = &**p.add(i);
            let v = &c.ldctl_value;
            out.push(Control {
                oid: CStr::from_ptr(c.ldctl_oid).to_string_lossy().into_owned(),
                critical: c.ldctl_iscritical != 0,
                value: if v.bv_val.is_null() {
                    None
                } else {
                    Some(
                        std::slice::from_raw_parts(v.bv_val as *const u8, v.bv_len as usize)
                            .to_vec(),
                    )
                },
            });
            i += 1;
        }
        ldap_controls_free(p);
    }
    out
}

unsafe fn take_strings(p: *mut *mut c_char) -> Vec<String> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    unsafe {
        let mut i = 0;
        while !(*p.add(i)).is_null() {
            out.push(CStr::from_ptr(*p.add(i)).to_string_lossy().into_owned());
            i += 1;
        }
        ldap_memvfree(p as *mut *mut c_void);
    }
    out
}

// ---------------- SASL ----------------

struct SaslDefaults {
    authcid: Option<CString>,
    realm: Option<CString>,
    authzid: Option<CString>,
}

unsafe extern "C" fn interact(
    _ld: *mut LDAP,
    _flags: c_uint,
    defaults: *mut c_void,
    list: *mut c_void,
) -> c_int {
    let d = unsafe { &*(defaults as *const SaslDefaults) };
    let mut p = list as *mut sasl_interact_t;
    unsafe {
        while (*p).id != SASL_CB_LIST_END {
            let v = match (*p).id {
                SASL_CB_AUTHNAME => d.authcid.as_ref(),
                SASL_CB_GETREALM => d.realm.as_ref(),
                SASL_CB_USER => d.authzid.as_ref(),
                SASL_CB_PASS => None,
                _ => None,
            };
            match v {
                Some(s) => {
                    (*p).result = s.as_ptr() as *const c_void;
                    (*p).len = s.as_bytes().len() as c_uint;
                }
                None => {
                    (*p).result = c"".as_ptr() as *const c_void;
                    (*p).len = 0;
                }
            }
            p = p.add(1);
        }
    }
    0
}

// ---------------- connect & bind ----------------

pub fn connect(opts: &ConnectOptions, t: &Target) -> Result<Box<dyn Session>> {
    let host = if t.host.contains(':') {
        format!("[{}]", t.host)
    } else {
        t.host.clone()
    };
    let scheme = if opts.tls.mode == TlsMode::Ldaps {
        "ldaps"
    } else {
        "ldap"
    };
    let uri = cstr(&format!("{scheme}://{host}:{}", t.port))?;
    let mut ld: *mut LDAP = null_mut();
    let rc = unsafe { ldap_initialize(&mut ld, uri.as_ptr()) };
    if rc != 0 || ld.is_null() {
        return Err(Error::connect(format!(
            "ldap_initialize: {}",
            err_string(rc)
        )));
    }
    let mut s = OlSession {
        ld,
        _verify: Box::new(trust::VerifyState::new(&opts.tls, &t.host)?),
        info: SessionInfo {
            host: t.host.clone(),
            port: t.port,
            ..Default::default()
        },
        timeout: opts.timeout,
    };
    unsafe {
        let v3: c_int = LDAP_VERSION3;
        ldap_set_option(
            ld,
            LDAP_OPT_PROTOCOL_VERSION,
            &v3 as *const _ as *const c_void,
        );
        ldap_set_option(
            ld,
            LDAP_OPT_REFERRALS,
            if opts.referrals {
                LDAP_OPT_ON
            } else {
                LDAP_OPT_OFF
            },
        );
        let ntv = libc::timeval {
            tv_sec: opts.connect_timeout as _,
            tv_usec: 0,
        };
        ldap_set_option(
            ld,
            LDAP_OPT_NETWORK_TIMEOUT,
            &ntv as *const _ as *const c_void,
        );
        let otv = libc::timeval {
            tv_sec: opts.timeout as _,
            tv_usec: 0,
        };
        ldap_set_option(ld, LDAP_OPT_TIMEOUT, &otv as *const _ as *const c_void);
    }

    if opts.tls.mode != TlsMode::None {
        unsafe {
            // SecTrust (installed below) is the single authority for chain, hostname and
            // revocation. ALLOW turns off OpenLDAP's own hostname check, which differs from
            // SecTrust (it substitutes the machine name for "localhost" and cannot honour
            // --tls-server-name). trust::install re-imposes SSL_VERIFY_PEER |
            // FAIL_IF_NO_PEER_CERT, so a server without a certificate is still rejected.
            let req: c_int = LDAP_OPT_X_TLS_ALLOW;
            ldap_set_option(
                ld,
                LDAP_OPT_X_TLS_REQUIRE_CERT,
                &req as *const _ as *const c_void,
            );
            let min: c_int = match opts.tls.min {
                TlsMin::V1_2 => 0x0303,
                TlsMin::V1_3 => 0x0304,
            };
            ldap_set_option(
                ld,
                LDAP_OPT_X_TLS_PROTOCOL_MIN,
                &min as *const _ as *const c_void,
            );
            let is_server: c_int = 0;
            let rc = ldap_set_option(
                ld,
                LDAP_OPT_X_TLS_NEWCTX,
                &is_server as *const _ as *const c_void,
            );
            if rc != 0 {
                return Err(Error::connect(format!("TLS context: {}", err_string(rc))));
            }
            let mut ctx: *mut SSL_CTX = null_mut();
            ldap_get_option(ld, LDAP_OPT_X_TLS_CTX, &mut ctx as *mut _ as *mut c_void);
            if ctx.is_null() {
                return Err(Error::connect("TLS context unavailable"));
            }
            // The Box keeps the state at a stable address for the life of the session.
            trust::install(ctx, &mut *s._verify);
            identity::configure(ctx, &opts.tls.client, opts.tls.store, &t.host)?;
        }
    }
    let rc = unsafe { ldap_connect(ld) };
    if rc != 0 {
        return Err(connect_error(&s, rc));
    }
    if opts.tls.mode == TlsMode::Starttls {
        let rc = unsafe { ldap_start_tls_s(ld, null_mut(), null_mut()) };
        if rc != 0 {
            return Err(connect_error(&s, rc));
        }
    }
    if opts.tls.mode != TlsMode::None {
        s.info.tls = true;
        unsafe {
            let mut ssl: *mut SSL = null_mut();
            ldap_get_option(
                ld,
                LDAP_OPT_X_TLS_SSL_CTX,
                &mut ssl as *mut _ as *mut c_void,
            );
            if !ssl.is_null() {
                s.info.tls_version = Some(
                    CStr::from_ptr(SSL_get_version(ssl))
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        s.info.peer_chain = s._verify.chain.clone();
    }
    bind(&mut s, opts)?;
    Ok(Box::new(s))
}

fn connect_error(s: &OlSession, rc: c_int) -> Error {
    let (diag, _) = s.diag();
    let mut msg = format!("{}:{}: {}", s.info.host, s.info.port, err_string(rc));
    if let Some(v) = &s._verify.error {
        msg = format!("{msg}: {v}");
    } else if !diag.is_empty() {
        msg = format!("{msg}: {diag}");
    }
    if rc == 2 || rc == 52 || rc == 53 {
        // StartTLS refused by the server.
        return Error::connect(format!("{msg} (StartTLS refused; try ldaps://)"));
    }
    Error::connect(msg)
}

fn bind(s: &mut OlSession, opts: &ConnectOptions) -> Result<()> {
    let a = &opts.auth;
    let ld = s.ld;
    let rc = match a.mech {
        Mech::Anonymous => return Ok(()),
        Mech::Simple => {
            let dn = cstr(a.bind_dn.as_deref().unwrap_or(""))?;
            let pw = a
                .password
                .as_ref()
                .ok_or_else(|| Error::usage("simple bind needs a password"))?;
            let mut buf = pw.bytes().to_vec();
            let mut cred = berval {
                bv_len: buf.len() as _,
                bv_val: buf.as_mut_ptr() as *mut c_char,
            };
            let rc = unsafe {
                ldap_sasl_bind_s(
                    ld,
                    dn.as_ptr(),
                    null(),
                    &mut cred,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            zeroize::Zeroize::zeroize(&mut buf);
            rc
        }
        Mech::Gssapi | Mech::Spnego | Mech::External => {
            if let Some(cc) = &a.ccache {
                // Single-threaded at this point.
                unsafe { std::env::set_var("KRB5CCNAME", cc) };
            }
            let secprops = match a.qos {
                Qos::Auth | Qos::Auto => "maxssf=0",
                Qos::Sign => "minssf=1,maxssf=1",
                Qos::Seal => "minssf=56",
            };
            let secprops = cstr(secprops)?;
            unsafe {
                ldap_set_option(
                    ld,
                    LDAP_OPT_X_SASL_SECPROPS,
                    secprops.as_ptr() as *const c_void,
                );
                ldap_set_option(ld, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON);
                if s.info.tls
                    && a.channel_binding != ChannelBinding::None
                    && a.mech != Mech::External
                {
                    let cb: c_int = LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT;
                    let rc = ldap_set_option(
                        ld,
                        LDAP_OPT_X_SASL_CBINDING,
                        &cb as *const _ as *const c_void,
                    );
                    if rc != 0 && a.channel_binding == ChannelBinding::Require {
                        return Err(Error::auth("channel binding could not be enabled"));
                    }
                }
            }
            let mech = cstr(match a.mech {
                Mech::Gssapi => "GSSAPI",
                Mech::Spnego => "GSS-SPNEGO",
                _ => "EXTERNAL",
            })?;
            let mut d = SaslDefaults {
                authcid: a.user.as_deref().map(cstr).transpose()?,
                realm: a.realm.as_deref().map(cstr).transpose()?,
                authzid: a.authzid.as_deref().map(cstr).transpose()?,
            };
            unsafe {
                ldap_sasl_interactive_bind_s(
                    ld,
                    null(),
                    mech.as_ptr(),
                    null_mut(),
                    null_mut(),
                    LDAP_SASL_QUIET,
                    interact,
                    &mut d as *mut _ as *mut c_void,
                )
            }
        }
        Mech::Ntlm => return Err(Error::usage("--mech ntlm is only supported on Windows")),
    };
    if rc == 0 {
        return Ok(());
    }
    if is_transport_error(rc) {
        return Err(connect_error(s, rc));
    }
    let (diag, _) = s.diag();
    let mut msg = format!("{} ({rc})", err_string(rc));
    if !diag.is_empty() {
        msg = format!("{msg}: {diag}");
    }
    if matches!(a.mech, Mech::Gssapi | Mech::Spnego)
        && (diag.contains("credentials") || diag.contains("ticket") || rc == -2)
    {
        msg.push_str(" — do you have a Kerberos ticket? (klist / kinit user@REALM)");
    }
    Err(Error::auth(msg))
}

// ---------------- operations ----------------

struct Mods {
    _types: Vec<CString>,
    _vals: Vec<Vec<Vec<u8>>>,
    _bvs: Vec<Vec<berval>>,
    _bvptrs: Vec<Vec<*mut berval>>,
    _mods: Vec<LDAPMod>,
    ptrs: Vec<*mut LDAPMod>,
}

impl Mods {
    fn new(items: &[(c_int, &str, &[Vec<u8>])]) -> Result<Self> {
        let types: Vec<CString> = items
            .iter()
            .map(|(_, t, _)| cstr(t))
            .collect::<Result<_>>()?;
        let mut vals: Vec<Vec<Vec<u8>>> = items.iter().map(|(_, _, v)| v.to_vec()).collect();
        let mut bvs: Vec<Vec<berval>> = vals
            .iter_mut()
            .map(|vs| {
                vs.iter_mut()
                    .map(|v| berval {
                        bv_len: v.len() as _,
                        bv_val: v.as_mut_ptr() as *mut c_char,
                    })
                    .collect()
            })
            .collect();
        let mut bvptrs: Vec<Vec<*mut berval>> = bvs
            .iter_mut()
            .map(|b| {
                let mut p: Vec<*mut berval> = b.iter_mut().map(|x| x as *mut _).collect();
                p.push(null_mut());
                p
            })
            .collect();
        let mut mods: Vec<LDAPMod> = items
            .iter()
            .enumerate()
            .map(|(i, (op, _, v))| LDAPMod {
                mod_op: op | LDAP_MOD_BVALUES,
                mod_type: types[i].as_ptr() as *mut c_char,
                mod_bvalues: if v.is_empty() && *op == 1 {
                    null_mut()
                } else {
                    bvptrs[i].as_mut_ptr()
                },
            })
            .collect();
        let mut ptrs: Vec<*mut LDAPMod> = mods.iter_mut().map(|m| m as *mut _).collect();
        ptrs.push(null_mut());
        Ok(Mods {
            _types: types,
            _vals: vals,
            _bvs: bvs,
            _bvptrs: bvptrs,
            _mods: mods,
            ptrs,
        })
    }
}

impl Session for OlSession {
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
        let base = cstr(&req.base)?;
        let filter = cstr(&req.filter)?;
        let attr_c: Vec<CString> = req.attrs.iter().map(|a| cstr(a)).collect::<Result<_>>()?;
        let mut attr_p: Vec<*mut c_char> =
            attr_c.iter().map(|a| a.as_ptr() as *mut c_char).collect();
        attr_p.push(null_mut());
        let mut ctrls = CtrlArray::new(controls)?;
        let scope = match req.scope {
            Scope::Base => 0,
            Scope::One => 1,
            Scope::Sub => 2,
            Scope::Children => 3,
        };
        let deref: c_int = req.deref as c_int;
        let mut msgid: c_int = 0;
        let mut tl = libc::timeval {
            tv_sec: req.time_limit as _,
            tv_usec: 0,
        };
        let rc = unsafe {
            ldap_set_option(self.ld, LDAP_OPT_DEREF, &deref as *const _ as *const c_void);
            ldap_search_ext(
                self.ld,
                base.as_ptr(),
                scope,
                filter.as_ptr(),
                if req.attrs.is_empty() {
                    null_mut()
                } else {
                    attr_p.as_mut_ptr()
                },
                req.types_only as c_int,
                ctrls.as_ptr(),
                null_mut(),
                if req.time_limit > 0 {
                    &mut tl
                } else {
                    null_mut()
                },
                req.size_limit as c_int,
                &mut msgid,
            )
        };
        if rc != 0 {
            return self.sync_result(rc);
        }
        loop {
            let mut res: *mut LDAPMessage = null_mut();
            let mut tv = self.tv();
            let t = unsafe { ldap_result(self.ld, msgid, LDAP_MSG_ONE, &mut tv, &mut res) };
            if t == 0 {
                unsafe { ldap_abandon_ext(self.ld, msgid, null_mut(), null_mut()) };
                return Err(Error::connect(format!(
                    "search timed out after {}s",
                    self.timeout
                )));
            }
            if t < 0 {
                return self.sync_result(t).and_then(|r| r.into_result());
            }
            match t {
                LDAP_RES_SEARCH_ENTRY => {
                    let e = unsafe { read_entry(self.ld, res) };
                    unsafe { ldap_msgfree(res) };
                    on_entry(e)?;
                }
                LDAP_RES_SEARCH_REFERENCE => {
                    let mut refs: *mut *mut c_char = null_mut();
                    unsafe { ldap_parse_reference(self.ld, res, &mut refs, null_mut(), 1) };
                    on_reference(unsafe { take_strings(refs) })?;
                }
                LDAP_RES_SEARCH_RESULT => {
                    let (mut code, mut matched, mut msg, mut refs, mut sctrls) =
                        (0, null_mut(), null_mut(), null_mut(), null_mut());
                    let prc = unsafe {
                        ldap_parse_result(
                            self.ld,
                            res,
                            &mut code,
                            &mut matched,
                            &mut msg,
                            &mut refs,
                            &mut sctrls,
                            1,
                        )
                    };
                    if prc != 0 {
                        return self.sync_result(prc);
                    }
                    return Ok(OpResult {
                        code,
                        matched: unsafe { take_string(matched) },
                        message: unsafe { take_string(msg) },
                        controls: unsafe { take_controls(sctrls) },
                        referrals: unsafe { take_strings(refs) },
                    });
                }
                _ => unsafe {
                    ldap_msgfree(res);
                },
            }
        }
    }

    fn add(&mut self, dn: &str, attrs: &super::Attrs, controls: &[Control]) -> Result<OpResult> {
        let dn = cstr(dn)?;
        let items: Vec<(c_int, &str, &[Vec<u8>])> = attrs
            .iter()
            .map(|(a, v)| (0, a.as_str(), v.as_slice()))
            .collect();
        let mut mods = Mods::new(&items)?;
        let mut ctrls = CtrlArray::new(controls)?;
        let rc = unsafe {
            ldap_add_ext_s(
                self.ld,
                dn.as_ptr(),
                mods.ptrs.as_mut_ptr(),
                ctrls.as_ptr(),
                null_mut(),
            )
        };
        self.sync_result(rc)
    }

    fn modify(
        &mut self,
        dn: &str,
        mods: &[Modification],
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = cstr(dn)?;
        let items: Vec<(c_int, &str, &[Vec<u8>])> = mods
            .iter()
            .map(|m| {
                let op = match m.op {
                    ModOp::Add => 0,
                    ModOp::Delete => 1,
                    ModOp::Replace => 2,
                    ModOp::Increment => 3,
                };
                (op, m.attr.as_str(), m.values.as_slice())
            })
            .collect();
        let mut m = Mods::new(&items)?;
        let mut ctrls = CtrlArray::new(controls)?;
        let rc = unsafe {
            ldap_modify_ext_s(
                self.ld,
                dn.as_ptr(),
                m.ptrs.as_mut_ptr(),
                ctrls.as_ptr(),
                null_mut(),
            )
        };
        self.sync_result(rc)
    }

    fn delete(&mut self, dn: &str, controls: &[Control]) -> Result<OpResult> {
        let dn = cstr(dn)?;
        let mut ctrls = CtrlArray::new(controls)?;
        let rc = unsafe { ldap_delete_ext_s(self.ld, dn.as_ptr(), ctrls.as_ptr(), null_mut()) };
        self.sync_result(rc)
    }

    fn rename(
        &mut self,
        dn: &str,
        new_rdn: &str,
        new_superior: Option<&str>,
        delete_old: bool,
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = cstr(dn)?;
        let rdn = cstr(new_rdn)?;
        let sup = new_superior.map(cstr).transpose()?;
        let mut ctrls = CtrlArray::new(controls)?;
        let rc = unsafe {
            ldap_rename_s(
                self.ld,
                dn.as_ptr(),
                rdn.as_ptr(),
                sup.as_ref().map_or(null(), |s| s.as_ptr()),
                delete_old as c_int,
                ctrls.as_ptr(),
                null_mut(),
            )
        };
        self.sync_result(rc)
    }

    fn compare(
        &mut self,
        dn: &str,
        attr: &str,
        value: &[u8],
        controls: &[Control],
    ) -> Result<OpResult> {
        let dn = cstr(dn)?;
        let attr = cstr(attr)?;
        let mut v = value.to_vec();
        let mut bv = berval {
            bv_len: v.len() as _,
            bv_val: v.as_mut_ptr() as *mut c_char,
        };
        let mut ctrls = CtrlArray::new(controls)?;
        let rc = unsafe {
            ldap_compare_ext_s(
                self.ld,
                dn.as_ptr(),
                attr.as_ptr(),
                &mut bv,
                ctrls.as_ptr(),
                null_mut(),
            )
        };
        if rc == 5 || rc == 6 {
            return Ok(OpResult {
                code: rc,
                ..Default::default()
            });
        }
        self.sync_result(rc)
    }

    fn extended(
        &mut self,
        oid: &str,
        value: Option<&[u8]>,
        controls: &[Control],
    ) -> Result<ExtResult> {
        let oid = cstr(oid)?;
        let mut v = value.map(|v| v.to_vec());
        let mut bv = v.as_mut().map(|v| berval {
            bv_len: v.len() as _,
            bv_val: v.as_mut_ptr() as *mut c_char,
        });
        let mut ctrls = CtrlArray::new(controls)?;
        let mut retoid: *mut c_char = null_mut();
        let mut retdata: *mut berval = null_mut();
        let rc = unsafe {
            ldap_extended_operation_s(
                self.ld,
                oid.as_ptr(),
                bv.as_mut().map_or(null_mut(), |b| b as *mut _),
                ctrls.as_ptr(),
                null_mut(),
                &mut retoid,
                &mut retdata,
            )
        };
        let result = self.sync_result(rc)?;
        let oid = if retoid.is_null() {
            None
        } else {
            Some(unsafe { take_string(retoid) })
        };
        let value = if retdata.is_null() {
            None
        } else {
            unsafe {
                let b = &*retdata;
                let v = if b.bv_val.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(b.bv_val as *const u8, b.bv_len as usize).to_vec()
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
        let dn = take_string(ldap_get_dn(ld, e));
        let mut attrs = Vec::new();
        let mut ber: *mut BerElement = null_mut();
        let mut a = ldap_first_attribute(ld, e, &mut ber);
        while !a.is_null() {
            let name = CStr::from_ptr(a).to_string_lossy().into_owned();
            let vals = ldap_get_values_len(ld, e, a);
            let mut vs = Vec::new();
            if !vals.is_null() {
                let mut i = 0;
                while !(*vals.add(i)).is_null() {
                    let b = &**vals.add(i);
                    vs.push(if b.bv_val.is_null() {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(b.bv_val as *const u8, b.bv_len as usize)
                            .to_vec()
                    });
                    i += 1;
                }
                ldap_value_free_len(vals);
            }
            attrs.push((name, vs));
            ldap_memfree(a as *mut c_void);
            a = ldap_next_attribute(ld, e, ber);
        }
        if !ber.is_null() {
            ber_free(ber, 0);
        }
        Entry { dn, attrs }
    }
}

// ---------------- DNS SRV via dns_sd (respects VPN / scoped resolvers) ----------------

struct SrvCtx {
    out: Vec<Srv>,
    done: bool,
    error: i32,
}

unsafe extern "C" fn srv_reply(
    _sd: DNSServiceRef,
    flags: u32,
    _iface: u32,
    err: i32,
    _fullname: *const c_char,
    rrtype: u16,
    _rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    _ttl: u32,
    ctx: *mut c_void,
) {
    let c = unsafe { &mut *(ctx as *mut SrvCtx) };
    if err != 0 {
        c.error = err;
        c.done = true;
        return;
    }
    if rrtype == 33 && rdlen >= 7 {
        let d = unsafe { std::slice::from_raw_parts(rdata as *const u8, rdlen as usize) };
        let mut name = Vec::new();
        let mut i = 6;
        while i < d.len() && d[i] != 0 {
            let l = d[i] as usize;
            if i + 1 + l > d.len() {
                break;
            }
            name.push(String::from_utf8_lossy(&d[i + 1..i + 1 + l]).into_owned());
            i += l + 1;
        }
        c.out.push(Srv {
            priority: u16::from_be_bytes([d[0], d[1]]),
            weight: u16::from_be_bytes([d[2], d[3]]),
            port: u16::from_be_bytes([d[4], d[5]]),
            target: name.join("."),
        });
    }
    if flags & K_DNS_SERVICE_FLAGS_MORE_COMING == 0 {
        c.done = true;
    }
}

pub fn query_srv(name: &str) -> Result<Vec<Srv>> {
    let cname = cstr(name)?;
    let mut ctx = SrvCtx {
        out: Vec::new(),
        done: false,
        error: 0,
    };
    let mut sd: DNSServiceRef = null_mut();
    let rc = unsafe {
        DNSServiceQueryRecord(
            &mut sd,
            K_DNS_SERVICE_FLAGS_TIMEOUT,
            0,
            cname.as_ptr(),
            33,
            1,
            srv_reply,
            &mut ctx as *mut _ as *mut c_void,
        )
    };
    if rc != 0 {
        return Err(Error::connect(format!(
            "DNS query for {name} failed ({rc})"
        )));
    }
    let fd = unsafe { DNSServiceRefSockFD(sd) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ctx.done {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as c_int) };
        if n <= 0 {
            break;
        }
        if unsafe { DNSServiceProcessResult(sd) } != 0 {
            break;
        }
    }
    unsafe { DNSServiceRefDeallocate(sd) };
    // NoSuchRecord (-65554) and timeouts (-65568) simply mean "no answer".
    if ctx.error != 0 && ctx.error != -65554 && ctx.error != -65568 && ctx.out.is_empty() {
        return Err(Error::connect(format!(
            "DNS query for {name} failed ({})",
            ctx.error
        )));
    }
    Ok(ctx.out)
}

pub fn preferred_dc(_domain: &str, _site: Option<&str>, _gc: bool) -> Option<String> {
    None
}
