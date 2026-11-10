//! Hand-written FFI declarations for OpenLDAP 2.6, OpenSSL 3, Cyrus SASL and dns_sd.
#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

// ---------------- OpenLDAP ----------------

#[repr(C)]
pub struct LDAP {
    _p: [u8; 0],
}
#[repr(C)]
pub struct LDAPMessage {
    _p: [u8; 0],
}
#[repr(C)]
pub struct BerElement {
    _p: [u8; 0],
}

#[repr(C)]
pub struct berval {
    pub bv_len: c_ulong,
    pub bv_val: *mut c_char,
}

#[repr(C)]
pub struct LDAPControl {
    pub ldctl_oid: *mut c_char,
    pub ldctl_value: berval,
    pub ldctl_iscritical: c_char,
}

#[repr(C)]
pub struct LDAPMod {
    pub mod_op: c_int,
    pub mod_type: *mut c_char,
    pub mod_bvalues: *mut *mut berval,
}

#[repr(C)]
pub struct sasl_interact_t {
    pub id: c_ulong,
    pub challenge: *const c_char,
    pub prompt: *const c_char,
    pub defresult: *const c_char,
    pub result: *const c_void,
    pub len: c_uint,
}

pub type InteractFn = unsafe extern "C" fn(*mut LDAP, c_uint, *mut c_void, *mut c_void) -> c_int;

pub const LDAP_OPT_DEREF: c_int = 0x0002;
pub const LDAP_OPT_REFERRALS: c_int = 0x0008;
pub const LDAP_OPT_PROTOCOL_VERSION: c_int = 0x0011;
pub const LDAP_OPT_DIAGNOSTIC_MESSAGE: c_int = 0x0032;
pub const LDAP_OPT_MATCHED_DN: c_int = 0x0033;
pub const LDAP_OPT_TIMEOUT: c_int = 0x5002;
pub const LDAP_OPT_NETWORK_TIMEOUT: c_int = 0x5005;
pub const LDAP_OPT_X_TLS_CTX: c_int = 0x6001;
pub const LDAP_OPT_X_TLS_REQUIRE_CERT: c_int = 0x6006;
pub const LDAP_OPT_X_TLS_PROTOCOL_MIN: c_int = 0x6007;
pub const LDAP_OPT_X_TLS_SSL_CTX: c_int = 0x600a;
pub const LDAP_OPT_X_TLS_NEWCTX: c_int = 0x600f;
pub const LDAP_OPT_X_TLS_VERSION: c_int = 0x6013;
pub const LDAP_OPT_X_TLS_ALLOW: c_int = 3;
pub const LDAP_OPT_X_SASL_SECPROPS: c_int = 0x6106;
pub const LDAP_OPT_X_SASL_NOCANON: c_int = 0x610b;
pub const LDAP_OPT_X_SASL_CBINDING: c_int = 0x610e;
pub const LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT: c_int = 2;
pub const LDAP_OPT_ON: *const c_void = 1 as *const c_void;
pub const LDAP_OPT_OFF: *const c_void = std::ptr::null();

pub const LDAP_VERSION3: c_int = 3;
pub const LDAP_SASL_QUIET: c_uint = 2;
pub const LDAP_MOD_BVALUES: c_int = 0x80;
pub const LDAP_RES_SEARCH_ENTRY: c_int = 0x64;
pub const LDAP_RES_SEARCH_RESULT: c_int = 0x65;
pub const LDAP_RES_SEARCH_REFERENCE: c_int = 0x73;
pub const LDAP_MSG_ONE: c_int = 0;
pub const LDAP_SERVER_DOWN: c_int = -1;
pub const LDAP_TIMEOUT: c_int = -5;
pub const LDAP_CONNECT_ERROR: c_int = -11;

pub const SASL_CB_LIST_END: c_ulong = 0;
pub const SASL_CB_USER: c_ulong = 0x4001;
pub const SASL_CB_AUTHNAME: c_ulong = 0x4002;
pub const SASL_CB_PASS: c_ulong = 0x4004;
pub const SASL_CB_GETREALM: c_ulong = 0x4008;

unsafe extern "C" {
    pub fn ldap_initialize(ldp: *mut *mut LDAP, uri: *const c_char) -> c_int;
    pub fn ldap_set_option(ld: *mut LDAP, option: c_int, invalue: *const c_void) -> c_int;
    pub fn ldap_get_option(ld: *mut LDAP, option: c_int, outvalue: *mut c_void) -> c_int;
    pub fn ldap_connect(ld: *mut LDAP) -> c_int;
    pub fn ldap_start_tls_s(
        ld: *mut LDAP,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_sasl_bind_s(
        ld: *mut LDAP,
        dn: *const c_char,
        mech: *const c_char,
        cred: *mut berval,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
        servercred: *mut *mut berval,
    ) -> c_int;
    pub fn ldap_sasl_interactive_bind_s(
        ld: *mut LDAP,
        dn: *const c_char,
        mechs: *const c_char,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
        flags: c_uint,
        interact: InteractFn,
        defaults: *mut c_void,
    ) -> c_int;
    pub fn ldap_search_ext(
        ld: *mut LDAP,
        base: *const c_char,
        scope: c_int,
        filter: *const c_char,
        attrs: *mut *mut c_char,
        attrsonly: c_int,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
        timeout: *mut libc::timeval,
        sizelimit: c_int,
        msgidp: *mut c_int,
    ) -> c_int;
    pub fn ldap_result(
        ld: *mut LDAP,
        msgid: c_int,
        all: c_int,
        timeout: *mut libc::timeval,
        res: *mut *mut LDAPMessage,
    ) -> c_int;
    pub fn ldap_msgtype(m: *mut LDAPMessage) -> c_int;
    pub fn ldap_msgfree(m: *mut LDAPMessage) -> c_int;
    pub fn ldap_abandon_ext(
        ld: *mut LDAP,
        msgid: c_int,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_get_dn(ld: *mut LDAP, e: *mut LDAPMessage) -> *mut c_char;
    pub fn ldap_first_attribute(
        ld: *mut LDAP,
        e: *mut LDAPMessage,
        ber: *mut *mut BerElement,
    ) -> *mut c_char;
    pub fn ldap_next_attribute(
        ld: *mut LDAP,
        e: *mut LDAPMessage,
        ber: *mut BerElement,
    ) -> *mut c_char;
    pub fn ldap_get_values_len(
        ld: *mut LDAP,
        e: *mut LDAPMessage,
        attr: *const c_char,
    ) -> *mut *mut berval;
    pub fn ldap_value_free_len(v: *mut *mut berval);
    pub fn ldap_memfree(p: *mut c_void);
    pub fn ldap_memvfree(v: *mut *mut c_void);
    pub fn ber_free(ber: *mut BerElement, freebuf: c_int);
    pub fn ber_bvfree(bv: *mut berval);
    pub fn ldap_parse_result(
        ld: *mut LDAP,
        res: *mut LDAPMessage,
        errcode: *mut c_int,
        matched: *mut *mut c_char,
        errmsg: *mut *mut c_char,
        referrals: *mut *mut *mut c_char,
        ctrls: *mut *mut *mut LDAPControl,
        freeit: c_int,
    ) -> c_int;
    pub fn ldap_parse_reference(
        ld: *mut LDAP,
        r: *mut LDAPMessage,
        referrals: *mut *mut *mut c_char,
        ctrls: *mut *mut *mut LDAPControl,
        freeit: c_int,
    ) -> c_int;
    pub fn ldap_controls_free(c: *mut *mut LDAPControl);
    pub fn ldap_add_ext_s(
        ld: *mut LDAP,
        dn: *const c_char,
        a: *mut *mut LDAPMod,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_modify_ext_s(
        ld: *mut LDAP,
        dn: *const c_char,
        m: *mut *mut LDAPMod,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_delete_ext_s(
        ld: *mut LDAP,
        dn: *const c_char,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_rename_s(
        ld: *mut LDAP,
        dn: *const c_char,
        newrdn: *const c_char,
        newsup: *const c_char,
        deleteold: c_int,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_compare_ext_s(
        ld: *mut LDAP,
        dn: *const c_char,
        attr: *const c_char,
        value: *mut berval,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_extended_operation_s(
        ld: *mut LDAP,
        oid: *const c_char,
        data: *mut berval,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
        retoid: *mut *mut c_char,
        retdata: *mut *mut berval,
    ) -> c_int;
    pub fn ldap_unbind_ext_s(
        ld: *mut LDAP,
        s: *mut *mut LDAPControl,
        c: *mut *mut LDAPControl,
    ) -> c_int;
    pub fn ldap_err2string(err: c_int) -> *const c_char;
}

// ---------------- OpenSSL ----------------

#[repr(C)]
pub struct SSL_CTX {
    _p: [u8; 0],
}
#[repr(C)]
pub struct SSL {
    _p: [u8; 0],
}
#[repr(C)]
pub struct X509 {
    _p: [u8; 0],
}
#[repr(C)]
pub struct X509_STORE_CTX {
    _p: [u8; 0],
}
#[repr(C)]
pub struct EVP_PKEY {
    _p: [u8; 0],
}
#[repr(C)]
pub struct PKCS12 {
    _p: [u8; 0],
}
#[repr(C)]
pub struct OPENSSL_STACK {
    _p: [u8; 0],
}

pub type CertVerifyCb = unsafe extern "C" fn(*mut X509_STORE_CTX, *mut c_void) -> c_int;

pub const SSL_VERIFY_PEER: c_int = 0x01;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;
pub const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
pub const SSL_CTRL_CHAIN_CERT: c_int = 89;

unsafe extern "C" {
    pub fn SSL_CTX_set_cert_verify_callback(ctx: *mut SSL_CTX, cb: CertVerifyCb, arg: *mut c_void);
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, cb: *const c_void);
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int;
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, k: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;
    pub fn X509_STORE_CTX_get0_cert(ctx: *const X509_STORE_CTX) -> *mut X509;
    pub fn X509_STORE_CTX_get0_untrusted(ctx: *const X509_STORE_CTX) -> *mut OPENSSL_STACK;
    pub fn X509_STORE_CTX_set_error(ctx: *mut X509_STORE_CTX, e: c_int);
    pub fn i2d_X509(x: *const X509, out: *mut *mut u8) -> c_int;
    pub fn X509_free(x: *mut X509);
    pub fn EVP_PKEY_free(k: *mut EVP_PKEY);
    pub fn OPENSSL_sk_num(s: *const OPENSSL_STACK) -> c_int;
    pub fn OPENSSL_sk_value(s: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    pub fn OPENSSL_sk_free(s: *mut OPENSSL_STACK);
    pub fn d2i_PKCS12(a: *mut *mut PKCS12, pp: *mut *const u8, len: c_long) -> *mut PKCS12;
    pub fn PKCS12_parse(
        p12: *mut PKCS12,
        pass: *const c_char,
        pkey: *mut *mut EVP_PKEY,
        cert: *mut *mut X509,
        ca: *mut *mut OPENSSL_STACK,
    ) -> c_int;
    pub fn PKCS12_free(p: *mut PKCS12);
    pub fn OSSL_PROVIDER_load(libctx: *mut c_void, name: *const c_char) -> *mut c_void;
    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    pub fn ERR_clear_error();
}

// ---------------- dns_sd ----------------

pub type DNSServiceRef = *mut c_void;
pub type DNSServiceQueryRecordReply = unsafe extern "C" fn(
    sd: DNSServiceRef,
    flags: u32,
    iface: u32,
    err: i32,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    ttl: u32,
    ctx: *mut c_void,
);
pub const K_DNS_SERVICE_FLAGS_MORE_COMING: u32 = 0x1;
pub const K_DNS_SERVICE_FLAGS_TIMEOUT: u32 = 0x10000;
pub const K_DNS_SERVICE_FLAGS_RETURN_INTERMEDIATES: u32 = 0x1000;

unsafe extern "C" {
    pub fn DNSServiceQueryRecord(
        sd: *mut DNSServiceRef,
        flags: u32,
        iface: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        cb: DNSServiceQueryRecordReply,
        ctx: *mut c_void,
    ) -> i32;
    pub fn DNSServiceRefSockFD(sd: DNSServiceRef) -> c_int;
    pub fn DNSServiceProcessResult(sd: DNSServiceRef) -> i32;
    pub fn DNSServiceRefDeallocate(sd: DNSServiceRef);
}

// ---------------- Security.framework extras ----------------

#[repr(C)]
pub struct SecItemImportExportKeyParameters {
    pub version: u32,
    pub flags: u32,
    pub passphrase: *const c_void,
    pub alert_title: *const c_void,
    pub alert_prompt: *const c_void,
    pub access_ref: *const c_void,
    pub key_usage: *const c_void,
    pub key_attributes: *const c_void,
}
pub const K_SEC_FORMAT_PKCS12: u32 = 12;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    pub fn SecItemExport(
        item: *const c_void,
        format: u32,
        flags: u32,
        params: *const SecItemImportExportKeyParameters,
        out: *mut *const c_void,
    ) -> i32;
    pub fn SecIdentityCopyPreferred(
        name: *const c_void,
        key_usage: *const c_void,
        issuers: *const c_void,
    ) -> *const c_void;
}
