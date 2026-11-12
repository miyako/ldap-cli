// Links the vendored static OpenLDAP + OpenSSL on macOS (built by
// scripts/build-deps-macos.sh into deps/macos), plus system libsasl2 and frameworks.
// Windows needs nothing: Wldap32, Secur32, Crypt32, Dnsapi, Netapi32 come via windows-sys.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LDAP_CLI_DEPS");
    if target_os != "macos" {
        return;
    }
    let root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let deps = std::env::var("LDAP_CLI_DEPS").unwrap_or_else(|_| format!("{root}/deps/macos"));
    let lib = format!("{deps}/lib");
    if !std::path::Path::new(&format!("{lib}/libldap.a")).exists() {
        panic!(
            "{lib}/libldap.a not found: run scripts/build-deps-macos.sh first (or set LDAP_CLI_DEPS)"
        );
    }
    println!("cargo:rerun-if-changed={lib}/libldap.a");
    println!("cargo:rerun-if-changed=src/backend/openldap/gssapi.c");
    cc::Build::new()
        .file("src/backend/openldap/gssapi.c")
        .include(format!("{deps}/include"))
        .warnings(true)
        .flag("-Werror")
        .compile("ldap_cli_gssapi");
    println!("cargo:rustc-link-search=native={lib}");
    for l in ["ldap", "lber", "ssl", "crypto"] {
        println!("cargo:rustc-link-lib=static={l}");
    }
    println!("cargo:rustc-link-lib=dylib=sasl2");
    println!("cargo:rustc-link-lib=dylib=resolv");
    for f in ["Security", "CoreFoundation", "GSS"] {
        println!("cargo:rustc-link-lib=framework={f}");
    }
}
