# ldap-cli

`ldap` is an LDAP command-line client with one syntax and native backends:

| | Windows (x64, arm64) | macOS (universal, 11+) |
|---|---|---|
| Protocol | Wldap32 | OpenLDAP 2.6 (vendored, static) |
| TLS | Schannel | OpenSSL 3.5 (vendored, static) |
| Trust decision | Windows certificate store (CryptoAPI when `--ca-cert` is used) | Keychain trust settings via Security.framework (SecTrust) |
| Kerberos / SSO | SSPI Negotiate (logon session or `--user`) | system Cyrus SASL → GSS.framework (`kinit` tickets) |
| NTLM | yes (`-M ntlm`, or `--allow-ntlm` fallback) | no |
| Client certificates | `CurrentUser\My` / `LocalMachine\My`, inline PKCS#12 | Keychain (exportable keys), inline PKCS#12 |
| DC discovery | `DsGetDcName` + DNS SRV | DNS SRV via dns_sd (honours VPN/scoped resolvers) |

The binaries are released for the `ldap` wrapper component; see [Release assets](#release-assets).

## Quick start

```sh
# Anonymous RootDSE, TLS details and server chain
ldap -H ldaps://dc1.corp.example probe

# Kerberos SSO search (Windows: logon session; macOS: run kinit first)
ldap --domain corp.example -M gssapi search -f '(sAMAccountName={u})' -a u="$USER" mail memberOf

# Simple bind; the password comes from the environment, a file, stdin or a prompt
ldap -H ldaps://ldap.example.org -D 'cn=admin,dc=example,dc=org' --password-env LDAP_PW \
     search -b 'ou=people,dc=example,dc=org' -f '(cn={q}*)' -a q="$INPUT" cn mail
```

## Commands

`search` `add` `modify` `delete` `modrdn` `compare` `exop` `whoami` `passwd`, plus `probe` (TLS, chain, RootDSE) and the offline helpers `escape` and `dn`. Run `ldap <command> --help` for every option.

| Command | Highlights |
|---|---|
| `search` | Automatic paging (`--page-size`, default 500), server-side sort (`--sort -cn,sn`), AD range retrieval for large groups, default base from the RootDSE, any control with `--control OID[!][=b64:…]` |
| `add` / `modify` | `--dn` with `--attr` / `--add` / `--replace` / `--delete` / `--increment`, or LDIF with `--file` (`-` = stdin); `--continue-on-error`, `--dry-run` |
| `delete` | Several DNs, `--file`, `--subtree` (AD tree-delete control when offered, otherwise deepest-first) |
| `compare` | Exit 0 = true, 1 = false |
| `exop` | `whoami`, `cancel`, `refresh`, or any OID with `--value b64:…` |
| `passwd` | `--method auto` picks RFC 3062 or AD `unicodePwd`; user change with `--old-password-*`, admin reset without; `--generate N` |

## Templates and escaping (LDAP injection)

Filters, DNs, bases and RDNs are **templates**. `{name}` is replaced by `--arg name=VALUE` (or `--arg-file name=PATH`), escaped for where it appears:

* in a filter — RFC 4515: `*` `(` `)` `\` NUL → `\2a` `\28` `\29` `\5c` `\00`
* in a DN — RFC 4514: `, + " \ < > ;`, a leading space or `#`, a trailing space, NUL

Text typed in the template keeps its meaning, so `(cn={q}*)` is a safe prefix search: a `*` in the user's input is escaped, the template's `*` is a wildcard. `{{` / `}}` give literal braces. Filters are syntax-checked before they are sent (`--raw-filter` skips the check; placeholders are still escaped).

```sh
ldap escape filter 'a*(b)'          # a\2a\28b\29
ldap escape dn '#Smith, John'       # \#Smith\, John
ldap dn build 'CN={cn},OU=Users,DC=corp' -a 'cn=Smith, John'
ldap dn parse 'CN=Smith\, John,OU=Users,DC=corp'   # JSON
```

## Security model

* **Encrypted by default.** `ldap://` means StartTLS; plaintext needs `--tls none --allow-plaintext`, and a simple bind over plaintext is always refused.
* **No secrets on the command line.** Passwords come from `--password-env`, `--password-stdin`, `--password-file` or a prompt. Client keys come from the OS store, `env:VAR` or stdin — never argv, never certificate files. Only one option may read stdin per run.
* **Empty passwords are rejected** (an empty simple-bind password is an unauthenticated bind that many servers report as success, RFC 4513 §5.1.2).
* **Trust comes from the OS.** `--ca-cert` (base64 DER or pasted PEM; also `LDAP_CA_CERTS` and profiles) *adds* anchors; it never replaces the system store. Hostname verification is always on; `--tls-server-name` changes the verified name. `--insecure-skip-verify` warns on every run.
* **SASL layers.** `--sasl-qos auto` uses no SASL layer over TLS (AD rejects one) and sealing over plaintext. Channel binding (`tls-endpoint`) is on for SASL binds over TLS (macOS: OpenLDAP 2.6; Windows: automatic in Wldap32).
* **NTLM is opt-in.** `-M gssapi` restricts Negotiate to Kerberos; `-M spnego --allow-ntlm` permits fallback; `-M ntlm` forces it (Windows only).
* **DNS discovery is constrained.** SRV targets outside `--domain` are ignored unless `--allow-foreign-dc`.
* **Referral chasing** is off by default and refused with simple binds.

## Options at a glance

| Area | Options |
|---|---|
| Connection | `-H/--uri` (repeat for failover), `--domain`, `--site`, `--gc`, `--tls ldaps\|starttls\|none`, `--connect-timeout`, `--timeout`, `--referrals`, `--profile` |
| TLS | `--ca-cert B64`, `--tls-server-name`, `--tls-min 1.2\|1.3`, `--revocation off\|soft\|hard`, `--client-cert sha256/HEX\|subject:…\|auto\|env:VAR\|stdin`, `--client-cert-password-env`, `--cert-store user\|machine`, `--insecure-skip-verify` |
| Authentication | `-M anonymous\|simple\|gssapi\|spnego\|ntlm\|external`, `-D/--bind-dn`, `-U/--user`, `--realm`, `--authzid`, `--password-env\|-stdin\|-file`, `--ccache` (macOS), `--sasl-qos`, `--channel-binding`, `--allow-ntlm` |
| Output | `-o ldif\|json\|jsonl\|csv` (default: LDIF on a terminal, JSON Lines when piped), `--binary base64\|hex\|decode` (SID, GUID, FILETIME), `--ldif-wrap`, `-v`, `--dry-run` |

Exit codes: `0` success, `1` compare false, `2` usage, `3` connection/TLS, `4` authentication, `10 + N` LDAP result code `N` (e.g. 42 = noSuchObject).

## Profiles

`~/.config/ldap/config.toml` (macOS) or `%APPDATA%\ldap\config.toml` (Windows); override with `LDAP_CONFIG`. Command-line options win. Passwords and keys are not accepted in profiles.

```toml
default_profile = "corp"

[profile.corp]
domain = "corp.example"
mech = "gssapi"
base = "DC=corp,DC=example"
format = "jsonl"
ca_certs = ["MIIDdzCCAl+gAwIBAgIQ…"]   # internal root, if not deployed by GPO/MDM
```

## Building

macOS (Xcode command-line tools, Rust ≥ 1.88):

```sh
scripts/build-deps-macos.sh          # pinned OpenSSL + OpenLDAP → deps/macos (universal, static)
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
lipo -create -output ldap target/{aarch64,x86_64}-apple-darwin/release/ldap
tests/integration/macos.sh "$PWD/ldap"   # needs `brew install openldap` for slapd
```

Windows (MSVC toolchain): `cargo build --release --target x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc`. The CRT is linked statically.

Pinned sources and their SHA-256 are in `deps.lock`.

## Release assets

The **Release** workflow (manual, from `main`, `release-signing` environment) publishes:

| Asset | Contents |
|---|---|
| `ldap-<version>-macos-universal.zip` | `ldap` (arm64 + x86_64, Developer ID signed, hardened runtime, notarized), README, licenses |
| `ldap-<version>-windows-x64.zip` | `ldap.exe`, README, licenses |
| `ldap-<version>-windows-arm64.zip` | `ldap.exe`, README, licenses |
| `SHA256SUMS.txt` | checksums of the zips |

## Status and known gaps

Tested: the macOS backend end to end against slapd (64 integration tests on both arm64 and x86_64), unit tests on both platforms, Windows x64/arm64 compile in CI.

Not yet verified against a real Active Directory (needs a Windows Server 2025 DC with LDAP signing and channel binding enforced):

* Windows backend at runtime: SSPI binds, the `Kerberos,!NTLM` package list with logon-session credentials, `PKCS12_NO_PERSIST_KEY` import, client-certificate callback, Wldap32 default revocation behaviour.
* macOS GSSAPI / GSS-SPNEGO binds and channel binding against AD.
* `EXTERNAL` with AD strong certificate mapping; `unicodePwd` changes; DC discovery.

Deferred: CLDAP "LDAP ping" site discovery (use `--site`), non-exportable Keychain keys (needs an OpenSSL provider backed by Security.framework), Kerberos SPN override, Windows Authenticode signing.

## Third-party licenses

macOS binaries include OpenLDAP (OpenLDAP Public License) and OpenSSL (Apache License 2.0); see `licenses/`.
