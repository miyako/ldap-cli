# ldap-cli

`ldap` is an LDAP command-line client with one syntax and native backends:

| | Windows (x64, arm64) | macOS (universal, 11+) |
|---|---|---|
| Protocol | Wldap32 | OpenLDAP 2.6 (vendored, static) |
| TLS | Schannel | OpenSSL 3.5 (vendored, static) |
| Trust decision | Windows certificate store (CryptoAPI when `--ca-cert` is used) | Keychain trust settings via Security.framework (SecTrust) |
| Kerberos / SSO | SSPI Negotiate (logon session or `--user`) | system Cyrus SASL → GSS.framework (`kinit` tickets); native GSS for required CBT |
| Explicit user/password SASL | SSPI credentials; explicit CBT token exchange in required mode | native GSS.framework, isolated memory-only Kerberos credentials, no prior tickets |
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

# Explicit AD user/password, verified TLS and required CBT, on either platform.
# The caller writes the password to the process's stdin pipe, never argv/a file.
ldap -H ldaps://dc1.corp.example -M gssapi --user alice@CORP.EXAMPLE \
     --password-stdin --channel-binding require \
     search --base= --scope base --size-limit 1 --page-size 0 -- 1.1
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
* **SASL layers.** `--sasl-qos auto` uses no SASL layer over TLS (AD rejects one) and sealing over plaintext. `--channel-binding require` requires verified TLS and a supported SASL mechanism; simple, anonymous and EXTERNAL binds cannot satisfy it. It refuses insecure verification, referral chasing and password files (use a private stdin pipe or environment variable). TLS endpoint extraction or native authentication failures stop the connection without a simple/anonymous/SSO retry.
* **Explicit credentials are not SSO.** On macOS, `-M gssapi --user user@REALM --password-stdin` (or `--password-env`/`--password-file`) acquires new Kerberos credentials into a unique `MEMORY:` cache, passes that handle directly to GSS, and destroys it after binding. It does not read or change the default ticket cache or require `kinit`. A reachable KDC, correct realm configuration and the server's `ldap/FQDN` SPN are still necessary. Native macOS explicit-credential/required-CBT mode requires TLS, uses GSSAPI only, and rejects `--ccache`, `--authzid` and `--realm` overrides. Other ticket-based SSO modes retain their existing behaviour.
* **Required CBT on Windows** passes the verified leaf certificate's `tls-server-end-point` binding explicitly to SSPI, restricts the package list, checks the negotiated package, and disables transparent reconnect. Kerberos-only `-M gssapi` uses SASL GSS-SPNEGO on the wire, with NTLM excluded. NTLM remains available only when selected/allowed. Certificate signature digests SHA-256/384/512 and MD5/SHA-1 upgraded to SHA-256 are supported; unrecognized signatures (including RSA-PSS parameters) fail explicitly rather than guessing a CBT.
* **Best-effort modes are not enforcement.** macOS ticket-only `auto` still uses Cyrus SASL/OpenLDAP; setting a library option is not proof of CBT exchange. Windows non-required modes retain Wldap32's automatic behaviour; `--channel-binding none` does not disable that native implicit CBT and is not a Windows no-CBT negative control.
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

`ldap capabilities` runs offline, before loading profiles or reading credentials, and prints:

```json
{"schema":1,"features":["explicit-credentials-sasl","channel-binding-require"]}
```

Wrappers must require schema 1 and both features before sending strict-mode credentials.
An older binary's unknown-command error, malformed JSON or a missing feature means
unsupported, never permission to fall back. These features describe implemented
client paths, **not real-AD interoperability certification**. Use portable UPN
identities (`user@REALM`), not LDAP DNs; Windows also accepts `DOMAIN\user`.
Explicit `--user` replaces any profile user; passwords never select a different
identity on failure. Empty identities, empty password and embedded NUL are refused.

Policy/unsupported combinations exit 2 before binding; TLS/trust failures exit 3;
bind/acquisition failures exit 4 with native diagnostics. `SEC_E_BAD_BINDINGS`
(`80090346`) is identified as channel-binding rejection when reported. Generic
LDAP 49 or an opaque GSS error is **not** enough to distinguish a bad password
from CBT/account-policy problems. Errors in subsequent operations retain LDAP
exit codes. An AD server without Who Am I support can return an operation error
after a successful bind: use the RootDSE search above to test bind success, and
server-side identity evidence to prove which user authenticated.

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
bash tests/integration/kerberos-macos.sh "$PWD/ldap"  # also needs Homebrew krb5
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

The existing macOS slapd suite covers simple binds, TLS and directory operations.
The isolated local MIT-KDC/slapd regression additionally covers explicit credentials
without prior tickets, LDAPS/StartTLS, wrong passwords in the presence of another
user's default tickets, concurrent Alice/Bob sessions, unchanged default caches,
and trust/hostname rejection. This is **not an AD Always-policy test**.
For test-owned component integration, set `LDAP_KERBEROS_TEST_HOOK` to an
executable before running that regression. It runs while the fixture is alive,
inheriting its Kerberos configuration, `LDAP_TEST_URI`, `LDAP_TEST_CA_CERT`,
`LDAP_TEST_BASE`, and synthetic `LDAP_TEST_USER_A/B`, `LDAP_TEST_PASSWORD_A/B`,
`LDAP_TEST_IDENTITY_A/B`. Services and files are cleaned up when the hook returns.
Use disposable staged component copies; this does not change any release pin.

Not yet verified against a real Active Directory (needs a Windows Server 2025 DC with LDAP signing and channel binding enforced):

* Windows backend at runtime, including strict SSPI token exchange and package restrictions, logon-session SSO, `PKCS12_NO_PERSIST_KEY` import, client-certificate callback and revocation behaviour.
* macOS native GSSAPI explicit credentials/CBT and existing Cyrus GSS-SPNEGO against AD.
* `EXTERNAL` with AD strong certificate mapping; `unicodePwd` changes; DC discovery.

Deferred: CLDAP "LDAP ping" site discovery (use `--site`), non-exportable Keychain keys (needs an OpenSSL provider backed by Security.framework), Kerberos SPN override, Windows Authenticode signing.

### Real-AD acceptance (outstanding)

Use a dedicated test DC and two nonprivileged test users; wrong-password tests can
increment lockout counters. On **each Windows and macOS version being supported**:

1. Record OS build, CLI commit/version, DC build and patches, server FQDN/SPN,
   certificate chain/signature algorithm, effective
   `Domain controller: LDAP server channel binding token requirements = Always`
   (`LdapEnforceChannelBinding=2`), and the signing policy. Preserve the effective
   configuration evidence, not merely the policy intended by an administrator.
2. Verify `ldap capabilities`. Run the strict RootDSE command above with each
   user's password through a private stdin pipe. Repeat using `ldap://` StartTLS.
   Then run a directory operation on that same command connection (a normal
   `search` performs its RootDSE lookup and requested search after binding).
   Correlate DC authentication/security logs or an approved server-side trace
   with the intended user, client connection and timestamp; do not infer identity
   just because RootDSE is readable. Collect Who Am I output where supported.
3. Repeat with an intentionally wrong password and while a different service/user
   has default tickets. Require exit 4, no simple/anonymous/SSO retry, and no
   authenticated operation. Run both valid users concurrently and correlate
   each operation with its own identity. Confirm existing tickets are unchanged
   and no acquired credentials remain after each child process exits.
4. With **applicable SASL over TLS**, perform a no-CBT or deliberately mismatched-CBT
   negative control against that same enforced DC. On macOS, use the same explicit
   GSSAPI invocation with `--channel-binding none`: expect authentication rejection.
   On Windows use an independently instrumented no-CBT client; this CLI's legacy
   Wldap32 `none` path can still supply CBT automatically. Capture native errors
   and server evidence demonstrating rejection of the invalid/missing binding.
   Pair the valid test with affirmative token-validation evidence where the
   platform supplies it, or a controlled positive/negative comparison with the
   effective Always policy and authenticated identities recorded.
5. Test an untrusted chain and a wrong `--tls-server-name`: expect exit 3 before
   authentication. Confirm strict mode rejects `--insecure-skip-verify`, plaintext
   and non-CBT mechanisms with exit 2. Separately confirm a generic simple bind
   over trusted TLS **outside strict mode** still works.

Store sanitized commands, exit codes, authenticated identities and server evidence
together; never store the supplied passwords. Simple-bind success and the absence
of event 3075 do not prove CBT acceptance. Event 3075 is an audit event, not by
itself a failed login. Until these steps pass on both platforms, interoperability
and deployment readiness remain unverified. See
[Microsoft's applicability and enforcement guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding).

## Third-party licenses

macOS binaries include OpenLDAP (OpenLDAP Public License) and OpenSSL (Apache License 2.0); see `licenses/`.
