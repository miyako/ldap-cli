#!/usr/bin/env bash
# Integration tests against a throwaway local slapd (Homebrew OpenLDAP).
# Covers: TLS trust decisions (untrusted, inline CA, hostname, server-name override),
# StartTLS, simple bind rules, EXTERNAL with an inline PKCS#12, CRUD, paging, templates,
# compare, modrdn, subtree delete, whoami, passwd exop, output formats, probe.
#
# Usage: tests/integration/macos.sh [path/to/ldap]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LDAP="${1:-$ROOT/target/debug/ldap}"
BREW="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
SLAPD="$BREW/opt/openldap/libexec/slapd"
SCHEMA="$BREW/etc/openldap/schema"
OPENSSL="$BREW/opt/openssl@3/bin/openssl"
PORT=33389
SPORT=33636
D="$(mktemp -d "${TMPDIR:-/tmp}/ldap-cli-it.XXXXXX")"
PASS=0
FAIL=0

cleanup() {
  [[ -f "$D/slapd.pid" ]] && kill "$(cat "$D/slapd.pid")" 2>/dev/null
  rm -rf "$D"
}
trap cleanup EXIT

# ---------------- certificates ----------------
cd "$D"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=ldap-cli Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
"$OPENSSL" req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
"$OPENSSL" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 \
  -extfile <(printf "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n") 2>/dev/null
"$OPENSSL" req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/O=Test/CN=alice" 2>/dev/null
"$OPENSSL" x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 2 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n") 2>/dev/null
"$OPENSSL" pkcs12 -export -inkey client.key -in client.crt -passout pass:p12pass -out client.p12 2>/dev/null
# A second CA that the server does not use.
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 2 -subj "/CN=Other CA" \
  -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
CA_B64="$("$OPENSSL" x509 -in ca.crt -outform DER | base64)"
OTHER_B64="$("$OPENSSL" x509 -in other.crt -outform DER | base64)"
export LDAP_TEST_P12="$(base64 < client.p12)"
export LDAP_TEST_P12_PW="p12pass"
export LDAP_TEST_PW="secret"
export LDAP_TEST_EMPTY=""
export LDAP_CONFIG="$D/no-config.toml"

# ---------------- slapd ----------------
mkdir -p db
cat > slapd.conf <<EOF
include $SCHEMA/core.schema
include $SCHEMA/cosine.schema
include $SCHEMA/inetorgperson.schema
pidfile $D/slapd.pid
argsfile $D/slapd.args
TLSCertificateFile $D/server.crt
TLSCertificateKeyFile $D/server.key
TLSCACertificateFile $D/ca.crt
TLSVerifyClient try
authz-regexp "^cn=([^,]+),o=test\$" "uid=\$1,ou=people,dc=example,dc=test"
access to attrs=userPassword by self write by anonymous auth by * none
access to * by self write by users read by anonymous read
database mdb
maxsize 10485760
suffix "dc=example,dc=test"
rootdn "cn=admin,dc=example,dc=test"
rootpw secret
directory $D/db
EOF
nc -z localhost $PORT 2>/dev/null && { echo "port $PORT already in use (leftover slapd?)"; exit 1; }
"$SLAPD" -f "$D/slapd.conf" -h "ldap://localhost:$PORT/ ldaps://localhost:$SPORT/" || { echo "slapd failed to start"; exit 1; }
for _ in $(seq 50); do nc -z localhost $PORT 2>/dev/null && break; sleep 0.1; done

# ---------------- helpers ----------------
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; [[ -n "${2:-}" ]] && echo "$2" | sed 's/^/       /'; }
# expect <exit-code> <description> <command...>; output in $OUT
expect() {
  local want="$1" desc="$2"; shift 2
  OUT="$("$@" 2>&1)"; local got=$?
  if [[ "$got" == "$want" ]]; then ok "$desc"; else bad "$desc (exit $got, want $want)" "$OUT"; fi
}
contains() { if grep -qF -- "$2" <<<"$OUT"; then ok "$1"; else bad "$1 (missing '$2')" "$OUT"; fi; }

S=(-H "ldaps://localhost:$SPORT" --ca-cert "$CA_B64")
ADMIN=(-D "cn=admin,dc=example,dc=test" --password-env LDAP_TEST_PW)
BASE="dc=example,dc=test"

echo "TLS trust"
expect 3 "untrusted server certificate is rejected" "$LDAP" -H "ldaps://localhost:$SPORT" whoami
contains "rejection names the reason" "rejected"
expect 3 "an unrelated --ca-cert does not help" "$LDAP" -H "ldaps://localhost:$SPORT" --ca-cert "$OTHER_B64" whoami
expect 0 "inline --ca-cert is trusted" "$LDAP" "${S[@]}" whoami
contains "anonymous whoami" "anonymous"
expect 3 "hostname mismatch (127.0.0.1 vs localhost) is rejected" "$LDAP" -H "ldaps://127.0.0.1:$SPORT" --ca-cert "$CA_B64" whoami
expect 0 "--tls-server-name overrides the verified name" "$LDAP" -H "ldaps://127.0.0.1:$SPORT" --ca-cert "$CA_B64" --tls-server-name localhost whoami
expect 3 "--tls-server-name with a wrong name is rejected" "$LDAP" -H "ldaps://127.0.0.1:$SPORT" --ca-cert "$CA_B64" --tls-server-name evil.test whoami
expect 0 "StartTLS on ldap://" "$LDAP" -H "ldap://localhost:$PORT" --ca-cert "$CA_B64" whoami
expect 3 "StartTLS with an untrusted cert is rejected" "$LDAP" -H "ldap://localhost:$PORT" whoami
expect 0 "--insecure-skip-verify connects (with warning)" "$LDAP" -H "ldaps://localhost:$SPORT" --insecure-skip-verify whoami
contains "skip-verify warns" "NOT verified"
expect 0 "--tls-min 1.3" "$LDAP" "${S[@]}" --tls-min 1.3 whoami

echo "Bind rules"
expect 0 "simple bind over TLS" "$LDAP" "${S[@]}" "${ADMIN[@]}" whoami
contains "whoami shows the bind DN" "dn:cn=admin,dc=example,dc=test"
expect 2 "empty password rejected" "$LDAP" "${S[@]}" -D "cn=admin,$BASE" --password-env LDAP_TEST_EMPTY whoami
contains "empty password message" "unauthenticated bind"
expect 2 "simple bind over plaintext refused" "$LDAP" -H "ldap://localhost:$PORT" --tls none --allow-plaintext "${ADMIN[@]}" whoami
expect 2 "--tls none needs --allow-plaintext" "$LDAP" -H "ldap://localhost:$PORT" --tls none whoami
expect 0 "anonymous over plaintext with --allow-plaintext" "$LDAP" -H "ldap://localhost:$PORT" --tls none --allow-plaintext whoami
expect 4 "wrong password is an auth failure" env LDAP_TEST_PW=wrong "$LDAP" "${S[@]}" "${ADMIN[@]}" whoami
expect 2 "ntlm is Windows-only" "$LDAP" "${S[@]}" -M ntlm whoami
expect 2 "certificate files are refused" "$LDAP" "${S[@]}" --client-cert "$D/client.p12" whoami

echo "Data"
cat > data.ldif <<EOF
dn: $BASE
objectClass: dcObject
objectClass: organization
dc: example
o: Example

dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,$BASE
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Liddell
userPassword: alicepw

dn: uid=bob,ou=people,$BASE
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Builder
description:: w6l0w6k=

dn: uid=carol,ou=people,$BASE
objectClass: inetOrgPerson
uid: carol
cn: Carol (admin)
sn: Smith, Jr.
EOF
expect 0 "add from LDIF on stdin" sh -c "\"$LDAP\" ${S[*]@Q} ${ADMIN[*]@Q} add --file - < data.ldif"
expect 0 "add with --dn template (escaped comma)" "$LDAP" "${S[@]}" "${ADMIN[@]}" add --dn 'cn={cn},ou=people,dc=example,dc=test' -a 'cn=Doe, John' --attr objectClass=inetOrgPerson --attr 'cn=Doe, John' --attr sn=Doe
expect 0 "the escaped DN exists" "$LDAP" "${S[@]}" -o jsonl search -b 'ou=people,dc=example,dc=test' -f '(sn=Doe)' dn
contains "DN was escaped (server normalises to \\2C)" 'cn=Doe\\2C John,ou=people'
expect 0 "search with paging (page size 2)" "$LDAP" "${S[@]}" -o jsonl search -b "$BASE" -f '(objectClass=inetOrgPerson)' --page-size 2 uid
[[ "$(grep -c '"dn"' <<<"$OUT")" == 4 ]] && ok "paging returned all 4 entries" || bad "paging returned all 4 entries" "$OUT"
expect 0 "filter template neutralises injection" "$LDAP" "${S[@]}" -o jsonl search -b "$BASE" -f '(uid={u})' -a 'u=*)(uid=*' uid
[[ -z "$OUT" ]] && ok "injected filter matched nothing" || bad "injected filter matched nothing" "$OUT"
expect 0 "template with literal wildcard" "$LDAP" "${S[@]}" -o jsonl search -b "$BASE" -f '(cn={q}*)' -a 'q=Carol (' cn
contains "prefix search with escaped parens" "Carol (admin)"
expect 2 "malformed filter rejected before sending" "$LDAP" "${S[@]}" search -b "$BASE" -f '(uid=a'
expect 0 "default base from namingContexts" "$LDAP" "${S[@]}" -o jsonl search -f '(uid=bob)' description
contains "UTF-8 value in JSON" "été"
expect 0 "LDIF output base64-encodes non-ASCII" "$LDAP" "${S[@]}" -o ldif search -b "uid=bob,ou=people,$BASE" -s base description
contains "LDIF base64" "description:: w6l0w6k="
expect 0 "CSV output" "$LDAP" "${S[@]}" -o csv search -b "ou=people,$BASE" -f '(uid=carol)' sn
contains "CSV quoting" '"Smith, Jr."'
expect 0 "modify replace/add" "$LDAP" "${S[@]}" "${ADMIN[@]}" modify --dn "uid=bob,ou=people,$BASE" --replace mail=bob@example.test --add telephoneNumber=123
expect 0 "compare true" "$LDAP" "${S[@]}" compare --dn "uid=bob,ou=people,$BASE" --attr mail --value bob@example.test
expect 1 "compare false exits 1" "$LDAP" "${S[@]}" compare --dn "uid=bob,ou=people,$BASE" --attr mail --value nope@example.test
expect 0 "modrdn" "$LDAP" "${S[@]}" "${ADMIN[@]}" modrdn --dn "uid=bob,ou=people,$BASE" --new-rdn 'uid={n}' -a n=robert
expect 42 "renamed entry is gone (noSuchObject = 10+32)" "$LDAP" "${S[@]}" search -b "uid=bob,ou=people,$BASE" -s base
expect 0 "--dry-run prints without sending" "$LDAP" "${S[@]}" "${ADMIN[@]}" --dry-run delete "uid=robert,ou=people,$BASE"
contains "dry-run output" "changetype: delete"

echo "Extended operations"
expect 0 "passwd exop (admin reset)" env NEWPW=n3w-Passw0rd "$LDAP" "${S[@]}" "${ADMIN[@]}" passwd --dn "uid=alice,ou=people,$BASE" --new-password-env NEWPW --method exop
expect 0 "bind with the new password" env P=n3w-Passw0rd "$LDAP" "${S[@]}" -D "uid=alice,ou=people,$BASE" --password-env P whoami
contains "whoami as alice" "uid=alice"
expect 0 "exop by name" "$LDAP" "${S[@]}" exop whoami
expect 0 "EXTERNAL bind with inline PKCS#12" "$LDAP" "${S[@]}" -M external --client-cert env:LDAP_TEST_P12 --client-cert-password-env LDAP_TEST_P12_PW whoami
contains "EXTERNAL maps the certificate to alice" "dn:uid=alice,ou=people,dc=example,dc=test"
expect 2 "wrong PKCS#12 password" env LDAP_TEST_P12_PW=nope "$LDAP" "${S[@]}" -M external --client-cert env:LDAP_TEST_P12 --client-cert-password-env LDAP_TEST_P12_PW whoami

echo "Probe"
expect 0 "probe prints chain and RootDSE" "$LDAP" "${S[@]}" probe --print-ca
contains "probe shows TLS version" "tls: TLSv1."
contains "probe shows the server cert" "cert[0]: localhost"
contains "probe shows supported mechs" "supportedSASLMechanisms: GSSAPI"

echo "Subtree delete (client-side)"
expect 0 "delete --subtree" "$LDAP" "${S[@]}" "${ADMIN[@]}" delete --subtree "ou=people,$BASE"
expect 42 "subtree is gone" "$LDAP" "${S[@]}" search -b "ou=people,$BASE"

echo "Offline helpers"
expect 0 "escape filter" "$LDAP" escape filter 'a*(b)\'
contains "filter escaped" 'a\2a\28b\29\5c'
expect 0 "dn build" "$LDAP" dn build 'CN={cn},DC=x' -a 'cn= #lead,trail '
contains "dn built" 'CN=\ #lead\,trail\ ,DC=x'

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL == 0 ]]
