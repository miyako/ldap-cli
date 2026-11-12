#!/usr/bin/env bash
# Local MIT KDC + slapd regression. This is NOT real-AD CBT-policy acceptance.
# Requires Homebrew krb5, openldap and openssl@3. Uses only synthetic credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LDAP="${1:-$ROOT/target/debug/ldap}"
KRB="$(brew --prefix krb5)"
OL="$(brew --prefix openldap)"
SCHEMA="$(brew --prefix)/etc/openldap/schema"
OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
for tool in "$LDAP" "$KRB/sbin/krb5kdc" "$KRB/sbin/kadmin.local" "$OL/libexec/slapd"; do
  [[ -x "$tool" ]] || { echo "missing executable: $tool" >&2; exit 1; }
done
D="$(mktemp -d "${TMPDIR:-/tmp}/ldap-cli-kerberos.XXXXXX")"
KDC_PID=""
SLAPD_PID=""
cleanup() {
  [[ -z "$SLAPD_PID" ]] || { kill "$SLAPD_PID" 2>/dev/null || true; wait "$SLAPD_PID" 2>/dev/null || true; }
  [[ -z "$KDC_PID" ]] || { kill "$KDC_PID" 2>/dev/null || true; wait "$KDC_PID" 2>/dev/null || true; }
  rm -rf "$D"
}
trap cleanup EXIT
trap 'echo "Kerberos regression failed at line $LINENO" >&2; for log in "$D/setup.log" "$D/cert.log" "$D/kdc.log" "$D/slapd.log"; do [[ ! -f "$log" ]] || tail -8 "$log" >&2; done' ERR
export KRB5_CONFIG="$D/krb5.conf"
export KRB5_KDC_PROFILE="$D/kdc.conf"
export KRB5_KTNAME="$D/service.keytab"
export KRB5CCNAME="FILE:$D/ssocache"
export LDAP_CONFIG="$D/no-config.toml"
for port in 61088 61389 61636; do
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    echo "test port $port already occupied" >&2; exit 1
  fi
done
cat > "$KRB5_CONFIG" <<EOF
[libdefaults]
 default_realm = LDAPCLI.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
[realms]
 LDAPCLI.TEST = {
  kdc = 127.0.0.1:61088
 }
[domain_realm]
 localhost = LDAPCLI.TEST
EOF
cat > "$KRB5_KDC_PROFILE" <<EOF
[kdcdefaults]
 kdc_ports = 61088
 kdc_tcp_ports = 61088
[realms]
 LDAPCLI.TEST = {
  database_name = $D/principal
  key_stash_file = $D/stash
  acl_file = $D/kadm5.acl
 }
EOF
printf 'synthetic-master\nsynthetic-master\n' | "$KRB/sbin/kdb5_util" create -s -r LDAPCLI.TEST > "$D/setup.log" 2>&1
for user in alice bob; do
  printf 'synthetic-%s\nsynthetic-%s\n' "$user" "$user" |
    "$KRB/sbin/kadmin.local" -r LDAPCLI.TEST -q "addprinc $user" >> "$D/setup.log" 2>&1
done
"$KRB/sbin/kadmin.local" -r LDAPCLI.TEST -q "addprinc -randkey ldap/localhost" >> "$D/setup.log" 2>&1
"$KRB/sbin/kadmin.local" -r LDAPCLI.TEST -q "ktadd -k $KRB5_KTNAME ldap/localhost" >> "$D/setup.log" 2>&1
"$KRB/sbin/krb5kdc" -n -r LDAPCLI.TEST > "$D/kdc.log" 2>&1 &
KDC_PID=$!
for _ in $(seq 50); do
  nc -z 127.0.0.1 61088 2>/dev/null && break
  sleep 0.1
done
nc -z 127.0.0.1 61088 || { cat "$D/kdc.log"; exit 1; }

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$D/ca.key" -out "$D/ca.crt" \
  -days 1 -subj "/CN=ldap-cli Kerberos Test CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" > "$D/cert.log" 2>&1
"$OPENSSL" req -newkey rsa:2048 -nodes -keyout "$D/server.key" -out "$D/server.csr" \
  -subj "/CN=localhost" >> "$D/cert.log" 2>&1
"$OPENSSL" x509 -req -in "$D/server.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" \
  -CAcreateserial -out "$D/server.crt" -days 1 \
  -extfile <(printf "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n") >> "$D/cert.log" 2>&1
CA="$("$OPENSSL" x509 -in "$D/ca.crt" -outform DER | base64)"
mkdir "$D/db"
cat > "$D/slapd.conf" <<EOF
include $SCHEMA/core.schema
include $SCHEMA/cosine.schema
include $SCHEMA/inetorgperson.schema
pidfile $D/slapd.pid
TLSCertificateFile $D/server.crt
TLSCertificateKeyFile $D/server.key
sasl-host localhost
sasl-realm LDAPCLI.TEST
authz-regexp "^uid=([^,]+),cn=ldapcli.test,cn=gssapi,cn=auth\$" "uid=\$1,dc=example,dc=test"
access to * by users read by anonymous auth
database mdb
suffix "dc=example,dc=test"
directory $D/db
EOF
"$OL/sbin/slapadd" -f "$D/slapd.conf" <<EOF
dn: dc=example,dc=test
objectClass: dcObject
objectClass: organization
dc: example
o: LDAP CLI integration

dn: uid=alice,dc=example,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Alice

dn: uid=bob,dc=example,dc=test
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Bob
EOF
"$OL/libexec/slapd" -d 256 -f "$D/slapd.conf" -h "ldap://localhost:61389/ ldaps://localhost:61636/" > "$D/slapd.log" 2>&1 &
SLAPD_PID=$!
for _ in $(seq 50); do
  nc -z localhost 61636 2>/dev/null && break
  sleep 0.1
done
nc -z localhost 61636 || { cat "$D/slapd.log"; exit 1; }

S=(--uri ldaps://localhost:61636 --ca-cert "$CA" --mech gssapi --channel-binding require --password-stdin)
expect() {
  local wanted="$1"; shift
  local actual=0
  "$@" > "$D/output" 2>&1 || actual=$?
  if [[ "$actual" != "$wanted" ]]; then
    cat "$D/output"; echo "exit $actual, expected $wanted" >&2; exit 1
  fi
}
login() {
  local user="$1"
  printf 'synthetic-%s\n' "$user" | "$LDAP" "${S[@]}" --user "$user@LDAPCLI.TEST" whoami
}
echo "Explicit credentials without a pre-existing cache"
[[ ! -e "$D/ssocache" ]]
login alice > "$D/alice"
cat "$D/alice"
grep -qi alice "$D/alice"
[[ ! -e "$D/ssocache" ]]
echo "StartTLS with explicit credentials"
printf 'synthetic-alice\n' | expect 0 "$LDAP" --uri ldap://localhost:61389 --ca-cert "$CA" \
  --mech gssapi --channel-binding require --user alice@LDAPCLI.TEST --password-stdin whoami
echo "Default Alice tickets cannot override Bob's supplied credentials"
printf 'synthetic-alice\n' | "$KRB/bin/kinit" alice@LDAPCLI.TEST > "$D/kinit.log" 2>&1
BEFORE="$(shasum -a 256 "$D/ssocache")"
printf 'wrong-synthetic-password\n' | expect 4 "$LDAP" "${S[@]}" --user bob@LDAPCLI.TEST whoami
login bob > "$D/bob"
grep -qi bob "$D/bob"
[[ "$BEFORE" == "$(shasum -a 256 "$D/ssocache")" ]]
echo "Concurrent users remain separate"
PIDS=()
for i in 1 2 3 4; do
  login alice > "$D/alice-$i" & PIDS+=("$!")
  login bob > "$D/bob-$i" & PIDS+=("$!")
done
for pid in "${PIDS[@]}"; do wait "$pid"; done
for i in 1 2 3 4; do
  grep -qi alice "$D/alice-$i"
  grep -qi bob "$D/bob-$i"
done
[[ "$BEFORE" == "$(shasum -a 256 "$D/ssocache")" ]]
echo "Certificate trust and hostname failures happen before password authentication"
printf 'synthetic-alice\n' | expect 3 "$LDAP" --uri ldaps://localhost:61636 \
  --mech gssapi --channel-binding require --user alice@LDAPCLI.TEST --password-stdin whoami
printf 'synthetic-alice\n' | expect 3 "$LDAP" "${S[@]}" --tls-server-name wrong.invalid --user alice@LDAPCLI.TEST whoami
if [[ -n "${LDAP_KERBEROS_TEST_HOOK:-}" ]]; then
  # A test-owned component host can reuse this bounded fixture. Secrets are
  # synthetic and passed only through inherited environment, never argv/files.
  export LDAP_TEST_URI="ldaps://localhost:61636"
  export LDAP_TEST_CA_CERT="$CA"
  export LDAP_TEST_USER_A="alice@LDAPCLI.TEST"
  export LDAP_TEST_USER_B="bob@LDAPCLI.TEST"
  export LDAP_TEST_PASSWORD_A="synthetic-alice"
  export LDAP_TEST_PASSWORD_B="synthetic-bob"
  export LDAP_TEST_IDENTITY_A="dn:uid=alice,dc=example,dc=test"
  export LDAP_TEST_IDENTITY_B="dn:uid=bob,dc=example,dc=test"
  export LDAP_TEST_BASE="dc=example,dc=test"
  "$LDAP_KERBEROS_TEST_HOOK"
fi
echo "Local Kerberos regression passed. Real-AD Always-policy acceptance is still required."
