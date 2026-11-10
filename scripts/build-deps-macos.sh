#!/usr/bin/env bash
# Build the vendored macOS dependencies as universal (arm64 + x86_64) static libraries:
#   OpenSSL 3 (LTS) and OpenLDAP 2.6 (liblber + libldap only).
# Cyrus SASL is NOT vendored: we link the system libsasl2, whose plugins
# (GSSAPI built against GSS.framework, EXTERNAL, ...) match its ABI.
#
# Output: deps/macos/{include,lib}. Sources are pinned by version and SHA-256 in deps.lock.
# Usage: scripts/build-deps-macos.sh [--clean]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/deps.lock"
OUT="$ROOT/deps/macos"
WORK="$ROOT/deps/.build-macos"
MIN_MACOS="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
ARCHS=(arm64 x86_64)
JOBS="$(sysctl -n hw.ncpu)"

lock_get() { awk -F= -v k="$1" '$1==k {print $2}' "$LOCK"; }

OPENSSL_VERSION="$(lock_get openssl.version)"
OPENSSL_SHA256="$(lock_get openssl.sha256)"
OPENLDAP_VERSION="$(lock_get openldap.version)"
OPENLDAP_SHA256="$(lock_get openldap.sha256)"

if [[ "${1:-}" == "--clean" ]]; then rm -rf "$WORK" "$OUT"; fi
if [[ -f "$OUT/.stamp" && "$(cat "$OUT/.stamp")" == "openssl-$OPENSSL_VERSION openldap-$OPENLDAP_VERSION $MIN_MACOS" ]]; then
  echo "deps up to date: $OUT"; exit 0
fi
mkdir -p "$WORK/dl" "$OUT/include" "$OUT/lib"

fetch() { # url file expected_sha
  local url="$1" file="$WORK/dl/$2" want="$3"
  [[ -f "$file" ]] || curl -fsSL --retry 3 -o "$file" "$url"
  local got; got="$(shasum -a 256 "$file" | awk '{print $1}')"
  if [[ -z "$want" ]]; then
    echo "error: no sha256 pinned for $2 in deps.lock (downloaded file has $got)" >&2; exit 1
  fi
  if [[ "$got" != "$want" ]]; then
    echo "error: sha256 mismatch for $2: expected $want, got $got" >&2; exit 1
  fi
}

fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
      "openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_SHA256"
fetch "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-$OPENLDAP_VERSION.tgz" \
      "openldap-$OPENLDAP_VERSION.tgz" "$OPENLDAP_SHA256"

SDK="$(xcrun --sdk macosx --show-sdk-path)"

for arch in "${ARCHS[@]}"; do
  P="$WORK/$arch/prefix"; mkdir -p "$P"
  CFLAGS_ARCH="-arch $arch -mmacosx-version-min=$MIN_MACOS -isysroot $SDK -O2 -fvisibility=hidden"

  # ---- OpenSSL ----
  if [[ ! -f "$P/lib/libssl.a" ]]; then
    rm -rf "$WORK/$arch/openssl"; mkdir -p "$WORK/$arch/openssl"
    tar -xzf "$WORK/dl/openssl-$OPENSSL_VERSION.tar.gz" -C "$WORK/$arch/openssl" --strip-components 1
    ( cd "$WORK/$arch/openssl"
      target=darwin64-arm64-cc; [[ $arch == x86_64 ]] && target=darwin64-x86_64-cc
      ./Configure "$target" no-shared no-tests no-apps no-docs no-engine \
        --prefix="$P" --libdir=lib --openssldir=/private/etc/ssl \
        "-mmacosx-version-min=$MIN_MACOS" "-isysroot" "$SDK" -fvisibility=hidden
      make -j"$JOBS" build_libs >/dev/null
      make install_dev >/dev/null )
  fi

  # ---- OpenLDAP (client libraries only) ----
  if [[ ! -f "$P/lib/libldap.a" ]]; then
    rm -rf "$WORK/$arch/openldap"; mkdir -p "$WORK/$arch/openldap"
    tar -xzf "$WORK/dl/openldap-$OPENLDAP_VERSION.tgz" -C "$WORK/$arch/openldap" --strip-components 1
    ( cd "$WORK/$arch/openldap"
      host=aarch64-apple-darwin; [[ $arch == x86_64 ]] && host=x86_64-apple-darwin
      CC="clang" CFLAGS="$CFLAGS_ARCH" \
      CPPFLAGS="-I$P/include -I$SDK/usr/include/sasl" LDFLAGS="-L$P/lib -arch $arch" \
      ./configure --host="$host" --prefix="$P" \
        --disable-slapd --disable-shared --enable-static --disable-debug \
        --with-tls=openssl --with-cyrus-sasl --without-fetch \
        ac_cv_func_memcmp_working=yes >/dev/null
      make -C include >/dev/null
      make -j"$JOBS" -C libraries/liblber liblber.la >/dev/null
      make -j"$JOBS" -C libraries/libldap libldap.la >/dev/null
      cp libraries/liblber/.libs/liblber.a libraries/libldap/.libs/libldap.a "$P/lib/"
      mkdir -p "$P/include/openldap"
      cp include/{ldap,lber,ldap_cdefs,ldap_features,lber_types,ldap_schema,ldap_utf8}.h "$P/include/openldap/" )
  fi
done

# ---- lipo into universal libraries ----
for lib in libssl libcrypto liblber libldap; do
  lipo -create "$WORK/arm64/prefix/lib/$lib.a" "$WORK/x86_64/prefix/lib/$lib.a" -output "$OUT/lib/$lib.a"
done
rm -rf "$OUT/include"; mkdir -p "$OUT/include"
cp -R "$WORK/arm64/prefix/include/openssl" "$OUT/include/"
cp -R "$WORK/arm64/prefix/include/openldap/." "$OUT/include/"
echo "openssl-$OPENSSL_VERSION openldap-$OPENLDAP_VERSION $MIN_MACOS" > "$OUT/.stamp"
echo "built universal deps into $OUT"
lipo -info "$OUT"/lib/*.a
