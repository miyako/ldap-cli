#!/usr/bin/env bash
# Developer ID sign (hardened runtime) and notarize the universal macOS binary.
# Usage: scripts/sign-macos.sh <path/to/ldap> <output.zip>
# Env: APPLE_DEVELOPER_ID_CERTIFICATE (base64 .p12), APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD,
#      KEYCHAIN_PASSWORD, NOTARYTOOL_APPLE_ID, NOTARYTOOL_TEAM_ID, NOTARYTOOL_PASSWORD
set -euo pipefail

BIN="$1"
OUT="$2"
: "${APPLE_DEVELOPER_ID_CERTIFICATE:?}" "${APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD:?}" "${KEYCHAIN_PASSWORD:?}"
: "${NOTARYTOOL_APPLE_ID:?}" "${NOTARYTOOL_TEAM_ID:?}" "${NOTARYTOOL_PASSWORD:?}"

WORK="$(mktemp -d)"
KEYCHAIN="$WORK/signing.keychain-db"
cleanup() {
  security delete-keychain "$KEYCHAIN" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Temporary keychain holding only the Developer ID identity.
echo "$APPLE_DEVELOPER_ID_CERTIFICATE" | base64 --decode > "$WORK/cert.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$WORK/cert.p12" -k "$KEYCHAIN" -P "$APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN" | awk -F'"' '/Developer ID Application/ {print $2; exit}')"
[[ -n "$IDENTITY" ]] || { echo "no Developer ID Application identity in the certificate" >&2; exit 1; }

# A CLI needs no entitlements; hardened runtime + secure timestamp are required for notarization.
codesign --force --options runtime --timestamp --identifier com.github.miyako.ldap-cli --sign "$IDENTITY" "$BIN"
codesign --verify --strict --verbose=2 "$BIN"
lipo -info "$BIN"

STAGE="$WORK/stage"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/"
cp -R licenses "$STAGE/licenses"
cp README.md "$STAGE/"
( cd "$STAGE" && ditto -c -k --keepParent . "$WORK/notarize.zip" )

xcrun notarytool submit "$WORK/notarize.zip" \
  --apple-id "$NOTARYTOOL_APPLE_ID" --team-id "$NOTARYTOOL_TEAM_ID" --password "$NOTARYTOOL_PASSWORD" \
  --wait --output-format json > "$WORK/notarization.json"
cat "$WORK/notarization.json"
STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$WORK/notarization.json")"
if [[ "$STATUS" != "Accepted" ]]; then
  ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/notarization.json")"
  xcrun notarytool log "$ID" --apple-id "$NOTARYTOOL_APPLE_ID" --team-id "$NOTARYTOOL_TEAM_ID" --password "$NOTARYTOOL_PASSWORD" || true
  exit 1
fi
# Bare executables cannot be stapled; Gatekeeper checks the ticket online.
mkdir -p "$(dirname "$OUT")"
( cd "$STAGE" && zip -qry "$OLDPWD/$OUT" . )
echo "signed and notarized: $OUT"
