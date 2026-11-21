#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
[ ! -e .env ] && [ ! -e secrets/signing.p12 ] || { echo 'Configuration exists; refusing to overwrite.' >&2; exit 1; }
umask 077
mkdir -p secrets
secret() { openssl rand -base64 32; }
database=$(secret)
mfa=$(secret)
store=$(secret)
client=$(secret)
bootstrap=$(secret)
if [ "${GITHUB_ACTIONS:-false}" = true ]; then
  for value in "$database" "$mfa" "$store" "$client" "$bootstrap"; do printf '::add-mask::%s\n' "$value"; done
fi
export GK_STORE_PASSWORD="$store"
keytool -genkeypair -alias signing -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 365 -dname 'CN=Gatekeeper local' -storetype PKCS12 -keystore secrets/signing.p12 -storepass:env GK_STORE_PASSWORD >/dev/null 2>&1
unset GK_STORE_PASSWORD
printf 'DATABASE_PASSWORD=%s\nMFA_ENCRYPTION_KEY=%s\nSIGNING_KEYSTORE_PASSWORD=%s\nDEMO_CLIENT_SECRET=%s\nBOOTSTRAP_LOGIN=operator@example.test\nBOOTSTRAP_PASSWORD=%s\n' "$database" "$mfa" "$store" "$client" "$bootstrap" > .env
# Container uid 10001 needs read access to this local-only, read-only bind-mounted store.
chmod 644 secrets/signing.p12
echo 'Local configuration generated; credentials are ignored by Git.'
