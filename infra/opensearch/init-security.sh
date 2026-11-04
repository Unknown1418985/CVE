#!/bin/bash
# One-shot initialisation for OpenSearch, run as the `opensearch-init` container (root) using
# the OpenSearch image itself (it ships keytool and the security plugin's hash tool).
#
#  1. Creates a local certificate authority and a node certificate (PKCS#12) once, in the
#     `opensearch-certs` volume. The CA certificate (public part only) is copied to the
#     `platform-ca` volume so clients can verify OpenSearch over TLS.
#  2. Renders the security plugin configuration into the `opensearch-security` volume with a
#     single `admin` user (bcrypt hash of OPENSEARCH_ADMIN_PASSWORD). Service users and roles
#     are created later through the REST API by the infra-provisioner.
#
# The security configuration is only read when the security index does not exist yet, i.e. on
# the very first start of a fresh data volume.
set -euo pipefail

: "${OPENSEARCH_ADMIN_PASSWORD:?OPENSEARCH_ADMIN_PASSWORD is required}"
: "${OPENSEARCH_KEYSTORE_PASSWORD:?OPENSEARCH_KEYSTORE_PASSWORD is required}"
[ "${#OPENSEARCH_ADMIN_PASSWORD}" -ge 16 ] || { echo "OPENSEARCH_ADMIN_PASSWORD must be at least 16 characters" >&2; exit 1; }
[ "${#OPENSEARCH_KEYSTORE_PASSWORD}" -ge 16 ] || { echo "OPENSEARCH_KEYSTORE_PASSWORD must be at least 16 characters" >&2; exit 1; }

HOME_DIR=/usr/share/opensearch
KEYTOOL="$HOME_DIR/jdk/bin/keytool"
CERTS=/certs
CA_OUT=/platform-ca
SECURITY_OUT=/security-config
PW="$OPENSEARCH_KEYSTORE_PASSWORD"
VALIDITY_DAYS=825

umask 077

if [ ! -s "$CERTS/node.p12" ] || [ ! -s "$CERTS/ca.p12" ]; then
  echo "opensearch-init: generating local CA and node certificate"
  rm -f "$CERTS"/*.p12 "$CERTS"/*.pem "$CERTS"/*.csr
  "$KEYTOOL" -genkeypair -noprompt -alias ca -keyalg RSA -keysize 4096 -validity 3650 \
    -dname "CN=CVE Platform Local CA,O=CVE Platform" -ext bc:c=ca:true,pathlen:0 \
    -ext KU=keyCertSign,cRLSign -keystore "$CERTS/ca.p12" -storetype PKCS12 -storepass "$PW"
  "$KEYTOOL" -exportcert -rfc -alias ca -keystore "$CERTS/ca.p12" -storepass "$PW" -file "$CERTS/ca.pem"

  "$KEYTOOL" -genkeypair -noprompt -alias node -keyalg RSA -keysize 3072 -validity "$VALIDITY_DAYS" \
    -dname "CN=opensearch,OU=CVE Platform,O=CVE Platform" -keystore "$CERTS/node.p12" \
    -storetype PKCS12 -storepass "$PW"
  "$KEYTOOL" -certreq -alias node -keystore "$CERTS/node.p12" -storepass "$PW" -file "$CERTS/node.csr"
  "$KEYTOOL" -gencert -rfc -alias ca -keystore "$CERTS/ca.p12" -storepass "$PW" \
    -infile "$CERTS/node.csr" -outfile "$CERTS/node.pem" -validity "$VALIDITY_DAYS" \
    -ext SAN=dns:opensearch,dns:localhost,ip:127.0.0.1 \
    -ext KU=digitalSignature,keyEncipherment -ext EKU=serverAuth,clientAuth
  cat "$CERTS/node.pem" "$CERTS/ca.pem" > "$CERTS/node-chain.pem"
  "$KEYTOOL" -importcert -noprompt -alias node -file "$CERTS/node-chain.pem" \
    -keystore "$CERTS/node.p12" -storepass "$PW"
  "$KEYTOOL" -importcert -noprompt -alias ca -file "$CERTS/ca.pem" \
    -keystore "$CERTS/truststore.p12" -storetype PKCS12 -storepass "$PW"
  rm -f "$CERTS/node.csr" "$CERTS/node-chain.pem"
else
  echo "opensearch-init: certificates already exist, keeping them"
fi

# Only the public CA certificate is shared with clients.
install -m 0644 "$CERTS/ca.pem" "$CA_OUT/platform-ca.pem"

echo "opensearch-init: rendering security configuration"
cp "$HOME_DIR"/config/opensearch-security/*.yml "$SECURITY_OUT/"
admin_hash="$("$HOME_DIR/plugins/opensearch-security/tools/hash.sh" -p "$OPENSEARCH_ADMIN_PASSWORD" | tail -n 1)"
case "$admin_hash" in
  '$2'*) ;;
  *) echo "opensearch-init: failed to hash the admin password" >&2; exit 1 ;;
esac
cat > "$SECURITY_OUT/internal_users.yml" <<YAML
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$admin_hash"
  reserved: true
  backend_roles:
    - "admin"
  description: "Platform administrator (bootstrap only; services use their own users)"
YAML

chown -R 1000:1000 "$CERTS" "$SECURITY_OUT"
chmod 0700 "$CERTS" "$SECURITY_OUT"
chmod 0600 "$CERTS"/*.p12
echo "opensearch-init: done"
