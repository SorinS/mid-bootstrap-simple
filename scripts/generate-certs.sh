#!/bin/bash
#
# Generate TLS certificates for MID Bootstrap Server
#
# Usage:
#   ./generate-certs.sh                    # Use default IP (192.168.1.161)
#   ./generate-certs.sh 10.0.0.50          # Use custom IP
#   ./generate-certs.sh 10.0.0.50 my.dns   # Use custom IP and DNS name
#
# Output files:
#   bootstrap-ca.pem      - CA certificate (distribute to clients)
#   bootstrap-ca-key.pem  - CA private key (keep secure!)
#   bootstrap-cert.pem    - Server certificate
#   bootstrap-key.pem     - Server private key
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
SERVER_IP="${1:-192.168.1.161}"
SERVER_DNS="${2:-bootstrap.local}"
CA_DAYS=3650          # 10 years for CA
SERVER_DAYS=365       # 1 year for server cert
CA_KEY_BITS=4096
SERVER_KEY_BITS=2048

echo "Generating MID Bootstrap Server TLS certificates..."
echo "  Server IP:  $SERVER_IP"
echo "  Server DNS: $SERVER_DNS"
echo ""

# Generate CA private key
echo "[1/4] Generating CA private key..."
openssl genrsa -out bootstrap-ca-key.pem $CA_KEY_BITS 2>/dev/null

# Generate CA certificate
echo "[2/4] Generating CA certificate..."
openssl req -new -x509 \
    -days $CA_DAYS \
    -key bootstrap-ca-key.pem \
    -out bootstrap-ca.pem \
    -subj "/C=US/ST=State/L=City/O=HomeNet/CN=Bootstrap CA" \
    2>/dev/null

# Generate server private key
echo "[3/4] Generating server private key..."
openssl genrsa -out bootstrap-key.pem $SERVER_KEY_BITS 2>/dev/null

# Generate server certificate
echo "[4/4] Generating server certificate..."

cat > /tmp/bootstrap-ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_DNS
DNS.2 = localhost
IP.1 = $SERVER_IP
IP.2 = 127.0.0.1
EOF

openssl req -new \
    -key bootstrap-key.pem \
    -out /tmp/bootstrap.csr \
    -subj "/C=US/ST=State/L=City/O=HomeNet/CN=$SERVER_DNS" \
    2>/dev/null

openssl x509 -req \
    -in /tmp/bootstrap.csr \
    -CA bootstrap-ca.pem \
    -CAkey bootstrap-ca-key.pem \
    -CAcreateserial \
    -out bootstrap-cert.pem \
    -days $SERVER_DAYS \
    -sha256 \
    -extfile /tmp/bootstrap-ext.cnf \
    2>/dev/null

# Cleanup temp files
rm -f /tmp/bootstrap.csr /tmp/bootstrap-ext.cnf bootstrap-ca.srl 2>/dev/null

echo ""
echo "Done! Files created:"
ls -la bootstrap-*.pem
echo ""
echo "Certificate SANs:"
openssl x509 -in bootstrap-cert.pem -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*/  /'
echo ""
echo "Usage:"
echo "  ./mid-bootstrap-server -tls-cert certs/bootstrap-cert.pem -tls-key certs/bootstrap-key.pem ..."
