#!/usr/bin/env bash
# Generate a throwaway development PKI for docker-compose.tls.yml:
#   ca.pem / ca-key.pem             internal CA (the only trust anchor)
#   gateway.pem / gateway-key.pem   API server cert (localhost, gateway)
#   upstream.pem / upstream-key.pem upstream server cert (upstream)
#   gateway-client.pem / -key.pem   client cert the gateway presents upstream
#
# Usage: ./scripts/gen-dev-certs.sh [output-dir]   (default deploy/tls/dev)
# For development only: keys are world-readable so the distroless nonroot
# user can read the bind mount. Use a real secret store in production.
set -euo pipefail

OUT="${1:-deploy/tls/dev}"
DAYS=30
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca-key.pem -out ca.pem -days "$DAYS" -subj "/CN=identity-gateway dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue() { # name usage subjectAltName
  local name="$1" usage="$2" san="$3" ext
  ext=$(mktemp)
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=$usage"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$ext"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$name-key.pem" -out "$name.csr" -subj "/CN=$name" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days "$DAYS" -extfile "$ext" 2>/dev/null
  rm -f "$name.csr" "$ext"
}

issue gateway serverAuth "DNS:localhost,DNS:gateway,IP:127.0.0.1"
issue upstream serverAuth "DNS:upstream"
issue identity-gateway clientAuth ""
mv identity-gateway.pem gateway-client.pem
mv identity-gateway-key.pem gateway-client-key.pem
rm -f ca.srl
chmod 644 ./*.pem
chmod 600 ca-key.pem  # the CA key never needs to enter a container
echo "wrote dev PKI to $OUT"
