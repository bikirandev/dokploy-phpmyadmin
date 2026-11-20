#!/bin/sh
# Generates test-only certificates and SSH keys into /out. Run inside alpine.
set -eu
apk add --no-cache openssl openssh-keygen >/dev/null
cd /out

# A private CA and a server certificate for remote-tls.test
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=DB Portal Test CA" \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=remote-tls.test" \
  -keyout remote-tls.key -out remote-tls.csr 2>/dev/null
printf 'subjectAltName=DNS:remote-tls.test\nextendedKeyUsage=serverAuth\n' > remote-tls.ext
openssl x509 -req -days 30 -in remote-tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -extfile remote-tls.ext -out remote-tls.pem 2>/dev/null

# A self-signed certificate whose name matches strict.test
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=strict.test" \
  -addext "subjectAltName=DNS:strict.test" -keyout strict.key -out strict.pem 2>/dev/null

# The SSH key of the bastion user "deploy"
ssh-keygen -q -t ed25519 -N "" -C "dbportal-test" -f deploy_ed25519

# Test only: database containers must be able to read their keys.
chmod 0644 ./*.key ./*.pem deploy_ed25519 deploy_ed25519.pub
echo "fixtures generated"
