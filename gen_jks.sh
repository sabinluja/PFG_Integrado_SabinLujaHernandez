#!/bin/bash
# Genera JKS directamente desde cert+key sin pasar por P12
# Usa keytool importkeystore desde un P12 generado con OpenSSL 1.x (Debian/Ubuntu)

apt-get update -qq && apt-get install -y -qq openssl 2>/dev/null

for i in 1 2 3 4; do
  # OpenSSL en Debian/Ubuntu usa formato legacy compatible con Java 11
  openssl pkcs12 -export \
    -in    /keys/worker${i}.cert \
    -inkey /keys/worker${i}.key \
    -name  worker${i} \
    -out   /certs/worker${i}-daps.p12 \
    -passout pass:ids2024 \
    -legacy 2>/dev/null || \
  openssl pkcs12 -export \
    -in    /keys/worker${i}.cert \
    -inkey /keys/worker${i}.key \
    -name  worker${i} \
    -out   /certs/worker${i}-daps.p12 \
    -passout pass:ids2024

  keytool -importkeystore \
    -srckeystore  /certs/worker${i}-daps.p12 \
    -srcstoretype PKCS12 \
    -srcstorepass ids2024 \
    -destkeystore /certs/worker${i}-daps.jks \
    -deststoretype JKS \
    -deststorepass ids2024 \
    -noprompt

  rm /certs/worker${i}-daps.p12
  echo "worker${i}-daps.jks OK"
done