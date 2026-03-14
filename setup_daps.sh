#!/bin/bash
# =============================================================================
# setup_daps.sh — Adapta el DAPS del IDS Testbed para los 4 workers FL
#
# Sigue EXACTAMENTE el mismo patrón que register_connector.sh del testbed:
#   - Genera un certificado X.509 por worker
#   - El client_id = SKI:keyid:AKI  (igual que connectorA/B en el testbed)
#   - token_endpoint_auth_method: private_key_jwt  (no client_secret)
#   - transportCertsSha256 = SHA256 del certificado (sin dos puntos, minúsculas)
#   - import_certfile apunta al .cert del worker
#
# PREREQUISITO:
#   Copia desde el IDS Testbed los siguientes ficheros a las rutas indicadas:
#     DAPS/config/       → omejdn/config/
#     DAPS/keys/omejdn/  → omejdn/keys/omejdn/   (contiene omejdn.key)
#     DAPS/keys/TLS/     → omejdn/keys/TLS/       (daps.cert + daps.key para nginx)
#     DAPS/nginx.conf    → omejdn/nginx.conf
#     DAPS/keys/broker.cert → omejdn/keys/broker.cert
#     MetadataBroker/isstbroker-keystore.jks → broker/isstbroker-keystore.jks
#     MetadataBroker/server.crt              → broker/server.crt
#     MetadataBroker/server.key              → broker/server.key
#
# Ejecutar UNA SOLA VEZ desde la raíz del proyecto:
#   chmod +x setup_daps.sh && ./setup_daps.sh
#
# Lo que hace este script:
#   1. Crea los directorios necesarios
#   2. Genera certificados X.509 para workers 1-4 (mismo formato que connectorA/B)
#   3. Registra los 4 workers en clients.yml (mismo formato que register_connector.sh)
#   4. Genera keystores P12 para que cada ECC obtenga token del DAPS
# =============================================================================

set -e

KEYS_DIR="omejdn/keys"
CLIENTS_DIR="${KEYS_DIR}/clients"
CONFIG_DIR="omejdn/config"
CERTS_DIR="certs"

echo "=== Setup DAPS — adaptación IDS Testbed para 4 workers FL ==="
echo ""

# ---------------------------------------------------------------------------
# 0. Directorios
# ---------------------------------------------------------------------------
mkdir -p "${KEYS_DIR}/omejdn"
mkdir -p "${KEYS_DIR}/TLS"
mkdir -p "${CLIENTS_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p broker
mkdir -p "${CERTS_DIR}"

# ---------------------------------------------------------------------------
# 1. Verificar que los ficheros del testbed están copiados
# ---------------------------------------------------------------------------
echo "[0] Verificando ficheros del IDS Testbed..."

MISSING=0
for f in \
    "${KEYS_DIR}/omejdn/omejdn.key" \
    "${KEYS_DIR}/TLS/daps.cert" \
    "${KEYS_DIR}/TLS/daps.key" \
    "${CONFIG_DIR}/omejdn.yml" \
    "${CONFIG_DIR}/scope_description.yml" \
    "${CONFIG_DIR}/scope_mapping.yml" \
    "broker/isstbroker-keystore.jks" \
    "broker/server.crt" \
    "broker/server.key"
do
    if [ ! -f "${f}" ]; then
        echo "  ✗ Falta: ${f}"
        MISSING=1
    else
        echo "  ✔ OK:    ${f}"
    fi
done

if [ "${MISSING}" = "1" ]; then
    echo ""
    echo "ERROR: Copia los ficheros del IDS Testbed indicados arriba antes de continuar."
    echo "       Ver sección PREREQUISITO en la cabecera de este script."
    exit 1
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Generar certificados para workers 1-4
#    Mismo patrón que connectorA.cert / connectorB.cert del testbed:
#    Clave RSA-2048, certificado autofirmado con SKI y AKI
# ---------------------------------------------------------------------------
echo "[1] Generando certificados X.509 para workers 1-4..."

for i in 1 2 3 4; do
    WORKER="worker${i}"
    CERT_FILE="${KEYS_DIR}/${WORKER}.cert"
    KEY_FILE="${KEYS_DIR}/${WORKER}.key"

    if [ -f "${CERT_FILE}" ]; then
        echo "  ↷ ${CERT_FILE} ya existe — omitiendo generación"
        continue
    fi

    # Generar clave privada y certificado con extensiones para SKI/AKI
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${KEY_FILE}" \
        -out    "${CERT_FILE}" \
        -days   3650 \
        -subj   "//C=ES/L=Bilbao/O=TFG-FL/OU=IDS-FL-Workers/CN=${WORKER}" \
        -addext "subjectKeyIdentifier=hash" \
        -addext "authorityKeyIdentifier=keyid:always" \
        2>/dev/null

    echo "  ✔ ${CERT_FILE}"
    echo "  ✔ ${KEY_FILE}"
done

echo ""

# ---------------------------------------------------------------------------
# 3. Registrar workers en clients.yml
#    Sigue exactamente el mismo algoritmo que register_connector.sh del testbed
# ---------------------------------------------------------------------------
echo "[2] Registrando workers en clients.yml..."

# Escribir cabecera — el broker del testbed ya no se incluye porque
# usamos el broker del testbed tal cual; solo añadimos nuestros workers
CLIENTS_YML="${CONFIG_DIR}/clients.yml"

# Conservar la entrada del broker si ya estaba (viene del testbed)
# y recrear desde cero solo las entradas de workers
BROKER_BLOCK=""
if [ -f "${CLIENTS_YML}" ]; then
    # Extraer bloque del broker (desde "- client_id" hasta el siguiente "- client_id" o EOF)
    BROKER_BLOCK=$(awk '/client_name: broker/{found=1} found{print} /client_name: (connector|worker)/{if(found && !/broker/)exit}' "${CLIENTS_YML}" 2>/dev/null || true)
fi

# Reconstruir clients.yml: broker primero, luego workers
> "${CLIENTS_YML}"

# Re-añadir entrada del broker si existía
if grep -q "client_name: broker" "${KEYS_DIR}/broker.cert" 2>/dev/null || [ -f "${KEYS_DIR}/broker.cert" ]; then
    BROKER_CERT="${KEYS_DIR}/broker.cert"

    SKI="$(openssl x509 -in "${BROKER_CERT}" -noout -text 2>/dev/null | grep -A1 "Subject Key Identifier" | tail -n 1 | tr -d ' ')"
    AKI="$(openssl x509 -in "${BROKER_CERT}" -noout -text 2>/dev/null | grep -A1 "Authority Key Identifier" | tail -n 1 | tr -d ' ')"
    BROKER_SHA="$(openssl x509 -in "${BROKER_CERT}" -noout -sha256 -fingerprint 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d ':' | sed 's/.*=//')"

    if echo "${AKI}" | grep -q "keyid"; then
        BROKER_CLIENT_ID="${SKI}:${AKI}"
    else
        BROKER_CLIENT_ID="${SKI}:keyid:${AKI}"
    fi

    cat >> "${CLIENTS_YML}" << EOF
- client_id: ${BROKER_CLIENT_ID}
  client_name: broker
  grant_types: client_credentials
  token_endpoint_auth_method: private_key_jwt
  scope: idsc:IDS_CONNECTOR_ATTRIBUTES_ALL
  attributes:
  - key: idsc
    value: IDS_CONNECTOR_ATTRIBUTES_ALL
  - key: securityProfile
    value: idsc:BASE_SECURITY_PROFILE
  - key: referringConnector
    value: http://broker.demo
  - key: "@type"
    value: ids:DatPayload
  - key: "@context"
    value: https://w3id.org/idsa/contexts/context.jsonld
  - key: transportCertsSha256
    value: ${BROKER_SHA}
  import_certfile: keys/broker.cert
EOF
    echo "  ✔ broker registrado (desde ${BROKER_CERT})"
fi

# Registrar workers 1-4 — mismo algoritmo que register_connector.sh
for i in 1 2 3 4; do
    WORKER="worker${i}"
    CERT_FILE="${KEYS_DIR}/${WORKER}.cert"

    SKI="$(openssl x509 -in "${CERT_FILE}" -noout -text 2>/dev/null | grep -A1 "Subject Key Identifier" | tail -n 1 | tr -d ' ')"
    AKI="$(openssl x509 -in "${CERT_FILE}" -noout -text 2>/dev/null | grep -A1 "Authority Key Identifier" | tail -n 1 | tr -d ' ')"
    CERT_SHA="$(openssl x509 -in "${CERT_FILE}" -noout -sha256 -fingerprint 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d ':' | sed 's/.*=//')"

    # Mismo if/else que register_connector.sh
    if echo "${AKI}" | grep -q "keyid"; then
        CLIENT_ID="${SKI}:${AKI}"
    else
        CLIENT_ID="${SKI}:keyid:${AKI}"
    fi

    cat >> "${CLIENTS_YML}" << EOF
- client_id: ${CLIENT_ID}
  client_name: ${WORKER}
  grant_types: client_credentials
  token_endpoint_auth_method: private_key_jwt
  scope: idsc:IDS_CONNECTOR_ATTRIBUTES_ALL
  attributes:
  - key: idsc
    value: IDS_CONNECTOR_ATTRIBUTES_ALL
  - key: securityProfile
    value: idsc:BASE_SECURITY_PROFILE
  - key: referringConnector
    value: http://${WORKER}.demo
  - key: "@type"
    value: ids:DatPayload
  - key: "@context"
    value: https://w3id.org/idsa/contexts/context.jsonld
  - key: transportCertsSha256
    value: ${CERT_SHA}
  import_certfile: keys/${WORKER}.cert
EOF
    echo "  ✔ ${WORKER} registrado  (client_id: ${CLIENT_ID:0:30}...)"
done

echo ""

# ---------------------------------------------------------------------------
# 4. Generar keystores P12 para cada worker
#    El ECC los usa para autenticarse ante el DAPS (application.keyStoreName)
#    El P12 contiene: clave privada + certificado del worker
# ---------------------------------------------------------------------------
echo "[3] Generando keystores P12 para los ECCs..."

for i in 1 2 3 4; do
    WORKER="worker${i}"
    KEY_FILE="${KEYS_DIR}/${WORKER}.key"
    CERT_FILE="${KEYS_DIR}/${WORKER}.cert"
    P12_FILE="${CERTS_DIR}/${WORKER}-daps.p12"

    if [ -f "${P12_FILE}" ]; then
        echo "  ↷ ${P12_FILE} ya existe — omitiendo"
        continue
    fi

    openssl pkcs12 -export \
        -in      "${CERT_FILE}" \
        -inkey   "${KEY_FILE}" \
        -name    "${WORKER}" \
        -out     "${P12_FILE}" \
        -passout pass: \
        2>/dev/null

    echo "  ✔ ${P12_FILE}"
done

echo ""

# ---------------------------------------------------------------------------
# Resumen final
# ---------------------------------------------------------------------------
echo "=== Setup completado ==="
echo ""
echo "Estructura generada:"
echo "  omejdn/config/clients.yml    ← workers 1-4 registrados"
echo "  omejdn/keys/worker{1-4}.cert ← certificados IDS"
echo "  certs/worker{1-4}-daps.p12   ← keystores para los ECCs"
echo ""
echo "Comandos para arrancar:"
echo "  docker-compose up -d omejdn ids-broker broker-fuseki"
echo "  sleep 20"
echo "  docker-compose up -d"
echo ""
echo "Verificación:"
echo "  curl -k https://localhost:443/auth/jwks.json    # DAPS JWKS"
echo "  curl http://localhost:8080/infrastructure       # Broker catálogo"