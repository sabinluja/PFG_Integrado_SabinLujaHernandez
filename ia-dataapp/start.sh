#!/bin/sh
# =============================================================================
# start.sh — Arranque de la instancia IA DataApp FL
# =============================================================================

INSTANCE_ID="${INSTANCE_ID:-1}"
CERT_DIR="/cert/dataapp"
KEY_FILE="${CERT_DIR}/key.pem"
CERT_FILE="${CERT_DIR}/cert.pem"
SHARED_TRUSTSTORE="/cert/truststoreEcc.jks"
ALIAS="dataapp-worker${INSTANCE_ID}"

echo "[start.sh] Arrancando IA DataApp FL — instancia #${INSTANCE_ID}"

mkdir -p "${CERT_DIR}"

# ── 1. Generar certificado propio ────────────────────────────────────────────
echo "[start.sh] Generando certificado para worker${INSTANCE_ID}..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${KEY_FILE}" \
    -out    "${CERT_FILE}" \
    -days 3650 \
    -subj "/CN=be-dataapp-worker${INSTANCE_ID}/O=IDS/C=ES" \
    -addext "subjectAltName=DNS:be-dataapp-worker${INSTANCE_ID},DNS:localhost" \
    2>/dev/null
echo "[start.sh] Certificado generado OK"

# ── 2. Importar en el truststore compartido con lock para evitar race condition
LOCKFILE="/cert/truststore.lock"
LOCK_ACQUIRED=0
for i in $(seq 1 30); do
    if mkdir "${LOCKFILE}" 2>/dev/null; then
        LOCK_ACQUIRED=1
        break
    fi
    sleep 1
done

if [ "${LOCK_ACQUIRED}" = "1" ]; then
    # Borrar alias si existe, luego importar
    keytool -delete \
        -keystore  "${SHARED_TRUSTSTORE}" \
        -storepass allpassword \
        -alias     "${ALIAS}" \
        -noprompt 2>/dev/null || true

    keytool -importcert \
        -keystore  "${SHARED_TRUSTSTORE}" \
        -storepass allpassword \
        -alias     "${ALIAS}" \
        -file      "${CERT_FILE}" \
        -noprompt 2>/dev/null \
        && echo "[start.sh] Certificado importado en truststore OK" \
        || echo "[start.sh] WARN: no se pudo importar en truststore"

    rmdir "${LOCKFILE}"
else
    echo "[start.sh] WARN: no se pudo adquirir lock del truststore"
fi

# ── 3. Verificar ─────────────────────────────────────────────────────────────
keytool -list \
    -keystore  "${SHARED_TRUSTSTORE}" \
    -storepass allpassword \
    -alias     "${ALIAS}" \
    -noprompt 2>/dev/null \
    && echo "[start.sh] Verificacion OK — alias ${ALIAS} presente" \
    || echo "[start.sh] WARN: alias ${ALIAS} no encontrado en truststore"

# ── 4. Arrancar uvicorn con TLS ───────────────────────────────────────────────
RUNNER="${CERT_DIR}/run.py"
cat > "${RUNNER}" << 'PYEOF'
import ssl, asyncio, sys
sys.path.insert(0, "/app")
import uvicorn

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain("/cert/dataapp/cert.pem", "/cert/dataapp/key.pem")
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_ctx.set_ciphers(
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)

config = uvicorn.Config("app:app", host="0.0.0.0", port=8500, log_level="info")
config.load()
config.ssl = ssl_ctx
asyncio.run(uvicorn.Server(config).serve())
PYEOF

echo "[start.sh] Arrancando uvicorn con ECDHE cipher suites..."
exec python3 "${RUNNER}"