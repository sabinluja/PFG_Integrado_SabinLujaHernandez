#!/bin/sh
# =============================================================================
# start.sh — Arranque de la instancia IA DataApp FL
# =============================================================================
# Un único proceso: FastAPI en :8500 con SSL.
# Expone /proxy (para Postman) y /data (para el ECC).
# Sin Java DataApp. Sin fl_coordinator.py separado.
# =============================================================================

INSTANCE_ID="${INSTANCE_ID:-1}"

echo "[start.sh] Arrancando IA DataApp FL — instancia #${INSTANCE_ID}"

exec python3 -m uvicorn app:app \
    --host 0.0.0.0 \
    --port 8500 \
    --app-dir /app \
    --ssl-keyfile /cert/ssl-server.key \
    --ssl-certfile /cert/ssl-server.crt \
    --log-level info