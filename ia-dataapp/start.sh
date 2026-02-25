#!/bin/sh
# ============================================================
# start.sh — Arranque de la instancia IA DataApp FL
# ============================================================
# Proceso 1: FastAPI FL Worker       (todas las instancias, :8500)
# Proceso 2: Flask FL Coordinator    (SOLO instancia 1, :8600)
# Proceso 3: Java DataApp ECC        (todas las instancias, :8183)
# ============================================================

INSTANCE_ID="${INSTANCE_ID:-1}"
echo "[start.sh] ====================================="
echo "[start.sh] Arrancando instancia FL #${INSTANCE_ID}"
echo "[start.sh] ====================================="

# 1. FastAPI Worker FL
python3 -m uvicorn app:app \
    --host 0.0.0.0 \
    --port 8500 \
    --app-dir /app \
    --log-level info &
WORKER_PID=$!
echo "[start.sh] Worker FL arrancado (PID=$WORKER_PID, puerto 8500)"

# 2. Coordinador FL — solo en instancia 1
if [ "$INSTANCE_ID" = "1" ]; then
    sleep 5  # esperar a que worker esté listo
    echo "[start.sh] Arrancando Coordinador FL (puerto 8600)..."
    python3 /app/fl_coordinator.py &
    COORD_PID=$!
    echo "[start.sh] Coordinador FL arrancado (PID=$COORD_PID)"
fi

# 3. Java DataApp (ECC connector)
sleep 2
echo "[start.sh] Arrancando Java DataApp..."
exec java -jar /home/nobody/app/application.jar