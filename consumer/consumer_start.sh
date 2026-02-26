#!/bin/sh
# ============================================================
# consumer_start.sh — Arranque del Consumer IA DataApp
# ============================================================
# Procesos:
#   1. ids_receive_results.py  — FastAPI :8500
#      Recibe artefactos FL del Provider vía IDS
#   2. Java DataApp ECC        — :8183
#      Proxy IDS (el único que sabe enrutar al Provider)
#   3. ids_auto_send.py        — script único al arrancar
#      Envía algorithm.py al Provider vía IDS
#   4. ids_fl_poller.py        — proceso background permanente
#      Polling al Provider; cuando FL termina, solicita
#      fl_global_model + fl_results vía IDS (flujo canónico)
# ============================================================

echo "[consumer] ====================================="
echo "[consumer] Arrancando be-dataapp-consumer"
echo "[consumer] ====================================="

# ── 1. FastAPI Consumer ───────────────────────────────────────────────────────
echo "[consumer] Arrancando ids_receive_results.py (puerto 8500)..."
python3 -m uvicorn ids_receive_results:app \
    --host 0.0.0.0 --port 8500 \
    --app-dir /app --log-level info &
FASTAPI_PID=$!
echo "[consumer] FastAPI arrancado (PID=$FASTAPI_PID)"

# ── 2. Java DataApp ECC ───────────────────────────────────────────────────────
echo "[consumer] Arrancando Java DataApp ECC (puerto 8183)..."
java -jar /home/nobody/app/application.jar &
JAVA_PID=$!
echo "[consumer] Java DataApp arrancado (PID=$JAVA_PID)"

# ── 3. Esperar inicialización Java DataApp ────────────────────────────────────
echo "[consumer] Esperando 30s a que Java DataApp inicialice..."
sleep 30

# ── 4. Enviar algorithm.py al Provider vía IDS ────────────────────────────────
echo "[consumer] Lanzando ids_auto_send.py..."
python3 /app/ids_auto_send.py
IDS_EXIT=$?
if [ $IDS_EXIT -eq 0 ]; then
    echo "[consumer] ✅ algorithm.py enviado al Provider"
else
    echo "[consumer] ⚠️  Envío IDS falló (código $IDS_EXIT)"
fi

# ── 5. Arrancar poller IDS en background ──────────────────────────────────────
echo "[consumer] Arrancando ids_fl_poller.py (background)..."
python3 /app/ids_fl_poller.py &
POLLER_PID=$!
echo "[consumer] FL Poller arrancado (PID=$POLLER_PID)"

echo "[consumer] ====================================="
echo "[consumer] Consumer listo:"
echo "[consumer]   FastAPI (recibe IDS)  : http://localhost:8500"
echo "[consumer]   Java DataApp ECC      : https://localhost:8183"
echo "[consumer]   FL Poller             : background (PID=$POLLER_PID)"
echo "[consumer]"
echo "[consumer] El poller detectará cuando FL termine y"
echo "[consumer] solicitará modelo+resultados vía IDS."
echo "[consumer]"
echo "[consumer] Tras el FL:"
echo "[consumer]   GET http://localhost:8501/fl/model"
echo "[consumer]   GET http://localhost:8501/fl/results/summary"
echo "[consumer] ====================================="

wait $JAVA_PID