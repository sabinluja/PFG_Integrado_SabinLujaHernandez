#!/bin/sh
# ============================================================
# consumer_start.sh — Arranque del Consumer IA DataApp
# ============================================================
# 1. Arranca Java DataApp ECC  (:8183)
# 2. Espera a que ECC-Consumer y ECC-Provider estén listos
# 3. Envía algorithm.py al Provider vía IDS automáticamente
# ============================================================

echo "[consumer] ====================================="
echo "[consumer] Arrancando be-dataapp-consumer"
echo "[consumer] ====================================="

# 1. Arrancar Java DataApp en background
echo "[consumer] Arrancando Java DataApp (puerto 8183)..."
java -jar /home/nobody/app/application.jar &
JAVA_PID=$!
echo "[consumer] Java DataApp arrancado (PID=$JAVA_PID)"

# 2. Esperar a que Java DataApp esté listo antes de enviar
echo "[consumer] Esperando 30s a que Java DataApp inicialice..."
sleep 30

# 3. Enviar algorithm.py al Provider vía IDS
echo "[consumer] Lanzando envío IDS de algorithm.py..."
python3 /app/ids_auto_send.py
IDS_EXIT=$?

if [ $IDS_EXIT -eq 0 ]; then
    echo "[consumer] algorithm.py enviado correctamente al Provider"
else
    echo "[consumer] El envío IDS falló (código $IDS_EXIT)"
    echo "[consumer] El sistema sigue funcionando — puedes reenviar desde Postman"
fi

# 4. Mantener Java DataApp en primer plano
echo "[consumer] Java DataApp corriendo. Consumer listo."
wait $JAVA_PID