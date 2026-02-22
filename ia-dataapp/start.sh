#!/bin/sh
# Arranca FastAPI con uvicorn en background
python3 -m uvicorn app:app --host 0.0.0.0 --port 8500 --app-dir /app &

# Espera a que FastAPI arranque
sleep 3

# Arranca la app Java
exec java -jar /home/nobody/app/application.jar