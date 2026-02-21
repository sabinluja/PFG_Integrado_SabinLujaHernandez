#!/bin/sh
# Arranca Flask en background
python3 /app/app.py &

# Espera a que Flask arranque
sleep 3

# Arranca la app Java con la ruta correcta
exec java -jar /home/nobody/app/application.jar