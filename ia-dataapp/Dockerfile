# =============================================================================
# Dockerfile — IA DataApp FL Worker/Coordinator
# =============================================================================
# Sustituye completamente al Java DataApp del TRUE Connector.
# Solo Python — uvicorn arranca en :8500.
#
# Usa python:3.11-slim en lugar de ubuntu:22.04 para:
#   - Imagen más ligera (~150MB vs 400MB)
#   - Python ya incluido — no hace falta instalarlo
#   - Mucho más probable que Docker Desktop la tenga cacheada localmente
#
# Expone:
#   :8500/proxy  — para Postman (replica connectorA:8184/proxy del Java DataApp)
#   :8500/data   — para el ECC (DATA_APP_ENDPOINT)
# =============================================================================

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome
ENV TF_CPP_MIN_LOG_LEVEL=3

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY app.py       /app/app.py
COPY algorithm.py /app/algorithm.py

RUN mkdir -p \
    /home/nobody/data/input \
    /home/nobody/data/output \
    /home/nobody/log && \
    chown -R nobody:nogroup /home/nobody /app

COPY start.sh /start.sh
RUN chmod +x /start.sh && sed -i 's/\r//' /start.sh

USER nobody
WORKDIR /home/nobody

EXPOSE 8500

ENTRYPOINT ["/start.sh"]