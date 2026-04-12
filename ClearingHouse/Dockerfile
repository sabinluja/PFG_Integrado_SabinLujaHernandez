FROM python:3.11-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

LABEL maintainer="TFG Sistema IDS"
LABEL description="IDS Clearing House"
LABEL version="1.0.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"  

COPY --from=builder /opt/venv /opt/venv

RUN useradd -m -u 1000 -s /bin/bash clearinghouse && \
    mkdir -p /app/logs && \
    chown -R clearinghouse:clearinghouse /app

WORKDIR /app

COPY --chown=clearinghouse:clearinghouse app/ ./app/

USER clearinghouse

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]