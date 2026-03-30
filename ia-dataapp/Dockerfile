# =============================================================================
# Dockerfile — IA DataApp FL Worker/Coordinator
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome
ENV TF_CPP_MIN_LOG_LEVEL=3
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    curl ca-certificates openssl \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY app.py       /app/app.py
COPY algorithm.py /app/algorithm.py
COPY fl_config.json /app/fl_config.json

RUN mkdir -p \
        /home/nobody/data/input \
        /home/nobody/data/output \
        /home/nobody/log \
        /cert/dataapp && \
    chown -R nobody:nogroup /home/nobody /app /cert/dataapp

COPY start.sh /start.sh
RUN chmod +x /start.sh && sed -i 's/\r//' /start.sh

USER nobody
WORKDIR /home/nobody

EXPOSE 8500

ENTRYPOINT ["/start.sh"]