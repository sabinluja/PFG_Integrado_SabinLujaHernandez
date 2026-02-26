FROM rdlabengpa/ids_be_data_app:v0.3.8 AS java_source

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome
ENV TF_CPP_MIN_LOG_LEVEL=3

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    openjdk-17-jre-headless \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY --from=java_source /home/nobody/app /home/nobody/app
COPY --from=java_source /home/nobody/data /home/nobody/data_default

COPY app.py            /app/app.py
COPY fl_coordinator.py /app/fl_coordinator.py
COPY algorithm.py      /app/algorithm.py

RUN mkdir -p \
        /home/nobody/data/input \
        /home/nobody/data/output \
        /home/nobody/log \
        /app-src && \
    chown -R nobody:nogroup /home/nobody /app && \
    chmod 777 /app-src

COPY start.sh /start.sh
RUN chmod +x /start.sh && sed -i 's/\r//' /start.sh

USER nobody
WORKDIR /home/nobody

EXPOSE 8183 9000 8500 8600

ENTRYPOINT ["/start.sh"]