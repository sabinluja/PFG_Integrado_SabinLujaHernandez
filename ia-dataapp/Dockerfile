FROM rdlabengpa/ids_be_data_app:v0.3.8

USER root

RUN apk add --no-cache python3 py3-pip py3-pandas

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY algorithm.py /home/nobody/data/algorithm.py

RUN mkdir -p /home/nobody/data/output /home/nobody/log && \
    chown -R nobody:nobody /home/nobody/data /home/nobody/log /app

COPY start.sh /start.sh
RUN chmod +x /start.sh

USER nobody

EXPOSE 8183 9000 5000

ENTRYPOINT ["/start.sh"]