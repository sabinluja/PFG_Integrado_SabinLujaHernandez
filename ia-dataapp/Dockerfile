FROM rdlabengpa/ids_be_data_app:v0.3.8

USER root

RUN apk add --no-cache python3 py3-pip

COPY model/ /app/model/

RUN pip3 install --no-cache-dir -r /app/model/requirements.txt

USER nobody