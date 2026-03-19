#!/bin/sh
echo "Waiting 30s for omejdn to stabilize..."
sleep 30
exec java \
  -Djava.security.egd=file:/dev/./urandom \
  -Dsparql.url=http://broker-fuseki:3030/connectorData \
  -Delasticsearch.hostname= \
  -Ddaps.validateIncoming=true \
  -Dcomponent.uri=https://broker-reverseproxy/ \
  -Dcomponent.catalogUri=https://broker-reverseproxy/connectors/ \
  -Dssl.javakeystore=/etc/cert/isstbroker-keystore.jks \
  -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 \
  -jar /broker-core.jar