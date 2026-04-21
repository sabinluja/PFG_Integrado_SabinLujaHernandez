# Documentacion Tecnica de `ia-dataapp/app.py`

## 1. Objetivo de este documento

Este documento explica como funciona el `app.py` actual de la DataApp Python del proyecto, tomando como referencia el estado funcional que tienes ahora mismo.

El foco esta en cuatro bloques:

1. Como funciona el descubrimiento y la seleccion de datasets con LLM/Ollama.
2. Que funciones intervienen y como se encadenan.
3. Como funciona la parte del registry Docker para distribuir el algoritmo.
4. Como fluye una ronda completa de Federated Learning, especialmente el intercambio de pesos.

Ademas, en cada parte se explica:

- como interviene el canal WebSocket;
- como interviene el trayecto ECC-ECC;
- como se usan mensajes y conceptos del estandar IDS.

## 2. Vision general de la arquitectura actual

En cada worker hay dos planos claramente separados:

- `ECC / TRUE Connector`: gestiona identidad, contratos, self-description, catalogo, mensajes IDS multipart y trayectos ECC-ECC.
- `DataApp / FastAPI`: implementa la logica FL, la seleccion de datasets, el entrenamiento local, la agregacion y la observabilidad.

En el `app.py` actual, la arquitectura operativa queda asi:

- El **control plane** va principalmente por IDS:
  - `ids:QueryMessage`
  - `ids:DescriptionRequestMessage`
  - `ids:DescriptionResponseMessage`
  - `ids:ContractRequestMessage`
  - `ids:ContractAgreementMessage`
  - `ids:RejectionMessage`
  - `ids:ArtifactRequestMessage`
  - `ids:ArtifactResponseMessage`
  - `ids:NotificationMessage`
  - `ids:ResultMessage`

- El **data plane** de FL puede usar dos caminos:
  - WebSocket DataApp-to-DataApp, si se habilita el tunel y `FL_WEIGHTS_VIA_ECC=false`.
  - IDS sobre ECC-ECC, encapsulado en `ids:ArtifactRequestMessage`, que es el modo que ahora mismo queda como camino principal cuando `FL_WEIGHTS_VIA_ECC=true` y `FL_IDS_ECC_ONLY=true`.

- El **Clearing House** se reporta por IDS/ECC como camino principal, pero en el estado actual existe ademas una **persistencia espejo REST** para que el dashboard y el export no se queden vacios.

## 3. Funciones base que sostienen todo el flujo IDS

### 3.1 `_now_iso()`

Genera timestamps en formato ISO UTC. Se usa para:

- cabeceras IDS;
- eventos de auditoria;
- recursos y artefactos publicados.

### 3.2 `_ids_context()`

Devuelve el `@context` del Information Model. Es la base para construir mensajes y payloads compatibles con IDS.

### 3.3 `_get_dat_token()` y `_security_token()`

Estas funciones obtienen el DAT Token del DAPS y lo insertan en los mensajes salientes.

Eso es importante porque en IDS no basta con mandar JSON: el conector debe identificarse con un token valido asociado a su identidad.

### 3.4 `_build_outgoing_header()`

Construye la cabecera IDS de salida. Aqui se rellenan campos clave del estandar:

- `@type`
- `ids:modelVersion`
- `ids:issued`
- `ids:issuerConnector`
- `ids:senderAgent`
- `ids:securityToken`
- `ids:recipientConnector`

Es la funcion que hace que cada salida no sea una peticion ad hoc, sino un mensaje IDS formal.

### 3.5 `_ids_send()`

Es la funcion central de transporte IDS en la DataApp.

Su responsabilidad es:

- construir el multipart;
- insertar cabecera IDS y payload;
- decidir si la salida va:
  - al ECC remoto directamente, o
  - al ECC local por `https://ecc-workerX:8887/incoming-data-app/multipartMessageBodyFormData`, que a su vez reenvia al destino final;
- adjuntar `Forward-To` cuando se usa relay local;
- parsear la respuesta IDS.

En otras palabras: casi todo el trafico IDS del proyecto acaba pasando por `_ids_send()`.

### 3.6 `_parse_ids_http_response()`

Normaliza respuestas multipart y JSON. Es importante porque los TRUE Connector no siempre responden con el mismo formato serializado, y esta funcion intenta absorber esa variabilidad.

## 4. Como se cumple IDS en el proyecto

## 4.1 Lo que si esta alineado con IDS

El proyecto usa conceptos IDS reales en tres niveles:

- **Identidad**
  - cada connector tiene `connector URI`;
  - los mensajes llevan `securityToken` DAT.

- **Metadatos y catalogo**
  - los datasets se publican como recursos IDS;
  - cada dataset tiene `Resource`, `Representation`, `Artifact` y `ContractOffer`.

- **Interaccion**
  - el discovery usa `QueryMessage` y `DescriptionRequest/Response`;
  - la negociacion usa `ContractRequest` y `ContractAgreement`;
  - la transferencia del algoritmo y de los pesos usa `ArtifactRequestMessage` y `ArtifactResponseMessage`.

## 4.2 Matiz importante: cumplimiento practico frente a pureza teorica

El diseño esta muy orientado a IDS, pero hay dos matices importantes en el estado actual:

1. El broker se consulta de forma fiable contra Fuseki/SPARQL en `_get_registered_connectors()`, aunque el log lo presente como `ids:QueryMessage`.
2. El Clearing House tiene via principal IDS/ECC, pero ademas tiene persistencia espejo REST en `_report_to_ch()` para garantizar el dashboard/export.

Por tanto, el proyecto esta **fuertemente alineado con IDS en control plane y transferencias FL**, pero no todo es una implementacion "pura" de punta a punta sin compatibilidades.

## 5. Publicacion inicial de datasets y catalogo IDS

La publicacion local la hace principalmente:

- `_delay_publish_datasets()`
- `_publish_local_csvs()`
- `_get_all_local_csvs()`

### 5.1 `_get_all_local_csvs()`

Recorre los CSV locales del worker y extrae:

- nombre de fichero;
- columnas;
- numero de filas;
- tamano.

### 5.2 `_publish_local_csvs()`

Esta funcion convierte cada CSV en un recurso IDS completo dentro del ECC del worker.

Por cada dataset crea:

1. Un `ids:TextResource`.
2. Una representacion de metadatos semanticos con palabras clave de columnas.
3. Una representacion de entrenamiento con `ids:Artifact`.
4. Un `ids:ContractOffer` con permisos y restricciones.

Con esto, el worker queda publicable y descubrible desde otros peers sin mover datos brutos.

## 6. Descubrimiento de peers y papel del LLM/Ollama

La parte de discovery semantico gira sobre estas funciones:

- `_get_registered_connectors()`
- `_get_peer_best_csv()`
- `_llm_recommend_dataset()`
- `_discover_compatible_workers()`

Y estos endpoints:

- `GET /broker/connectors`
- `POST /broker/discover`
- `POST /broker/discover/worker`

### 6.1 `_get_registered_connectors()`

Obtiene los conectores registrados en el broker. En el codigo actual, el canal fiable real es SPARQL a Fuseki.

Su salida es una lista de pares:

- `connector_uri`
- `endpoint`

Con eso el coordinador ya sabe que peers existen.

### 6.2 `_get_peer_best_csv()`

Es la funcion mas importante del discovery.

Para cada peer hace:

1. Obtiene el catalogo del peer.
2. Extrae todos los CSV publicados y sus columnas.
3. Calcula el solapamiento matematico contra las columnas del coordinador.
4. Lanza la recomendacion semantica con LLM.
5. Decide el CSV final a usar.

### 6.3 `_llm_recommend_dataset()`

Esta funcion llama a Ollama mediante `LLM_ENDPOINT`, normalmente:

- `http://ollama:11434/api/generate`

Su funcionamiento es:

1. Construye un prompt con:
   - columnas del coordinador;
   - lista de datasets candidatos;
   - instrucciones estrictas para responder en JSON.
2. Lanza la peticion a Ollama en modo `stream=True`.
3. Va acumulando los tokens en `full_response`.
4. Reenvia esos tokens por WebSocket a la UI:
   - `_notify_ws_clients()`
   - `_notify_ai_clients()`
5. Cuando termina, extrae el JSON final de la respuesta.

Devuelve:

- `filename`
- `reasoning`
- `confidence`

### 6.4 Decision final LLM + matematica

El LLM no manda siempre. La logica real es:

- si el LLM no responde, falla o hace timeout:
  - gana la matematica;
- si el LLM responde con confianza menor del 80%:
  - gana la matematica;
- si el LLM responde con confianza alta pero el CSV elegido no supera el umbral de compatibilidad:
  - gana la matematica;
- solo si el LLM tiene confianza suficiente y el schema sigue siendo compatible:
  - el LLM puede sobrescribir la seleccion matematica.

Esto hace que Ollama actue como capa semantica, pero nunca rompa la compatibilidad estructural necesaria para FL.

### 6.5 Papel del WebSocket aqui

En discovery, el WebSocket no transporta datasets ni pesos. Se usa para observabilidad:

- streaming de tokens del LLM;
- eventos `llm_thinking`;
- decision final del modelo;
- trazas de monitor.

Es decir: aqui el WS es canal de telemetria y UX, no de intercambio FL.

## 7. Negociacion IDS con los peers

La negociacion se hace en `fl_negotiate()` y reutiliza el resultado de discovery.

### 7.1 Flujo

Para cada peer compatible:

1. Se envia `ids:DescriptionRequestMessage`.
2. Se obtiene el `Artifact` y el `ContractOffer` del peer.
3. Se construye un `ids:ContractRequest`.
4. Se envia `ids:ContractRequestMessage`.
5. Se interpreta la respuesta:
   - `ids:ContractAgreementMessage` -> aceptado;
   - `ids:RejectionMessage` -> rechazado.

### 7.2 Donde se ve la soberania del dato

En `ids_data()` cuando entra un `ids:ContractRequestMessage`, el worker puede rechazar por:

- `FL_OPT_OUT=true`;
- politica restringida del modelo publicado;
- consumidor no autorizado.

Eso es importante: no es una exclusion "manual" fuera de IDS. El rechazo se emite como mensaje IDS formal.

## 8. Parte del registry Docker y como entra en el flujo

Las funciones clave son:

- `_build_and_push_algo_image()`
- `_pull_and_extract_algo_image()`
- `_negotiate_and_send_algorithm()`
- `/fl/fetch-algorithm`

### 8.1 Cuando se usa el registry

Solo se usa si:

- `FL_ALGO_VIA_DOCKER=true`

Si no, el algoritmo se reparte en base64 dentro de IDS.

### 8.2 `_build_and_push_algo_image()`

En el coordinador:

1. crea un directorio temporal de build;
2. copia:
   - `algorithm.py`
   - `fl_config.json`
   - `Dockerfile.algorithm`
   - `requirements_algo.txt`
3. calcula un hash del algoritmo;
4. construye una imagen con tag unico;
5. hace `docker push` al registry privado.

El resultado es un tag como:

- `fl-registry:5000/fl-algo:coord2-<hash>`

### 8.3 `_pull_and_extract_algo_image()`

En el worker receptor:

1. hace `docker pull`;
2. crea un contenedor temporal;
3. extrae:
   - `algorithm.py`
   - `fl_config.json`
4. elimina el contenedor temporal;
5. deja listo el worker para entrenar.

### 8.4 `_negotiate_and_send_algorithm()`

Es la funcion que reparte el algoritmo al peer.

Tiene dos modos:

- **modo Docker**
  - envia un `ids:ArtifactRequestMessage` con tipo `fl_algorithm_docker`;
  - el payload lleva la referencia a la imagen;
  - el peer hace pull y extrae.

- **modo base64**
  - envia `algorithm.py` y `fl_config.json` en base64 dentro del `payload` y `ids:contentVersion`;
  - el peer lo recibe y lo guarda.

### 8.5 Relacion con IDS y ECC-ECC

Aunque el contenido sea una imagen Docker o un fichero codificado en base64, el transporte principal sigue siendo IDS:

- `ids:ArtifactRequestMessage`
- con `requestedArtifact`
- con `transferContract`
- con cabecera IDS valida
- atravesando ECC-ECC por WSS cuando `WS_ECC_ENABLED=true`.

El registry no sustituye a IDS: solo sustituye el formato del artefacto distribuido.

## 9. Flujo completo de una ronda FL

Esta es la parte mas importante del sistema.

Las funciones clave son:

- `_run_fl()`
- `_negotiate_and_send_algorithm()`
- `_send_global_weights()`
- `_train_local()`
- `_send_local_weights()`
- `ids_data()`
- `_fedavg()`

## 9.1 Antes de empezar la ronda

`/fl/start`:

1. carga `algorithm.py` y `fl_config.json`;
2. toma la lista de `_accepted_workers` de `/fl/negotiate`;
3. fija:
   - `PEER_ECC_URLS`
   - `PEER_CONNECTOR_URIS`
   - `PEER_SELECTED_CSVS`
4. lanza `_run_fl(...)`.

## 9.2 Inicio de la ronda en `_run_fl()`

Por cada ronda:

1. actualiza `fl_state`;
2. notifica inicio por WebSocket a la UI;
3. emite auditoria al Clearing House;
4. limpia `_round_weights`.

## 9.3 Distribucion del algoritmo

Si `algo_bytes` esta disponible, `_run_fl()` llama a `_negotiate_and_send_algorithm()` para cada peer aceptado.

Aqui el trayecto principal es:

- coordinador DataApp
- ECC local
- ECC remoto
- DataApp remota `/data`

Mensaje usado:

- `ids:ArtifactRequestMessage`

Contenido:

- algoritmo;
- configuracion;
- CSV seleccionado para ese peer;
- metadatos del coordinador.

## 9.4 Envio de pesos globales

Lo hace `_send_global_weights()`.

### Camino A: WebSocket

Si existe tunel WS y `FL_WEIGHTS_VIA_ECC=false`:

- el coordinador usa `_send_global_weights_ws()`;
- el payload viaja por `/ws/fl-training/{worker_id}`;
- el worker recibe los pesos en `_fl_worker_ws_client_connect()`.

Este es el camino mas rapido, pero no es el principal cuando se fuerza ECC-ECC.

### Camino B: IDS sobre ECC-ECC

Si `FL_WEIGHTS_VIA_ECC=true` o no se permite bypass:

- `_send_global_weights()` construye un payload `fl_global_weights`;
- lo serializa tambien en `ids:contentVersion`;
- lo manda como `ids:ArtifactRequestMessage`;
- usa `_ecc_forward_url()` para transformar:
  - `https://ecc-workerN:8889/data`
  - en
  - `wss://ecc-workerN:8086/data`

Este es el flujo principal actual cuando fuerzas IDS/ECC.

## 9.5 Recepcion de pesos globales en el worker

Entra por `ids_data()` del worker.

La funcion:

1. parsea multipart;
2. lee la cabecera IDS;
3. detecta `ids:ArtifactRequestMessage`;
4. reconstruye el `payload_dict` desde:
   - `payload`, o
   - `ids:contentVersion`, o
   - `ids:securityToken`.

Si detecta `artifact_type == "fl_global_weights"`:

1. guarda `coordinator_ecc_url`, `coordinator_conn_uri`, `transfer_contract`, `requested_artifact`;
2. si el modo WS estuviera activo, puede abrir el cliente WS al coordinador;
3. lanza un hilo local que hace:
   - `_train_local(...)`
   - `_send_local_weights(...)`

## 9.6 Entrenamiento local

Lo hace `_train_local()`.

Esta funcion:

1. selecciona el CSV efectivo:
   - el asignado por el coordinador, o
   - el local por defecto;
2. carga `algorithm.py`;
3. llama al metodo `run(...)` del algoritmo;
4. devuelve:
   - `weights_b64`
   - `n_samples`
   - `metrics`

## 9.7 Envio de pesos locales al coordinador

Lo hace `_send_local_weights()`.

### Camino principal actual

En el estado actual del codigo, el camino principal es:

- worker DataApp
- ECC local
- ECC del coordinador
- DataApp coordinadora `/data`

Mensaje usado:

- `ids:ArtifactRequestMessage`

Payload:

- `type = fl_weights`
- `weights_b64`
- `n_samples`
- `metrics`
- `round`

Tambien se incluyen:

- `requested_artifact`
- `transfer_contract`

Es decir: no es un POST arbitrario, sino una transferencia alineada con IDS.

### Camino fallback

Si falla el trayecto IDS y `ALLOW_IDS_BYPASS=true`:

- puede hacer POST directo al endpoint del coordinador.

Pero con la configuracion estricta, lo normal es que eso quede bloqueado.

## 9.8 Recepcion de pesos locales en el coordinador

Otra vez entra por `ids_data()`.

Si el `artifact_type` detectado es `fl_weights`:

1. toma:
   - `instance_id`
   - `round`
   - `weights_b64`
   - `n_samples`
   - `metrics`
2. los mete en `_round_weights`;
3. responde con `ids:ArtifactResponseMessage`.

## 9.9 Agregacion FedAvg

Cuando `_run_fl()` ve que ya tiene suficientes resultados:

1. toma `results = list(_round_weights.values())`;
2. llama a `_fedavg(results)`;
3. convierte el resultado a base64 con `_weights_to_b64()`;
4. calcula metricas globales ponderadas por `n_samples`.

Despues:

- guarda historico;
- guarda el mejor modelo;
- notifica por WebSocket;
- audita en Clearing House.

## 9.10 Fin de FL y publicacion del modelo final

Cuando acaban las rondas, `_publish_fl_model_as_ids_resource()`:

1. crea un recurso IDS para el modelo global;
2. crea un `ContractOffer` restringido a los peers participantes;
3. crea la representacion y artifact final;
4. publica todo en el ECC del coordinador.

Es decir: el resultado del FL no queda solo en disco, sino que se convierte en un recurso IDS reutilizable y gobernado por contrato.

## 10. Papel del WebSocket en el proyecto

Hay tres usos distintos de WS:

### 10.1 WS de monitorizacion

Se usa para:

- estado de entrenamiento;
- tokens del LLM;
- eventos del monitor IDS;
- actualizacion de la UI.

Funciones relacionadas:

- `_notify_ws_clients()`
- `_notify_ai_clients()`
- `_notify_ids_monitor()`
- `_WSConnectionManager`

### 10.2 WS del data-plane FL

Se usa solo cuando se quiere mover pesos globales por tunel WS DataApp-to-DataApp.

Funciones:

- `FLTrainingWSManager`
- `/ws/fl-training/{worker_id}`
- `_send_global_weights_ws()`
- `_fl_worker_ws_client_connect()`

### 10.3 WSS entre ECCs

Es distinto del WS entre DataApps.

Cuando `_ecc_forward_url()` transforma `:8889/data` a `:8086/data`, el trafico IDS va por el canal WSS del ECC remoto.

Ese es el tramo que en tus logs aparece como:

- `wss://ecc-worker1:8086/data`
- `wss://ecc-worker3:8086/data`
- `wss://ecc-clearinghouse:8086/data`

## 11. Papel del Clearing House en el flujo actual

La funcion principal es `_report_to_ch()`.

Hace esto:

1. construye un payload de auditoria con metadatos IDS;
2. intenta enviarlo al notario por `_ids_send()`;
3. actualmente lo encapsula externamente como `ids:ArtifactRequestMessage` para compatibilidad con el trayecto WSS del TRUE Connector;
4. ademas, si existe `CLEARING_HOUSE_URL`, hace persistencia espejo REST.

### Punto importante

Por tanto, el Clearing House actual no es "solo IDS puro" en persistencia final, porque mantiene un espejo REST.

Lo honesto es describirlo asi:

- **camino de notificacion principal**: IDS/ECC;
- **camino de persistencia de apoyo**: REST a la API del notario.

## 12. Resumen ejecutivo del flujo completo

El flujo real del proyecto queda asi:

1. Cada worker publica sus datasets como recursos IDS en su ECC.
2. El coordinador descubre peers desde el broker.
3. Para cada peer, inspecciona su catalogo y sus CSV publicados.
4. El coordinador combina:
   - matching matematico de columnas;
   - razonamiento semantico de Ollama.
5. Negocia contratos IDS con los peers compatibles.
6. Distribuye `algorithm.py` y `fl_config.json` por `ids:ArtifactRequestMessage`, o bien una imagen Docker si se activa el registry.
7. En cada ronda:
   - envia pesos globales;
   - cada worker entrena localmente;
   - cada worker devuelve pesos locales;
   - el coordinador agrega con FedAvg.
8. Al final, el modelo federado se publica como recurso IDS con contrato restringido a participantes.
9. Durante todo el flujo, la auditoria del sistema se envia al Clearing House.

## 13. Funciones mas importantes para defender el proyecto

Si en la memoria o en la defensa quieres citar las funciones clave, las mas representativas son estas:

- Transporte IDS:
  - `_ids_send()`
  - `_build_outgoing_header()`
  - `_parse_ids_http_response()`

- Discovery + broker:
  - `_get_registered_connectors()`
  - `_get_peer_best_csv()`
  - `_discover_compatible_workers()`

- LLM / Ollama:
  - `_llm_recommend_dataset()`

- Negociacion IDS:
  - `fl_negotiate()`
  - `ids_data()` en ramas `DescriptionRequest`, `ContractRequest` y `ArtifactRequest`

- Distribucion del algoritmo:
  - `_negotiate_and_send_algorithm()`
  - `_build_and_push_algo_image()`
  - `_pull_and_extract_algo_image()`

- Entrenamiento federado:
  - `_run_fl()`
  - `_train_local()`
  - `_send_global_weights()`
  - `_send_local_weights()`
  - `_fedavg()`

- Publicacion del modelo final:
  - `_publish_fl_model_as_ids_resource()`

- Auditoria:
  - `_report_to_ch()`

## 14. Conclusiones importantes

### 14.1 Lo mas fuerte del diseño

Lo mas potente de tu implementacion es que combina tres capas a la vez:

- gobernanza IDS real;
- automatizacion semantica con LLM local;
- entrenamiento federado con intercambio de pesos sin mover datos brutos.

### 14.2 Lo mas importante del flujo de pesos

Lo mas importante para entender la ronda es esto:

- el algoritmo se distribuye una vez por ronda;
- los pesos globales salen del coordinador;
- cada worker entrena con su CSV local;
- los pesos locales vuelven al coordinador;
- el coordinador agrega y vuelve a empezar.

Ese bucle es el corazon del sistema.

### 14.3 Donde entra IDS de verdad

IDS no esta solo "decorando" el proyecto. IDS aparece de forma real en:

- identidad;
- catalogo;
- contratos;
- artefactos;
- trayectos ECC-ECC;
- publicacion final del modelo.

### 14.4 Matiz final honesto

El sistema esta muy orientado a IDS y ECC-ECC, pero en el estado actual mantiene algunas compatibilidades practicas:

- broker via SPARQL/Fuseki para discovery fiable;
- persistencia espejo REST en Clearing House;
- algunos fallbacks HTTP opcionales si se habilitan.

Eso no invalida el diseño; al contrario, refleja una implementacion robusta en un entorno real con TRUE Connector.
