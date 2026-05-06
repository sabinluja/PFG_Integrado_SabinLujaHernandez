# Ciclo WS cliente -> DataApp

Este documento explica el tramo nuevo de comunicacion WebSocket entre el
cliente Python (`pfg_ids_fl_flow.py`) y la DataApp Python (`ia-dataapp/app.py`).

La idea principal es:

```text
Cliente Python -> WSS /ws/client -> DataApp -> POST /proxy -> endpoint interno real
```

Es decir, la funcion de negocio puede seguir siendo `/fl/start`, `/status`,
`/broker/discover/worker`, etc., pero el transporte externo cliente -> DataApp
entra por WebSocket y la DataApp despacha la accion desde `/proxy`.

## Puertos y URLs

Cada DataApp escucha dentro del contenedor en el puerto `8500`. Docker publica
ese puerto al host como `500N`:

| Worker | URL WS publica | Contenedor DataApp |
|---|---|---|
| Worker 1 | `wss://localhost:5001/ws/client` | `be-dataapp-worker1:8500` |
| Worker 2 | `wss://localhost:5002/ws/client` | `be-dataapp-worker2:8500` |
| Worker 3 | `wss://localhost:5003/ws/client` | `be-dataapp-worker3:8500` |
| Worker 4 | `wss://localhost:5004/ws/client` | `be-dataapp-worker4:8500` |

Ejemplo para Worker 2:

```text
localhost:5002 -> be-dataapp-worker2:8500
```

La URL WebSocket usada por el orquestador es:

```text
wss://localhost:5002/ws/client?client_id=pfg-orchestrator
```

## Ejemplo completo con `/fl/start`

### 1. El flow quiere llamar a una funcion de la DataApp

En `pfg_ids_fl_flow.py`, la fase de arranque del entrenamiento federado llama:

```python
data = http_post(
    "https://localhost:5002/fl/start",
    {},
    timeout=240,
)
```

La URL logica de la funcion es:

```text
https://localhost:5002/fl/start
```

Pero `http_post(...)` intenta primero usar WebSocket. Solo cae a REST si el WS
falla.

Funciones implicadas en el orquestador:

```python
fase4_arrancar_fl(...)
http_post(...)
_ws_rpc(...)
DataAppWebSocketClient.request(...)
```

### 2. `DataAppWebSocketClient` abre WSS contra la DataApp

`_ws_rpc(...)` crea o reutiliza una instancia de la clase:

```python
DataAppWebSocketClient("https://localhost:5002")
```

Esta clase es la encargada de gestionar el canal WebSocket del cliente. Su
funcion es ocultar al resto del flow los detalles de conexion, TLS, envio JSON y
recepcion de respuestas.

Primero, `DataAppWebSocketClient._ws_url(...)` transforma la URL base de la
DataApp:

```text
https://localhost:5002
```

en la URL WebSocket de control:

```text
wss://localhost:5002/ws/client?client_id=pfg-orchestrator
```

La conversion es:

```text
https://localhost:5002       -> wss://localhost:5002
/ws/client                   -> endpoint WS fijo de entrada a la DataApp
client_id=pfg-orchestrator   -> identificador visible en logs
```

La ruta funcional `/fl/start` todavia no se envia en este paso. En el siguiente
paso el flow la traduce a un `message` para que sea `/proxy` quien decida
que endpoint interno ejecutar.

Despues, `DataAppWebSocketClient._connect(...)` abre realmente la conexion WSS
usando la libreria Python `websockets`:

```python
from websockets.sync.client import connect
```

La llamada efectiva es equivalente a:

```python
self.ws = connect(
    "wss://localhost:5002/ws/client?client_id=pfg-orchestrator",
    ssl=ssl_ctx,
    max_size=None,
    ping_interval=None,
    ping_timeout=None,
)
```

Tambien configura TLS para aceptar el certificado autofirmado de la DataApp:

```python
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
```

Cuando la DataApp acepta el WebSocket, envia un mensaje `hello`. La clase lo lee
para confirmar que el canal abierto es el correcto:

```python
hello = json.loads(self.ws.recv())
```

Si el `hello` contiene:

```json
{
  "transport": "client-dataapp-websocket",
  "instance": "2"
}
```

entonces la conexion WSS cliente -> DataApp queda abierta y lista para que el
siguiente paso envie la peticion funcional.

### 3. El cliente envia la peticion por WS hacia `/proxy`

Antes de enviar, `_ws_rpc(...)` traduce:

```text
POST /fl/start -> message = fl_start
```

El orquestador envia este JSON por el WebSocket:

```json
{
  "id": "pfg-12",
  "type": "request",
  "method": "POST",
  "path": "/proxy",
  "body": {
    "multipart": "wss",
    "Forward-To": "wss://localhost:5002/ws/client?client_id=pfg-orchestrator",
    "Forward-To-Internal": "/fl/start",
    "messageType": "ArtifactRequestMessage",
    "message": "fl_start",
    "params": {},
    "timeout": 240,
    "logicalMethod": "POST",
    "logicalPath": "/fl/start"
  },
  "timeout": 240
}
```

Aqui `/proxy` es la ruta que recibe la DataApp por el WS. `messageType` mantiene
semantica IDS y el endpoint real `/fl/start` va representado como
`message="fl_start"`.

### 4. La DataApp recibe la conexion en `/ws/client`

En `ia-dataapp/app.py`, la conexion entra en:

```python
@app.websocket("/ws/client")
async def ws_client_control(websocket: WebSocket):
    ...
```

La DataApp acepta la conexion:

```python
await websocket.accept()
```

Y devuelve un saludo inicial:

```json
{
  "type": "hello",
  "transport": "client-dataapp-websocket",
  "instance": "2",
  "client_id": "pfg-orchestrator"
}
```

### 5. La DataApp valida la ruta WS

La DataApp comprueba que la ruta esta permitida:

```python
_client_ws_path_allowed("/proxy")
```

Rutas permitidas por `/ws/client`:

```text
/health
/status
/llm-status
/metrics
/proxy
/fl/
/ids/
/broker/
/dataset/
/catalog/
/system/
/transport/status
/transport/performance
```

Esto evita que `/ws/client` sea un proxy arbitrario.

### 6. `/ws/client` llama internamente a `/proxy`

Si la ruta esta permitida, `ws_client_control(...)` llama a:

```python
_client_ws_local_request("POST", "/proxy", body, 240)
```

Internamente se ejecuta:

```text
POST https://127.0.0.1:8500/proxy
```

Esto es una llamada local dentro de la propia DataApp. No contradice el
objetivo: el transporte externo cliente -> DataApp ya ha entrado por WSS.

### 7. `/proxy` lee `message` y decide con `if/elif`

En `ia-dataapp/app.py`, el endpoint:

```python
@app.post("/proxy")
async def proxy(request: Request):
    ...
```

detecta que el cuerpo trae:

```json
{
  "multipart": "wss",
  "Forward-To": "wss://localhost:5002/ws/client?client_id=pfg-orchestrator",
  "Forward-To-Internal": "/fl/start",
  "messageType": "ArtifactRequestMessage",
  "message": "fl_start",
  "params": {}
}
```

Como existe `message="fl_start"`, entra en el modo dispatcher. El campo
`messageType` sigue indicando el tipo IDS de la peticion. Los campos
`multipart`, `Forward-To` y `Forward-To-Internal` se mantienen para que el
mensaje sea trazable como una llamada WSS/proxy completa:

```python
_proxy_dispatch_message("fl_start", params={}, timeout=240)
```

Dentro de `_proxy_dispatch_message(...)` hay un bloque `if/elif` explicito:

```python
elif normalized in ("fl_start", "start_fl") or path_alias == "/fl/start":
    target = ("POST", "/fl/start", endpoint_body or {})
```

Y despues ejecuta localmente:

```text
POST https://127.0.0.1:8500/fl/start
```

Resumen de este subtramo:

```text
Cliente externo -> WSS /ws/client -> DataApp
DataApp -> HTTPS local 127.0.0.1 -> /proxy
/proxy -> if/elif message=fl_start -> endpoint real /fl/start
```

### 8. Se ejecuta la funcion real `/fl/start`

La llamada interna entra en el endpoint real:

```python
@app.post("/fl/start")
...
```

Ese endpoint arranca el entrenamiento federado.

A partir de aqui, el entrenamiento ya no es el tramo cliente -> DataApp. Empieza
el flujo IDS/FL:

```text
DataApp coordinator -> ECC local -> WSS ECC remoto -> DataApp peer
```

Ejemplo de URLs WSS IDS/ECC:

```text
wss://ecc-worker1:8086/data
wss://ecc-worker3:8086/data
```

### 9. La DataApp responde al cliente por el mismo WS

La DataApp devuelve la respuesta al orquestador por `/ws/client`. La respuesta
incluye primero la capa `/proxy`:

```json
{
  "id": "pfg-12",
  "type": "response",
  "transport": "client-dataapp-websocket",
  "ok": true,
  "status_code": 200,
  "body": {
    "transport": "proxy-message-dispatcher",
    "messageType": "ids:ArtifactRequestMessage",
    "message": "fl_start",
    "target_method": "POST",
    "target_path": "/fl/start",
    "ok": true,
    "status_code": 200,
    "body": {
      "status": "started"
    }
  }
}
```

El cliente recibe esta respuesta en:

```python
DataAppWebSocketClient.request(...)
```

Y `http_post(...)` devuelve el `body` a `fase4_arrancar_fl(...)`.

## Monitorizacion posterior

Despues de arrancar FL, el flow ya no abre un WebSocket de monitorizacion.
Consulta el estado con polling HTTP:

```text
GET https://localhost:5002/fl/status
GET https://localhost:5002/transport/status
```

Resumen:

```text
/ws/client     -> llamadas de control cliente -> DataApp
/transport/*   -> estado REST de transportes conservados
```

## Logs esperados

En el flow:

```text
INFO [WS cliente->DataApp] CONEXION ABIERTA transporte=WSS url=wss://localhost:5002/ws/client?client_id=pfg-orchestrator dataapp_worker=2
INFO [WS cliente->DataApp] OK transporte=WSS metodo=POST url_rest_logica=https://localhost:5002/fl/start despachado_por=/ws/client -> /proxy message=fl_start elapsed_ms=...
```

En `docker logs be-dataapp-worker2 -f`:

```text
[WS CLIENTE->DATAAPP] CONEXION ACEPTADA transporte=WSS endpoint=/ws/client cliente=pfg-orchestrator url_publica=wss://localhost:5002/ws/client contenedor=be-dataapp-worker2:8500
[/proxy dispatcher] message=fl_start params_type=dict
[/proxy dispatcher] fl_start -> POST /fl/start
[WS CLIENTE->DATAAPP] PETICION OK transporte=WSS cliente=pfg-orchestrator endpoint_ws=/ws/client despacho_interno=POST /proxy status=200 elapsed_ms=...
```

Si aparece una linea como:

```text
127.0.0.1 - "POST /proxy HTTP/1.1" 200 OK
127.0.0.1 - "POST /fl/start HTTP/1.1" 200 OK
```

es normal. Son llamadas locales internas de la DataApp a su propio `/proxy` y
despues al handler real. La conexion externa del cliente ya entro por WSS.

## Ciclo completo resumido

```text
pfg_ids_fl_flow.py
  -> fase4_arrancar_fl(...)
  -> http_post("https://localhost:5002/fl/start", {})
  -> _ws_rpc("POST", ...)
  -> _proxy_message_for_ws_request("POST", "/fl/start") = "fl_start"
  -> DataAppWebSocketClient._connect()
  -> WSS wss://localhost:5002/ws/client?client_id=pfg-orchestrator
  -> DataApp @app.websocket("/ws/client")
  -> ws_client_control(...)
  -> _client_ws_path_allowed("/proxy")
  -> _client_ws_local_request("POST", "/proxy", ...)
  -> POST interno https://127.0.0.1:8500/proxy
  -> @app.post("/proxy")
  -> _proxy_dispatch_message("fl_start", ...)
  -> if/elif fl_start => POST /fl/start
  -> POST interno https://127.0.0.1:8500/fl/start
  -> @app.post("/fl/start")
  -> respuesta
  -> WSS /ws/client
  -> pfg_ids_fl_flow.py
```

Frase clave:

```text
La funcion sigue siendo /fl/start, pero el transporte externo cliente -> DataApp
es WSS mediante /ws/client. La DataApp recibe el JSON por WebSocket, llama a
/proxy, /proxy lee message=fl_start, ejecuta el if/elif correspondiente y
despacha internamente al endpoint real. La respuesta vuelve por el mismo
WebSocket.
```
