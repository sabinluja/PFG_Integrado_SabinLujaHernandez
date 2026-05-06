#!/usr/bin/env python3
"""
pfg_ids_fl_flow.py  --  Demostración completa IDS + Federated Learning
======================================================================
Arquitectura Híbrida:
  - Control Plane (IDS): Negociación de contratos y descubrimiento HTTPS.
  - Data Plane (WS): Transferencia asíncrona de alto rendimiento de pesos FL.

  FASE 0   Conectividad y Topología de Red
           Health-check del coordinador y descubrimiento de nodos via Broker Fuseki.
  FASE 1   Catálogo IDS del Coordinador
           Verificación del Catálogo Federado y listado de Datasets soberanos.
  FASE 2   Preparación de Artefactos FL (Imagen Docker)
           Compilación del algoritmo de IA en una imagen Docker inmutable.
  FASE 3   Búsqueda de Nodos y Filtro de Compatibilidad (IA Local)
           Descubrimiento de peers via Broker + validación con LLAMA y heurísticas.
  FASE 4   Negociación Estricta de Contratos IDS
           Firma de contratos GAIA-X: ContractRequest → Agreement/Rejection.
  FASE 5   Entrenamiento Federado (Federated Learning)
           Arranque, monitorización en tiempo real y agregación FedAvg.
  FASE 6   Auditoría Final y Soberanía de Datos
           Test de acceso: solo los nodos participantes pueden ver el modelo.

Se incluye soporte de Cancelación Global (/system/reset) pulsando P.

Uso:
  python pfg_ids_fl_flow.py
  python pfg_ids_fl_flow.py --skip-fl
  python pfg_ids_fl_flow.py --coordinator 3
  python pfg_ids_fl_flow.py --timeout 360
"""


import sys
import json
import argparse
import time
import re
import os
import threading
import ssl
from urllib.parse import urlparse
try:
    import msvcrt
    _HAS_MSVCRT = True
except ImportError:
    _HAS_MSVCRT = False

import requests
import urllib3
try:
    import websockets
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

TLS_CERT = "./cert/daps/ca.crt" if os.path.exists("./cert/daps/ca.crt") else False

# =============================================================================
# Duplicación de logs a archivo "General"
# =============================================================================
class TeeWithStripANSI:
    def __init__(self, filename):
        self.stdout = sys.stdout
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        self.file = open(filename, "w", encoding="utf-8")
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, message):
        self.stdout.write(message)
        self.file.write(self.ansi_escape.sub('', message))
        self.file.flush()

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def isatty(self):
        return hasattr(self.stdout, 'isatty') and self.stdout.isatty()

try:
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ia-dataapp", "log", "fl_orchestrator.log")
    sys.stdout = TeeWithStripANSI(log_path)
except Exception:
    pass

if not TLS_CERT:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Configuracion
# =============================================================================

# Puerto del dataapp coordinator: convencion 5000 + N (p.ej. 5002 para worker-2)
# Se puede sobreescribir con --coordinator-port
DEFAULT_COORDINATOR_PORT_BASE = 5000

# Flag global de cancelacion -- lo activa el hilo del listener de teclado
_cancel_requested = False


# =============================================================================
# Colores y logging
# =============================================================================

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
GRAY    = "\033[90m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"


def _sep(char="=", width=72, color=CYAN):
    print(f"{color}{char * width}{RESET}")


def banner(title, subtitle=""):
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    if subtitle:
        print(f"{GRAY}  {subtitle}{RESET}")
    _sep("=", color=BOLD + CYAN)


def phase(num, title, description=""):
    print()
    _sep("-", color=BLUE)
    print(f"{BOLD}{BLUE}  FASE {num}  --  {title}{RESET}")
    if description:
        for line in description.splitlines():
            print(f"{GRAY}  {line}{RESET}")
    _sep("-", color=BLUE)


def step(label):
    print(f"\n  {BOLD}{WHITE}▸ {label}{RESET}")


def substep(msg):
    print(f"    {GRAY}-> {msg}{RESET}")


def ok(msg):
    print(f"    {GREEN}OK  {msg}{RESET}")


def fail(msg):
    print(f"    {RED}ERR {msg}{RESET}")
    sys.exit(1)


def warn(msg):
    print(f"    {YELLOW}WARN {msg}{RESET}")


def info(msg):
    print(f"    {GRAY}INFO {msg}{RESET}")


def field(label, value, indent=4):
    pad = " " * indent
    val = str(value)
    if len(val) > 110:
        val = val[:107] + "..."
    print(f"{pad}{MAGENTA}{label:<28}{RESET} {val}")


def ids_arrow(direction, msg_type, src, dst):
    arrow = "->" if direction == "out" else "<-"
    color = CYAN if direction == "out" else GREEN
    short = msg_type.replace("ids:", "").replace("Message", "Msg")
    print(f"    {color}[IDS {arrow}] {short:<42}{GRAY}  {src}  ->  {dst}{RESET}")


def section(title):
    print(f"\n    {BOLD}{WHITE}-- {title} --{RESET}")


def _cm_short_label(name):
    mapping = {
        "Benign": "BEN",
        "GenericAttack": "GEN",
        "Exploits": "EXP",
        "Fuzzers": "FUZ",
        "GroupedAttacks": "GRP",
    }
    return mapping.get(name, str(name)[:3].upper())


# =============================================================================
# Cliente HTTP
# =============================================================================

SESSION = requests.Session()
SESSION.verify = False
CLIENT_WS_ENABLED = os.getenv("PFG_CLIENT_DATAAPP_WS", "true").lower() not in ("0", "false", "no")
CLIENT_WS_OPEN_TIMEOUT = float(os.getenv("PFG_CLIENT_WS_OPEN_TIMEOUT", "8"))
CLIENT_WS_CONNECT_RETRIES = int(os.getenv("PFG_CLIENT_WS_CONNECT_RETRIES", "2"))
PROXY_CONTROL_ARTIFACT_BASE = os.getenv(
    "PFG_PROXY_CONTROL_ARTIFACT_BASE",
    "http://w3id.org/engrd/connector/artifact/fl-control",
)
PROXY_CONTROL_CONTRACT_BASE = os.getenv(
    "PFG_PROXY_CONTROL_CONTRACT_BASE",
    "http://w3id.org/engrd/connector/contract/fl-control",
)
_WS_RPC_CLIENTS = {}


class DataAppWebSocketClient:
    """
    Cliente RPC minimo sobre WebSocket para hablar con la DataApp.
    Mantiene una conexion persistente por DataApp y deja REST solo como fallback.
    """
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.ws = None
        self.seq = 0

    def _ws_url(self):
        parsed = urlparse(self.base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{scheme}://{parsed.netloc}/ws/client?client_id=pfg-orchestrator"

    def _connect(self, timeout):
        if self.ws is not None:
            return
        from websockets.sync.client import connect
        ws_url = self._ws_url()
        ssl_ctx = None
        if ws_url.startswith("wss://"):
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        last_exc = None
        open_timeout = min(max(CLIENT_WS_OPEN_TIMEOUT, 1.0), max(float(timeout or 1), 1.0))
        for attempt in range(max(1, CLIENT_WS_CONNECT_RETRIES)):
            try:
                self.ws = connect(
                    ws_url,
                    ssl=ssl_ctx,
                    open_timeout=open_timeout,
                    close_timeout=3,
                    max_size=None,
                    ping_interval=None,
                    ping_timeout=None,
                )
                hello = json.loads(self.ws.recv(timeout=open_timeout))
                if hello.get("transport") != "client-dataapp-websocket":
                    raise RuntimeError(f"handshake WS inesperado: {hello}")
                break
            except Exception as exc:
                last_exc = exc
                if self.ws is not None:
                    try:
                        self.ws.close()
                    except Exception:
                        pass
                self.ws = None
                if attempt + 1 < max(1, CLIENT_WS_CONNECT_RETRIES):
                    time.sleep(0.5)
        else:
            raise last_exc
        info(
            "[WS cliente->DataApp] CONEXION ABIERTA "
            f"transporte=WSS url={ws_url} "
            f"dataapp_worker={hello.get('instance', '?')}"
        )

    def request(self, method, path, body=None, timeout=240):
        self._connect(timeout)
        self.seq += 1
        request_id = f"pfg-{self.seq}"
        self.ws.send(json.dumps({
            "id": request_id,
            "type": "request",
            "method": method,
            "path": path,
            "body": body,
            "timeout": timeout,
        }))
        while True:
            response = json.loads(self.ws.recv())
            if response.get("id") == request_id:
                if not response.get("ok"):
                    raise RuntimeError(
                        f"WS {method} {path} devolvio "
                        f"{response.get('status_code')}: {response.get('error') or response.get('body')}"
                    )
                return response

    def close(self):
        if self.ws is not None:
            try:
                self.ws.close()
            finally:
                self.ws = None


def _url_parts_for_ws(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None, None
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return base_url, path


def _proxy_message_for_ws_request(method, path):
    """
    Traduce la URL logica a una accion de artifact para /proxy.
    El transporte externo sigue siendo /ws/client, pero la DataApp registra
    despacho_interno=POST /proxy y /proxy decide el endpoint final a partir
    de messageType=ArtifactRequestMessage + payload.action.
    """
    method = (method or "GET").upper()
    clean_path = (path or "/").split("?", 1)[0]
    mapping = {
        ("GET", "/health"): "health",
        ("GET", "/status"): "status",
        ("GET", "/metrics"): "metrics",
        ("GET", "/transport/status"): "transport_status",
        ("GET", "/ids/self-description"): "ids_self_description",
        ("GET", "/ids/contract"): "ids_contract",
        ("GET", "/broker/connectors"): "broker_connectors",
        ("POST", "/broker/discover"): "broker_discover",
        ("POST", "/broker/discover/worker"): "broker_discover_worker",
        ("GET", "/dataset/info"): "dataset_info",
        ("GET", "/dataset/all-columns"): "dataset_all_columns",
        ("GET", "/dataset/llm-recommend"): "dataset_llm_recommend",
        ("POST", "/catalog/publish-datasets"): "catalog_publish_datasets",
        ("POST", "/fl/fetch-algorithm"): "fl_fetch_algorithm",
        ("POST", "/fl/start"): "fl_start",
        ("GET", "/fl/status"): "fl_status",
        ("GET", "/fl/docker-image-status"): "fl_docker_image_status",
        ("GET", "/fl/results"): "fl_results",
        ("GET", "/fl/model"): "fl_model",
        ("POST", "/fl/negotiate"): "fl_negotiate",
        ("POST", "/fl/accept-negotiation"): "fl_accept_negotiation",
        ("POST", "/fl/receive-algorithm"): "fl_receive_algorithm",
        ("POST", "/fl/receive-global-weights"): "fl_receive_global_weights",
        ("POST", "/fl/receive-local-weights"): "fl_receive_local_weights",
        ("POST", "/system/reset"): "system_reset",
        ("POST", "/system/reset-all"): "system_reset_all",
    }
    return mapping.get((method, clean_path))


def _safe_uri_segment(value):
    segment = (value or "operation").strip().lower().replace("_", "-")
    return "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in segment).strip("-") or "operation"


def _proxy_control_ids_refs(proxy_action):
    """
    Cada accion local se modela como un artifact/contrato de control distinto.
    Asi /proxy no reutiliza el mismo requestedArtifact/transferContract para
    fases semanticamente diferentes del flujo.
    """
    segment = _safe_uri_segment(proxy_action)
    artifact_base = PROXY_CONTROL_ARTIFACT_BASE.rstrip("/")
    contract_base = PROXY_CONTROL_CONTRACT_BASE.rstrip("/")
    return f"{artifact_base}/{segment}", f"{contract_base}/{segment}"


def _proxy_wss_forward_for_base_url(base_url):
    parsed = urlparse(base_url or "")
    port = parsed.port
    if port and port >= DEFAULT_COORDINATOR_PORT_BASE:
        worker_id = port - DEFAULT_COORDINATOR_PORT_BASE
        if worker_id > 0:
            return f"wss://ecc-worker{worker_id}:8086/data"
    return os.getenv("PFG_PROXY_FORWARD_TO", "")


def _proxy_body_for_local_request(method, path, body=None, timeout=240, base_url=None):
    proxy_action = _proxy_message_for_ws_request(method, path)
    if not proxy_action:
        return None
    forward_to = os.getenv("PFG_PROXY_FORWARD_TO") or _proxy_wss_forward_for_base_url(base_url)
    forward_to_internal = os.getenv("PFG_PROXY_FORWARD_TO_INTERNAL") or forward_to
    requested_artifact, transfer_contract = _proxy_control_ids_refs(proxy_action)
    return {
        "multipart": "wss",
        "Forward-To": forward_to,
        "Forward-To-Internal": forward_to_internal,
        "messageType": "ArtifactRequestMessage",
        "requestedArtifact": requested_artifact,
        "transferContract": transfer_contract,
        "payload": {
            "action": proxy_action,
            "body": body if body is not None else {},
            "logicalMethod": method,
            "logicalPath": path,
        },
        "timeout": timeout,
    }


def _unwrap_proxy_body(parsed):
    if not isinstance(parsed, dict):
        return parsed
    if parsed.get("transport") not in ("proxy-artifact-dispatcher", "proxy-message-dispatcher"):
        return parsed
    if not parsed.get("ok"):
        raise RuntimeError(
            f"/proxy {parsed.get('action') or parsed.get('message') or parsed.get('messageType')} devolvio "
            f"{parsed.get('status_code')}: {parsed.get('error') or parsed.get('body') or parsed.get('text')}"
        )
    if "body" in parsed:
        return parsed.get("body")
    if "text" in parsed:
        return {"_raw": parsed.get("text", "")}
    return parsed


def _unwrap_proxy_dispatch_response(ws_resp):
    body = ws_resp.get("body")
    if not isinstance(body, dict):
        return ws_resp
    if body.get("transport") not in ("proxy-artifact-dispatcher", "proxy-message-dispatcher"):
        return ws_resp
    if not body.get("ok"):
        raise RuntimeError(
            f"/proxy {body.get('action') or body.get('message') or body.get('messageType')} devolvio "
            f"{body.get('status_code')}: {body.get('error') or body.get('body') or body.get('text')}"
        )
    ws_resp["proxy_action"] = body.get("action") or body.get("message")
    ws_resp["proxy_message"] = ws_resp["proxy_action"]
    ws_resp["proxy_target"] = body.get("target_path")
    if "body" in body:
        ws_resp["body"] = body.get("body")
        ws_resp.pop("text", None)
    elif "text" in body:
        ws_resp["text"] = body.get("text", "")
        ws_resp.pop("body", None)
    return ws_resp


def _ws_rpc(method, url, body=None, timeout=240):
    if not CLIENT_WS_ENABLED or not _WS_AVAILABLE:
        return None
    base_url, path = _url_parts_for_ws(url)
    if not base_url:
        return None
    proxy_action = None
    if path != "/proxy":
        proxy_body = _proxy_body_for_local_request(method, path, body=body, timeout=timeout, base_url=base_url)
        if proxy_body:
            payload = proxy_body.get("payload") if isinstance(proxy_body.get("payload"), dict) else {}
            proxy_action = payload.get("action")
            body = proxy_body
            method = "POST"
            path = "/proxy"
    client = _WS_RPC_CLIENTS.get(base_url)
    if client is None:
        client = DataAppWebSocketClient(base_url)
        _WS_RPC_CLIENTS[base_url] = client
    try:
        ws_resp = client.request(method, path, body=body, timeout=timeout)
        if proxy_action:
            ws_resp = _unwrap_proxy_dispatch_response(ws_resp)
        return ws_resp
    except Exception:
        client.close()
        _WS_RPC_CLIENTS.pop(base_url, None)
        raise


def _close_ws_rpc_clients():
    for client in list(_WS_RPC_CLIENTS.values()):
        client.close()
    _WS_RPC_CLIENTS.clear()


def http_get(url, timeout=240, quiet=False):
    if not quiet:
        substep(f"GET  {url}")
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("GET", url, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" payload.action={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                if not quiet:
                    info(
                        "[WS cliente->DataApp] OK "
                        f"transporte=WSS metodo=GET url_rest_logica={url} "
                        f"despachado_por=/ws/client{proxy_hop}{proxy_msg} "
                        f"elapsed_ms={ws_resp.get('elapsed_ms', '?')}"
                    )
                body = ws_resp.get("body")
                return body if body is not None else {"_raw": ws_resp.get("text", "")}
        except Exception as exc:
            ws_exc = exc
    try:
        base_url, path = _url_parts_for_ws(url)
        proxy_body = _proxy_body_for_local_request("GET", path, timeout=timeout, base_url=base_url) if path != "/proxy" else None
        if proxy_body:
            r = SESSION.post(f"{base_url}/proxy", json=proxy_body, timeout=timeout)
        else:
            r = SESSION.get(url, timeout=timeout)
        r.raise_for_status()
        try:
            result = _unwrap_proxy_body(r.json())
        except Exception:
            result = {"_raw": r.text}
        if ws_exc and not quiet:
            info(f"[WS cliente->DataApp] handshake no disponible; fallback REST /proxy OK ({ws_exc})")
        return result
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url} -- el container no esta levantado?")
    except requests.exceptions.ReadTimeout:
        fail(f"Timeout ({timeout}s) esperando {url}")
    except requests.exceptions.HTTPError as exc:
        fail(f"HTTP {exc.response.status_code} en {url}")


def http_post(url, body, timeout=240):
    substep(f"POST {url}")
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("POST", url, body=body, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" payload.action={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                info(
                    "[WS cliente->DataApp] OK "
                    f"transporte=WSS metodo=POST url_rest_logica={url} "
                    f"despachado_por=/ws/client{proxy_hop}{proxy_msg} "
                    f"elapsed_ms={ws_resp.get('elapsed_ms', '?')}"
                )
                parsed_body = ws_resp.get("body")
                return parsed_body if parsed_body is not None else {"_raw": ws_resp.get("text", "")}
        except Exception as exc:
            ws_exc = exc
    try:
        base_url, path = _url_parts_for_ws(url)
        proxy_body = _proxy_body_for_local_request("POST", path, body=body, timeout=timeout, base_url=base_url) if path != "/proxy" else None
        if proxy_body:
            r = SESSION.post(f"{base_url}/proxy", json=proxy_body, timeout=timeout)
        else:
            r = SESSION.post(url, json=body, timeout=timeout)
        r.raise_for_status()
        try:
            result = _unwrap_proxy_body(r.json())
        except Exception:
            result = {"_raw": r.text}
        if ws_exc:
            info(f"[WS cliente->DataApp] handshake no disponible; fallback REST /proxy OK ({ws_exc})")
        return result
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) esperando respuesta de {url}\n"
            f"      El ECC TRUE Connector puede tardar en la primera llamada (token DAPS).\n"
            f"      Usa --timeout N para subir el limite."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} en {url}\n      {body_txt}")


def http_post_raw(url, body, timeout=240):
    substep(f"POST {url}")
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("POST", url, body=body, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" payload.action={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                info(
                    "[WS cliente->DataApp] OK "
                    f"transporte=WSS metodo=POST url_rest_logica={url} "
                    f"despachado_por=/ws/client{proxy_hop}{proxy_msg} "
                    f"elapsed_ms={ws_resp.get('elapsed_ms', '?')}"
                )
                if "text" in ws_resp:
                    return ws_resp.get("text", "")
                return json.dumps(ws_resp.get("body", {}), ensure_ascii=False)
        except Exception as exc:
            ws_exc = exc
    try:
        base_url, path = _url_parts_for_ws(url)
        proxy_body = _proxy_body_for_local_request("POST", path, body=body, timeout=timeout, base_url=base_url) if path != "/proxy" else None
        if proxy_body:
            r = SESSION.post(f"{base_url}/proxy", json=proxy_body, timeout=timeout)
        else:
            r = SESSION.post(url, json=body, timeout=timeout)
        r.raise_for_status()
        if proxy_body:
            try:
                result = json.dumps(_unwrap_proxy_body(r.json()), ensure_ascii=False)
                if ws_exc:
                    info(f"[WS cliente->DataApp] handshake no disponible; fallback REST /proxy OK ({ws_exc})")
                return result
            except Exception:
                pass
        if ws_exc:
            info(f"[WS cliente->DataApp] handshake no disponible; fallback REST /proxy OK ({ws_exc})")
        return r.text
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) esperando respuesta de {url}\n"
            f"      El ECC TRUE Connector puede tardar en la primera llamada (token DAPS).\n"
            f"      Usa --timeout N para subir el limite."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} en {url}\n      {body_txt}")


# =============================================================================
# Parser IDS -- JSON puro o embebido en multipart
# =============================================================================

def parse_ids(raw, want_type=None):
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            if not want_type or want_type in obj.get("@type", ""):
                return obj
    except Exception:
        pass

    blocks = re.findall(r'\{[\s\S]*?\}', raw)
    blocks.sort(key=len, reverse=True)

    if want_type:
        for b in blocks:
            try:
                obj = json.loads(b)
                if isinstance(obj, dict) and want_type in obj.get("@type", ""):
                    return obj
            except Exception:
                pass

    for b in blocks:
        try:
            obj = json.loads(b)
            if isinstance(obj, dict) and ("@id" in obj or "ids:resourceCatalog" in obj):
                return obj
        except Exception:
            pass

    return {}


# =============================================================================
# FASE 0 -- Resolver endpoints desde /status y Broker Fuseki
# =============================================================================

def _ecc_internal_url(endpoint_raw, connector_uri):
    """
    Convierte el endpoint publico del broker (puerto 8449 externo)
    al endpoint interno Docker (puerto 8889 /data -- Camel ECC receiver).
    Mapeo: ecc-workerN:8889/data
    """
    if endpoint_raw:
        m = re.search(r"(ecc-worker\d+):(\d+)", endpoint_raw)
        if m:
            host = m.group(1)
            return f"https://{host}:8889/data"
        m2 = re.search(r"(ecc-worker\d+)", endpoint_raw)
        if m2:
            return f"https://{m2.group(1)}:8889/data"
    m = re.search(r"worker(\d+)", connector_uri)
    if m:
        return f"https://ecc-worker{m.group(1)}:8889/data"
    return ""


def _ecc_label(ecc_url):
    m = re.search(r"(ecc-worker\d+):(\d+)", ecc_url)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    m2 = re.search(r"https?://([^/]+)", ecc_url)
    return m2.group(1) if m2 else ecc_url


def fase0_resolver_endpoints(coordinator_url, cid, req_timeout):
    phase(
        0,
        "Conectividad y Topología de Red",
        "Verificamos que el coordinador responde y consultamos al Metadata Broker (Fuseki)\n"
        "para obtener el mapa completo de todos los conectores IDS registrados en la red."
    )

    # -- health check del DataApp coordinator -----------------------------------
    step(f"Health-check del Worker-{cid} (GET /status)")
    status = http_get(f"{coordinator_url}/status", timeout=req_timeout)
    ok(f"Worker-{cid} responde correctamente en {coordinator_url}")
    field("instance",        status.get("instance", "?"))
    field("role (actual)",   status.get("role",     "worker"))
    print()
    print(f"    {BOLD}{GREEN}** Worker-{cid} asumio el rol de COORDINATOR **{RESET}")

    # -- TODOS los conectores desde el broker (incluido el coordinator) ----------
    step("Descubrimiento de topología via Broker Fuseki (GET /broker/connectors)")
    bd    = http_get(f"{coordinator_url}/broker/connectors", timeout=req_timeout)
    raw_p = bd.get("connectors", [])
    count = bd.get("count", len(raw_p))

    ok(f"{count} conectores en el broker")
    print()

    all_entries      = {}   # wid -> entry (todos, incluyendo coordinator)
    all_peers        = []   # solo los que NO son coordinator
    peers            = {}

    for c in raw_p:
        uri     = c.get("connector_uri", "")
        ep_raw  = c.get("endpoint", "")
        ecc_url = _ecc_internal_url(ep_raw, uri)
        label   = _ecc_label(ecc_url)
        m       = re.search(r"worker(\d+)", uri) or re.search(r"worker(\d+)", ecc_url)
        wid     = m.group(1) if m else "?"

        entry = {
            "connector_uri": uri,
            "ecc_url":       ecc_url,
            "ecc_label":     label,
            "endpoint_raw":  ep_raw,
        }
        all_entries[wid] = entry

        is_coord = (wid == str(cid))
        tag = f"  {CYAN}<- coordinator{RESET}" if is_coord else ""
        print(f"    {GRAY}*  Worker-{wid}{RESET}{tag}")
        field("  connector_uri",     uri,    indent=8)
        field("  endpoint (broker)", ep_raw, indent=8)
        field("  ecc_url (interno)", ecc_url, indent=8)
        print()

        if not is_coord:
            peers[f"worker{wid}"] = entry
            all_peers.append(entry)

    if not all_entries:
        fail(
            "El broker no devolvio ningun conector.\n"
            "      Comprueba que broker-core, broker-fuseki y broker-reverseproxy estan levantados\n"
            "      y que los workers se han auto-registrado."
        )

    # -- 0c: Datos del Worker-{cid} extraidos del Broker (Silencioso) -----------
    coord_entry = all_entries.get(str(cid))
    if coord_entry:
        coordinator_entry = coord_entry
    else:
        fallback_ecc = f"https://ecc-worker{cid}:8889/data"
        coordinator_entry = {
            "connector_uri": status.get("connector_uri", f"http://w3id.org/engrd/connector/worker{cid}"),
            "ecc_url":       fallback_ecc,
            "ecc_label":     _ecc_label(fallback_ecc),
        }

    if not all_peers:
        fail(
            "El broker no devolvio ningun peer (aparte del coordinator).\n"
            "      Comprueba que los demas workers estan levantados y registrados."
        )

    print()

    return {
        "coordinator": coordinator_entry,
        "peers":       peers,
        "all_peers":   all_peers,
    }

# =============================================================================
# Helper interno oculto -- El Coordinator obtiene el algoritmo via IDS/local
# =============================================================================

def helper_solicitar_algoritmo(coordinator_url, cid, endpoints, req_timeout):
    """
    El coordinator (worker-N) asume su rol nativo e inicializa el modelo localmente.
    (Muestra si se construyó imagen Docker).
    """
    phase(
        2,
        "Preparación de Artefactos FL (Imagen Docker)",
        "El coordinador localiza el algoritmo de IA (algorithm.py), su configuración\n"
        "(fl_config.json) y sus dependencias (requirements_algo.txt). Con estos ficheros\n"
        "construye una imagen Docker inmutable y la registra en el Registry privado\n"
        "para que los nodos autorizados puedan descargarla tras la negociación."
    )
    step("Compilación del algoritmo en imagen Docker (POST /fl/fetch-algorithm)")

    try:
        data = http_post(f"{coordinator_url}/fl/fetch-algorithm", {}, timeout=req_timeout)

        mode  = data.get("delivery_mode", "ids_base64")
        image = data.get("docker_image")

        if mode == "docker_image":
            print(f"      {GREEN}Imagen Docker compilada y registrada:{RESET}")
            print(f"        {BOLD}{image}{RESET}")
            print(f"      {GRAY}↳ Contiene: algorithm.py + fl_config.json + dependencias Python{RESET}")
            print(f"      {GRAY}↳ Los nodos autorizados la descargarán del Registry tras firmar contrato{RESET}")
        else:
            print(f"      {GRAY}Algoritmo cargado en memoria (modo legacy base64){RESET}")
        print()
    except Exception as exc:
        fail(f"El coordinator no pudo obtener el algoritmo internamente: {exc}")
        
# =============================================================================
# FASE 2 -- Descubrimiento de peers compatibles
# =============================================================================

def _mostrar_resultado_worker(w, endpoints, coord_label):
    """
    Muestra el resultado del analisis de un solo worker inmediatamente.
    Llamado en cuanto el backend devuelve la respuesta de /broker/discover/worker.
    """
    import time as _time

    uri      = w.get("connector_uri", "?")
    match    = w.get("match_ratio", 0)
    sel_csv  = w.get("selected_csv") or "(auto)"
    math_csv = w.get("math_filename") or sel_csv
    m        = re.search(r"worker(\d+)", uri)
    wid      = m.group(1) if m else "?"
    peer     = endpoints["peers"].get(f"worker{wid}", {})
    ecc      = peer.get("ecc_url") or w.get("ecc_url", "(desconocido)")
    pl       = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
    compatible = w.get("compatible", match >= 0.80)

    color = GREEN if compatible else YELLOW
    tag   = "OK " if compatible else "--- (descartado)"
    print(f"    {color}{tag}{RESET}  Worker-{wid}  {GRAY}{uri}{RESET}")
    field("  ECC (broker)", ecc, indent=8)

    # Handshake de metadatos (IDS Catalog fetch)
    ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
    ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)

    print(f"\n        {GRAY}Descubrimiento dinamico -- Consultando Catalogo IDS del peer (Self-Description):{RESET}")
    for ev in w.get("all_evaluated", []):
        fname_ev = ev["filename"]
        ratio_ev = ev["ratio"]
        common_c = ev.get("common_cols_count", 0)
        total_c  = ev.get("total_cols", 0)
        print(f"          - Recurso en catalogo: {fname_ev:<30} (match: {ratio_ev:.0%} - {common_c}/{total_c} cols)")

    llm_rec = w.get("llm_recommended")

    if llm_rec:
        llm_conf = w.get("llm_confidence", 0)
        llm_mod  = w.get("llm_model", "Ollama")
        llm_rsn  = w.get("llm_reasoning", "Decision basada en esquema semantico.")

        print(f"\n        {MAGENTA}-> IA Local ({llm_mod}) -- razonamiento:{RESET}")
        print(f"          {GRAY}", end="", flush=True)
        for _ch in llm_rsn:
            print(_ch, end="", flush=True)
            _time.sleep(0.008)
        print(f"{RESET}\n")

        field(f"  IA ({llm_mod}) Sugerencia", f"{CYAN}{llm_rec} (confianza: {llm_conf:.0%}){RESET}", indent=8)

        if llm_conf >= 0.80:
            field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)
        else:
            print(f"        {YELLOW} Confianza de IA < 80%. Fallback a emparejamiento matematico.{RESET}")
            field("  CSV (Seleccionado por columnas)", math_csv, indent=8)
            field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)
    else:
        print(f"\n        {YELLOW}LLM Fallback:{RESET} La validacion por IA no devolvio un formato valido o dio Timeout.")
        print(f"        {YELLOW}Activando plan de rescate: se aplicara la delegacion 100% matematica.{RESET}")
        field("  CSV (Seleccionado por columnas)", math_csv, indent=8)
        field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)

    if compatible:
        info(f"     El coordinator usara {sel_csv!r} en worker-{wid} para el entrenamiento FL")
    print()


def fase2_descubrir_peers(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]
    # ECC URL del coordinator para excluirlo del bucle de forma fiable
    coord_ecc_url = endpoints["coordinator"]["ecc_url"]

    phase(
        3,
        "Búsqueda de Nodos y Filtro de Compatibilidad (IA Local)",
        "El coordinador pregunta al Metadata Broker (Fuseki) por otros nodos disponibles en la red.\n"
        "A cada nodo encontrado le pide su Catálogo IDS. Utilizando un modelo generativo\n"
        "local (LLAMA) y algoritmos matemáticos, evalúa si los datos de los demás nodos\n"
        "son compatibles con los suyos (umbral ≥ 80% de similitud de columnas)."
    )

    step("Análisis de compatibilidad peer a peer (POST /broker/discover/worker)")

    # Obtener lista de todos los conectores del broker
    bd       = http_get(f"{coordinator_url}/broker/connectors", timeout=req_timeout)
    all_conn = bd.get("connectors", [])

    my_cols_count = "?"
    compatible    = []
    incompatible  = []

    for conn in all_conn:
        uri    = conn.get("connector_uri", "")
        ep_raw = conn.get("endpoint", "")

        # Derivar ecc_url del conector
        ecc_url = ""
        m_ecc = re.search(r"(ecc-worker\d+)", ep_raw or uri)
        if m_ecc:
            ecc_url = f"https://{m_ecc.group(1)}:8889/data"

        if not ecc_url:
            continue

        # Excluir el coordinator comparando por ecc_url (mas fiable que wid)
        if ecc_url == coord_ecc_url:
            continue

        try:
            w = http_post(
                f"{coordinator_url}/broker/discover/worker",
                {"ecc_url": ecc_url, "connector_uri": uri},
                timeout=req_timeout,
            )
        except Exception as exc:
            m_w = re.search(r"ecc-worker(\d+)", ecc_url)
            warn(f"Worker-{m_w.group(1) if m_w else '?'} error: {exc}")
            continue

        # Mostrar resultado inmediatamente
        _mostrar_resultado_worker(w, endpoints, coord_label)

        if w.get("compatible", w.get("match_ratio", 0) >= 0.80):
            compatible.append(w)
            my_cols_count = w.get("my_columns_count", my_cols_count)
        else:
            incompatible.append(w)

    total = len(compatible)
    ok(f"{total} workers compatibles de {len(compatible) + len(incompatible)} analizados")
    field("Columnas del coordinator", my_cols_count)

    if not compatible:
        warn(
            "Ningun worker supero el umbral del 80% de coincidencia de columnas.\n"
            "      Verifica que los workers tienen al menos un CSV con las mismas "
            "columnas que el coordinator."
        )

    return compatible


# =============================================================================
# FASE 3 -- Negociacion IDS coordinator -> cada peer
# =============================================================================

def fase3_negociar(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]

    phase(
        4,
        "Negociación Estricta de Contratos IDS",
        "Se inician los protocolos de confianza GAIA-X. El coordinador envía un 'Contract Request'\n"
        "a los nodos compatibles. Si aceptan los términos de soberanía, se firma un 'Contract Agreement'\n"
        "y se les otorga acceso a la URL y Token para descargar la imagen Docker del Algoritmo."
    )

    step("Negociación de contratos con peers (POST /fl/negotiate)")
    data     = http_post(f"{coordinator_url}/fl/negotiate", {}, timeout=req_timeout)
    accepted = data.get("accepted", [])
    rejected = data.get("rejected", [])

    print(f"\n  {BOLD}Detalle de cada negociacion IDS:{RESET}\n")

    for w in accepted:
        uri  = w.get("connector_uri", "?")
        tc   = w.get("transfer_contract", "")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        pl   = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
        pe   = peer.get("ecc_url")   or f"https://ecc-worker{wid}:8889/data"

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        field("  ECC (broker)", pe, indent=6)
        ids_arrow("out", "ids:DescriptionRequestMessage",        coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage",       pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",           coord_label, pl)
        ids_arrow("in",  "ids:ContractAgreementMessage",         pl, coord_label)
        ids_arrow("out", "ids:ContractAgreementMessage (confirm)", coord_label, pl)
        ids_arrow("in",  "ids:MessageProcessedNotificationMsg",  pl, coord_label)
        print(f"    {GREEN}ACEPTA -- contrato IDS establecido{RESET}")
        if tc:
            field("transfer_contract", tc[:72] + ("..." if len(tc) > 72 else ""))
        print()

    for w in rejected:
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        msg    = w.get("message", "")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        peer   = endpoints["peers"].get(f"worker{wid}", {})
        pl     = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
        pe     = peer.get("ecc_url")   or f"https://ecc-worker{wid}:8889/data"

        # Si la razon es 'unexpected_ids_response', extrae el motivo real del mensaje
        # (ocurre cuando el contenedor tiene cod. antiguo y no detecta el @type vacio)
        actual_reason = reason
        if reason == "unexpected_ids_response" and msg:
            try:
                import ast as _ast
                _msg_dict = _ast.literal_eval(msg) if isinstance(msg, str) else msg
                actual_reason = _msg_dict.get("reason", reason)
            except Exception:
                pass

        reason_labels = {
            "fl_opt_out"             : "FL_OPT_OUT=true (soberania del dato) -- IDS RejectionMessage",
            "fl_participation_denied": "FL_AUTHORIZED_URIS vacio (no autorizado a participar)",
            "unauthorized_consumer"  : "consumer URI no autorizada",
            "error"                  : "error de comunicacion",
        }
        reason_text = reason_labels.get(actual_reason, actual_reason)

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        field("  ECC (broker)", pe, indent=6)
        ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",     coord_label, pl)
        ids_arrow("in",  "ids:RejectionMessage",           pl, coord_label)
        print(f"    {RED}RECHAZA -- {reason_text}{RESET}")
        if actual_reason != reason:
            field("reason (API)", f"{actual_reason}  (detectado en mensaje IDS)")
        else:
            field("reason (API)", reason)
        if msg:
            field("mensaje",     msg[:100])
        print()

    # -- Resumen ---------------------------------------------------------------
    _sep("-", color=BLUE)
    print(f"  {BOLD}Resumen de participacion FL:{RESET}\n")

    for w in accepted:
        uri = w.get("connector_uri", "?")
        m   = re.search(r"worker(\d+)", uri)
        wid = m.group(1) if m else "?"
        print(f"    {GREEN}PARTICIPA   Worker-{wid}   {GRAY}{uri}{RESET}")

    for w in rejected:
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        msg    = w.get("message", "")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        # Extraer motivo real si viene como 'unexpected_ids_response'
        if reason == "unexpected_ids_response" and msg:
            try:
                import ast as _ast
                _md = _ast.literal_eval(msg) if isinstance(msg, str) else msg
                reason = _md.get("reason", reason)
            except Exception:
                pass
        reason_label = {
            "fl_opt_out": "fl_opt_out (IDS soberania)",
            "unauthorized_consumer": "unauthorized (IDS)",
        }.get(reason, reason)
        print(f"    {RED}RECHAZADO   Worker-{wid}   {GRAY}{uri}  --  {reason_label}{RESET}")

    print()

    return {"accepted": accepted, "rejected": rejected}


# =============================================================================
# Verificacion del coordinator
# =============================================================================

def verificar_coordinator(coordinator_url, cid, endpoints, req_timeout):
    print()
    _sep("-", color=BLUE)
    print(f"{BOLD}{BLUE}  Estado del coordinator tras la negociacion{RESET}")
    _sep("-", color=BLUE)

    step("Verificación del estado del coordinador (GET /status)")
    data = http_get(f"{coordinator_url}/status", timeout=req_timeout)

    role      = data.get("role", "?")
    algo_ok   = data.get("algorithm_loaded", False)
    config_ok = data.get("config_loaded", False)
    fl_status = data.get("fl_status", "?")
    peers     = data.get("peer_eccs", [])
    fl_cfg    = data.get("fl_config") or {}

    field("instance",         data.get("instance", "?"))
    field("role",             role)
    field("algorithm_loaded", "SI" if algo_ok  else "NO")
    field("config_loaded",    "SI" if config_ok else "NO")
    field("fl_status",        fl_status)

    if fl_cfg:
        section("FL Config")
        for k, v in fl_cfg.items():
            field(f"  {k}", v, indent=6)

    if peers:
        section("Peer ECCs activos (workers aceptados)")
        for p in peers:
            m   = re.search(r"worker(\d+)", p)
            wid = m.group(1) if m else "?"
            b   = endpoints["peers"].get(f"worker{wid}", {})
            b_ecc = b.get("ecc_url", "")
            match_tag = f"  {GREEN}(= broker){RESET}" if b_ecc == p else (
                        f"  {YELLOW}(broker: {b_ecc}){RESET}" if b_ecc else "")
            print(f"      {GRAY}Worker-{wid}: {p}{RESET}{match_tag}")

    print()
    if role == "coordinator" and algo_ok and config_ok:
        ok("Coordinator listo para /fl/start")
    else:
        warn(f"Estado inesperado: role={role}  algo={algo_ok}  config={config_ok}")


# =============================================================================
# FASE 4 -- Arranque del entrenamiento FL
# =============================================================================

def fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout):
    phase(
        5,
        "Entrenamiento Federado (Federated Learning)",
        "Arranca la primera ronda de entrenamiento. El coordinador notifica a los trabajadores\n"
        "autorizados que comiencen a entrenar de forma distribuida y monitoriza el progreso\n"
        "mediante polling HTTP."
    )

    step("Arranque del entrenamiento (POST /fl/start)")
    print(f"    -> Inicializando la configuracion federada del coordinator")
    print(f"       Preparando un espacio de entrada comun para todos los workers")
    print()
    print(f"    -> Ejecutando la seleccion compartida de variables numericas")
    print(f"       Analizando el dataset de referencia definido para el coordinator")
    print()
    data   = http_post(f"{coordinator_url}/fl/start", {}, timeout=req_timeout)
    status = data.get("status", "?")
    peers  = data.get("peers", [])
    cfg    = data.get("fl_config", {}) or {}
    fs     = data.get("feature_selection", {}) or {}

    if status == "started":
        print()
        ok("Entrenamiento FL arrancado correctamente")
    else:
        warn(f"Respuesta inesperada: status={status}")

    if fs.get("enabled"):
        source = fs.get("source") or "dataset de referencia del coordinator"
        source = os.path.basename(str(source))
        count = fs.get("selected_count", "?")
        print()
        print(f"    -> Seleccion de variables completada")
        print(f"       Dataset de referencia: {source}")
        print(f"       Variables numericas compartidas: {count}")
        print()
        print(f"    -> Mascara numerica persistida y distribuida")
        print(f"       Todos los workers entrenaran con la misma seleccion de entrada")

    section("Workers entrenando")
    for p in peers:
        m   = re.search(r"worker(\d+)", p)
        wid = m.group(1) if m else "?"
        b   = endpoints["peers"].get(f"worker{wid}", {})
        b_ecc = b.get("ecc_url", "")
        note  = f"  {GREEN}(broker){RESET}" if b_ecc == p else (
                f"  {YELLOW}(broker: {b_ecc}){RESET}" if b_ecc else "")
        print(f"      {GREEN}Worker-{wid}: {GRAY}{p}{RESET}{note}")

    print()
    info(f"Monitoriza:  GET {coordinator_url}/fl/status")
    info(f"Resultados:  GET {coordinator_url}/fl/results  (cuando status=completed)")
    info(f"Modelo:      GET {coordinator_url}/fl/model")


# =============================================================================
# FASE 5 -- Monitorizacion del entrenamiento en tiempo real
# =============================================================================

def _ids_log(direction, msg_type, src, dst):
    arrow = "--" if direction == "out" else "--"
    color = CYAN   if direction == "out" else GREEN
    short = msg_type.replace("ids:", "").replace("Message", "Msg")
    print(f"      {color}[IDS {arrow}]  {short:<44}{GRAY}{src}    {dst}{RESET}")


def _coord_ecc_label(cid):
    return f"ecc-worker{cid}:8889"


def _print_ronda_header(rnd_num, total_rounds, cid):
    print()
    print(f"    {CYAN}{'' * 54}{RESET}")
    print(f"    {BOLD}{CYAN}  RONDA {rnd_num}/{total_rounds or '?'}  "
          f"[coordinator-{cid}]{RESET}")
    print(f"    {CYAN}{'' * 54}{RESET}")


def _print_handshake_algoritmo(rnd_num, wid, peer_lbl, cid):
    """
    Handshake IDS completo para distribucion de algorithm.py + fl_config.json.
    En app.py esto ocurre en _negotiate_and_send_algorithm, que se llama
    en CADA ronda (el coordinator lo reenvia para asegurar sincronia).
    """
    coord_lbl = _coord_ecc_label(cid)
    print(f"\n      {BOLD}-> Worker-{wid}{RESET}")
    _ids_log("out", "ids:DescriptionRequestMessage",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:DescriptionResponseMessage",
             peer_lbl, coord_lbl)
    _ids_log("out", "ids:ContractRequestMessage",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:ContractAgreementMessage",
             peer_lbl, coord_lbl)
    _ids_log("out", "ids:ContractAgreementMessage (confirmacion)",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:MessageProcessedNotificationMessage",
             peer_lbl, coord_lbl)
    print(f"      {GRAY}[ronda {rnd_num}] algorithm.py + fl_config.json "
          f"(Docker/b64) -> {peer_lbl}  {GREEN}{RESET}")


def fase5_monitorizar_fl(coordinator_url, cid, nego, endpoints, req_timeout):
    """
    Monitoriza el entrenamiento FL con polling HTTP sobre /fl/status.
    Los pesos se siguen transportando por IDS/ECC, usando WSS cuando WS_ECC=true.
    """
    accepted      = nego.get("accepted", [])
    accepted_wids = sorted(
        m.group(1)
        for w in accepted
        for m in [re.search(r"worker(\d+)", w.get("connector_uri", ""))] if m
    )

    step("Monitorizacion del entrenamiento via /proxy")
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        ws_url = coordinator_url.replace("https://", "wss://").replace("http://", "ws://")
        print(f"      {GRAY}Entrada real : WebSocket {ws_url}/ws/client{RESET}")
        print(f"      {GRAY}Despacho    : POST /proxy  (messageType=ArtifactRequestMessage; payload.action=fl_status){RESET}")
    else:
        print(f"      {GRAY}Endpoint    : POST {coordinator_url}/proxy  (messageType=ArtifactRequestMessage; payload.action=fl_status){RESET}")
    print(f"      {GRAY}Workers participantes: {', '.join('worker-' + w for w in accepted_wids)}{RESET}")

    step("Verificacion de transporte conservado (GET /transport/status)")
    try:
        td = http_get(f"{coordinator_url}/transport/status", timeout=10)
        client_ws = td.get("client_dataapp_ws", {})
        ecc_wss_enabled = td.get("ecc_wss_enabled", False)
        ids_ecc_only = td.get("ids_ecc_only", False)
        weights_via_ecc = td.get("weights_via_ecc", False)
        info(f"[WS] /ws/client      -> {client_ws.get('requests', 0)} peticion(es) cliente->DataApp")
        if ids_ecc_only or weights_via_ecc:
            info(f"[ECC] Transporte de pesos FL: IDS via ECC<->ECC sobre {'WSS' if ecc_wss_enabled else 'HTTPS'}")
    except Exception as _te:
        warn(f"No se pudo consultar /transport/status: {_te}")

    _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids)

def _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids):
    """
    Monitorizacion por polling HTTP (GET /fl/status cada 5s).
    """
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        info("Monitorizando via WebSocket /ws/client -> POST /proxy payload.action=fl_status cada 5s...")
    else:
        info("Monitorizando via POST /proxy payload.action=fl_status cada 5s...")

    # Esperar a que el FL arranque
    for _ in range(30):
        try:
            fl = http_get(f"{coordinator_url}/fl/status", timeout=10, quiet=True)
            if fl.get("status") not in ("idle", ""):
                ok("FL en marcha"); break
        except Exception:
            pass
        time.sleep(2)

    seen_rounds          = 0
    next_rnd_to_announce = 1
    total_rounds         = None
    weights_shown        = {}
    t_start              = time.time()
    poll_interval        = 5

    while True:
        if time.time() - t_start > 3600:
            warn("Timeout de monitorizacion (1h)"); break

        try:
            fl = http_get(f"{coordinator_url}/fl/status", timeout=10, quiet=True)
        except Exception as e:
            warn(f"Error polling /fl/status: {e}"); time.sleep(poll_interval); continue

        status       = fl.get("status", "?")
        history      = fl.get("history", [])
        total_rounds = fl.get("total_rounds") or total_rounds

        # Vaciar history: mostrar rondas cerradas
        while seen_rounds < len(history):
            entry   = history[seen_rounds]
            rnd_num = entry.get("round", seen_rounds + 1)
            elapsed = entry.get("elapsed_seconds", 0)
            workers = entry.get("workers_ok", "?")
            samples = entry.get("total_samples", 0)
            gm      = entry.get("global_metrics", {})

            def _fv(k):
                v = gm.get(k)
                return f"{v:.4f}" if isinstance(v, float) else (str(v) if v is not None else "--")

            already = weights_shown.get(rnd_num, set())
            for wid in accepted_wids:
                if wid not in already:
                    already.add(wid)
                    n_exp = len(accepted_wids) + 1
                    total_so_far = 1 + len(already)
                    pe   = endpoints["peers"].get(f"worker{wid}", {})
                    pl   = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                    print()
                    print(f"    {BOLD}[ronda {rnd_num}]  Pesos recibidos de worker-{wid} (ECC-WSS):{RESET}")
                    print(f"      {GREEN}[ECC-WSS]  fl_weights::worker{wid}::round{rnd_num}  {GRAY}{pl}  --  {_coord_ecc_label(cid)}{RESET}")
                    print(f"    {GRAY} Pesos acumulados ({total_so_far}/{n_exp}){RESET}")
            weights_shown[rnd_num] = already

            print()
            print(f"    {GRAY}[ronda {rnd_num}] FedAvg -- {workers} workers, {samples:,} muestras{RESET}")
            print(f"    {GREEN}Ronda {rnd_num} OK en {elapsed}s  "
                  f"acc={_fv('accuracy')}  auc={_fv('auc')}  loss={_fv('loss')}{RESET}")
            seen_rounds += 1
            next_rnd_to_announce = seen_rounds + 1

        # Anunciar ronda actual si podemos
        rnd_match = re.match(r"round_(\d+)", status)
        if rnd_match:
            rnd_num = int(rnd_match.group(1))
            if rnd_num == next_rnd_to_announce:
                weights_shown.setdefault(rnd_num, set())
                next_rnd_to_announce = rnd_num + 1
                _print_ronda_header(rnd_num, total_rounds, cid)
                for w in nego.get("accepted", []):
                    uri = w.get("connector_uri", "")
                    m   = re.search(r"worker(\d+)", uri)
                    wid = m.group(1) if m else "?"
                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                    _print_handshake_algoritmo(rnd_num, wid, pl, cid)

        if status == "completed" and seen_rounds >= (total_rounds or 0):
            ok(f" FL completado -- {seen_rounds} rondas"); break
        elif status == "failed":
            warn(" FL termino con status=failed"); break

        time.sleep(poll_interval)

# =============================================================================
# RESULTADOS DEL ENTRENAMIENTO FL
# =============================================================================

def _mostrar_resultados_fl(coordinator_url, cid, req_timeout):
    """
    Muestra un resumen completo de resultados tras finalizar el entrenamiento FL.
    Consulta /fl/status y /fl/results para obtener metricas globales,
    per-class F1, confusion matrix y evolucion por ronda.
    """
    print()
    _sep("=", color=BOLD + GREEN)
    print(f"{BOLD}{GREEN}  RESULTADOS DEL ENTRENAMIENTO FEDERADO{RESET}")
    _sep("=", color=BOLD + GREEN)

    # --- Obtener datos del coordinator ---
    fl_data = {}
    fl_results = []
    try:
        fl_data = http_get(f"{coordinator_url}/fl/status", timeout=req_timeout)
    except Exception as e:
        warn(f"No se pudo obtener /fl/status: {e}")

    try:
        fl_results = http_get(f"{coordinator_url}/fl/results", timeout=req_timeout)
    except Exception:
        pass

    history = fl_data.get("history", fl_results if isinstance(fl_results, list) else [])
    if not history:
        warn("No hay historial de rondas disponible")
        return

    model_data = {}
    r_model = None
    try:
        model_data = http_get(f"{coordinator_url}/fl/model", timeout=req_timeout)
        r_model = True
    except Exception:
        r_model = None

    # --- Evolucion por ronda ---
    step("Evolucion por Ronda")
    header = f"  {'Ronda':>6}  {'Workers':>8}  {'Muestras':>10}  {'Accuracy':>10}  {'AUC':>8}  {'F1-macro':>9}  {'MCC':>8}  {'Loss':>8}  {'Tiempo':>8}"
    print(f"  {CYAN}{header}{RESET}")
    print(f"  {CYAN}{'-' * len(header)}{RESET}")

    for entry in history:
        rnd     = entry.get("round", "?")
        workers = entry.get("workers_ok", "?")
        samples = entry.get("total_samples", 0)
        gm      = entry.get("global_metrics", {})
        elapsed = entry.get("elapsed_seconds", 0)

        def _v(k, fmt=".4f"):
            v = gm.get(k)
            if v is None: return "--"
            return f"{v:{fmt}}"

        print(f"  {rnd:>6}  {workers:>8}  {samples:>10,}  {_v('accuracy'):>10}  "
              f"{_v('auc'):>8}  {_v('f1_macro'):>9}  {_v('mcc'):>8}  "
              f"{_v('loss'):>8}  {elapsed:>7.1f}s")
    print()

    # --- Mejor modelo global ---
    last = history[-1] if history else {}
    best_gm = model_data.get("metrics") or last.get("global_metrics", {})

    step("Metricas Globales del Mejor Modelo")
    metrics_order = [
        ("accuracy",    "Accuracy"),
        ("auc",         "AUC (macro)"),
        ("precision",   "Precision (macro)"),
        ("recall",      "Recall (macro)"),
        ("f1_macro",    "F1-Score (macro)"),
        ("focus_f1",    "Focus F1 (EXP/DIS/REC)"),
        ("f1_weighted", "F1-Score (weighted)"),
        ("mcc",         "MCC (Matthews)"),
        ("loss",        "Loss"),
    ]
    for key, label in metrics_order:
        v = best_gm.get(key)
        if v is not None:
            # Colorear segun calidad
            if key in ("accuracy", "auc", "f1_macro", "mcc") and isinstance(v, (int, float)):
                c = GREEN if v >= 0.9 else (YELLOW if v >= 0.7 else RED)
            elif key == "loss" and isinstance(v, (int, float)):
                c = GREEN if v < 0.3 else (YELLOW if v < 0.5 else RED)
            else:
                c = WHITE
            field(label, f"{c}{v:.6f}{RESET}")

    # Modo de clasificacion
    mode = best_gm.get("classification_mode", "")
    n_classes = best_gm.get("num_classes", "") or model_data.get("num_classes", "")
    if not mode and n_classes:
        mode = "multiclass" if int(n_classes) > 2 else "binary"
    if mode:
        field("Modo", f"{mode} ({n_classes} clases)" if n_classes else mode)
    print()

    # --- Distribucion de datos ---
    step("Distribucion de Datos entre Workers")
    total_samples = sum(e.get("total_samples", 0) for e in history)
    if total_samples > 0 and history:
        last_entry = history[-1]
        n_workers = last_entry.get("workers_ok", "?")
        field("Workers participantes", n_workers)
        field("Total muestras (ultima ronda)", f"{last_entry.get('total_samples', 0):,}")
        field("Rondas completadas", len(history))
    print()

    # --- Distribucion de clases (UNSW-NB15) ---
    try:
        class_names = model_data.get("class_names", [])
        per_class = model_data.get("per_class_report", {})

        if class_names:
            step("Distribucion de aciertos de cada clase (UNSW-NB15)")
            n_classes = len(class_names)
            field("Modo de clasificacion", f"Multiclase ({n_classes} clases)" if n_classes > 2 else "Binario")
            print()
            print(f"    {'Clase':<20} {'F1-Score':>10}  {'Rendimiento':>32}")
            print(f"    {'-'*20} {'-'*10}  {'-'*32}")
            sorted_classes = sorted(
                [(c, per_class.get(c, 0.0)) for c in class_names],
                key=lambda x: x[1], reverse=True
            )
            for cls_name, f1_val in sorted_classes:
                if not isinstance(f1_val, (int, float)):
                    f1_val = 0.0
                bar_len = int(f1_val * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                c = GREEN if f1_val >= 0.8 else (YELLOW if f1_val >= 0.5 else RED)
                print(f"    {cls_name:<20} {c}{f1_val:>10.4f}{RESET}  {c}{bar}{RESET}")
            print()
    except Exception:
        pass

    # --- Confusion Matrix ---
    try:
        if r_model:
            cm = model_data.get("confusion_matrix", [])
            class_names_cm = model_data.get("class_names", [
                "Benign", "GenericAttack", "Exploits", "Fuzzers", "GroupedAttacks"
            ])
            if cm and len(cm) > 2:
                step("Confusion Matrix (filas=real, cols=predicho)")
                n = min(len(cm), len(class_names_cm))
                row_width = max(14, max(len(name) for name in class_names_cm[:n]))
                short = [_cm_short_label(c) for c in class_names_cm[:n]]
                header_line = f"{'':>{row_width}}  " + "  ".join(f"{s:>7}" for s in short)
                print(f"    {CYAN}{header_line}{RESET}")
                for i in range(n):
                    row = cm[i] if i < len(cm) else []
                    padded_row = [row[j] if j < len(row) else 0 for j in range(n)]
                    row_vals = "  ".join(f"{val:>7}" for val in padded_row)
                    print(f"    {class_names_cm[i]:>{row_width}}  {row_vals}")
                print()
    except Exception:
        pass


# =============================================================================
# FASE 6 -- Test de Acceso al Modelo Global (Soberania de Datos)
# =============================================================================

def fase6_test_acceso_modelo(coordinator_url, cid, nego, endpoints, req_timeout):
    phase(
        6,
        "Auditoría Final y Soberanía de Datos",
        "El modelo global resultante se ensambla y se registra en el Catálogo IDS como un nuevo\n"
        "Activo Digital. Su contrato dictamina que SOLO los trabajadores que participaron en\n"
        "su entrenamiento tienen derecho a descargarlo. A continuación comprobamos este bloqueo."
    )

    try:
        fl_res = None
        info("Esperando a que el recurso del modelo FL se publique en el catalogo IDS...")
        for _ in range(15):
            sd = http_get(f"{coordinator_url}/ids/self-description", timeout=10)
            cat = (sd.get("ids:resourceCatalog") or [{}])[0]
            res = cat.get("ids:offeredResource", [])

            fl_res = next(
                (x for x in res if
                 "fl_model_coordinator" in x.get("@id", "") or
                 "FL Global Model" in ((x.get("ids:title") or [{}])[0]).get("@value", "")),
                None
            )
            if fl_res:
                break
            time.sleep(1)

        if not fl_res:
            warn("No se encontro el recurso del modelo FL en el catalogo tras la espera")
            return

        cid_val = ((fl_res.get("ids:contractOffer") or [{}])[0]).get("@id", "")
        if not cid_val:
            warn("No se encontro ContractOffer en el modelo")
            return

    except Exception as e:
        warn(f"Error parseando IDs para la fase 6: {e}")
        return

    # Obtenemos las URLs directamente del broker sin hardcodear
    coord_ecc = endpoints["coordinator"].get("ecc_url")
    coord_uri = endpoints["coordinator"].get("connector_uri")

    if not coord_ecc or not coord_uri:
        warn("No se pudo extraer la URL del coordinator desde el Broker para realizar la prueba.")
        return

    # -- Extraer TODOS los peers descubiertos (aceptados, rechazados Y descartados) --
    # De este modo worker-4 (schema incompatible -> descartado en discovery) tambien
    # se prueba y recibe un RejectionMessage real del coordinator porque su URI
    # no esta en la lista de autorizados del contrato FL.
    accepted_uris = {re.search(r"worker(\d+)", w.get("connector_uri", "")).group(1)
                     for w in nego.get("accepted", [])
                     if re.search(r"worker(\d+)", w.get("connector_uri", ""))}

    workers_to_test = []
    for wid_key in sorted(endpoints["peers"].keys()):   # worker1, worker2, ...
        m = re.search(r"worker(\d+)", wid_key)
        if m:
            workers_to_test.append(m.group(1))
    # Anadir los que puedan venir de nego pero no esten en endpoints["peers"]
    for w in nego.get("accepted", []) + nego.get("rejected", []):
        m = re.search(r"worker(\d+)", w.get("connector_uri", ""))
        if m and m.group(1) not in workers_to_test:
            workers_to_test.append(m.group(1))
    workers_to_test = list(dict.fromkeys(workers_to_test))

    if not workers_to_test:
        warn("No hay peers descubiertos para probar en la Fase 6.")
        return

    # -- Ejecutar el test de acceso global --
    for target_wid in workers_to_test:
        if f"worker{target_wid}" not in endpoints["peers"]:
            continue

        w_url = f"https://localhost:{5000 + int(target_wid)}"
        # ECC :8889 no es accesible desde DataApps -- redirigir al DataApp coordinator
        # que implementa la logica del contrato IDS directamente en su endpoint /data.
        _m_f6 = re.search(r"ecc-(worker\d+)", coord_ecc)
        _fwd_dataapp = (
            f"https://be-dataapp-{_m_f6.group(1)}:8500/data"
            if _m_f6 else coord_ecc
        )
        payload = {
            "Forward-To"      : _fwd_dataapp,
            "connectorUri"    : coord_uri,   # URI IDS explicita -- evita inferencia incorrecta
            "messageType"     : "ContractRequestMessage",
            "requestedElement" : fl_res.get("@id", ""),
            "contractId"      : cid_val,
            "contractProvider": coord_uri,
        }

        print()
        step(f"Test de acceso: Worker-{target_wid} solicita el modelo al Coordinador")
        _ids_log("out", "ids:ContractRequestMessage", f"worker-{target_wid}", f"coordinator-{cid}")

        try:
            raw = http_post_raw(f"{w_url}/proxy", payload, timeout=req_timeout)
            parsed = parse_ids(raw)
            if not parsed:
                parsed = parse_ids(raw, "Message") or {}

            ids_type = parsed.get("@type", "")

            if "ContractAgreement" in ids_type:
                step("Resultado: Acceso PERMITIDO (Contract Agreement)")
                _ids_log("in", "ids:ContractAgreementMessage", f"coordinator-{cid}", f"worker-{target_wid}")

                transfer_contract = parsed.get("@id", "?")
                ok(f"Worker-{target_wid} -- acceso PERMITIDO al modelo (Contract Agreement)")
                field("Recurso Target", fl_res.get("@id", "?"), indent=8)
                field("transferContract id", transfer_contract, indent=8)

            elif ("Rejection" in ids_type or "ContractRejection" in ids_type
                  or parsed.get("status") == "rejected"
                  or parsed.get("reason") in ("unauthorized_consumer", "fl_opt_out")):
                # Era un rechazo ESPERADO? -> worker no participo en el FL
                _is_expected_rejection = target_wid not in accepted_uris

                if _is_expected_rejection:
                    step("Resultado: Acceso DENEGADO (Soberanía de Datos aplicada)")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    ok(
                        f"Worker-{target_wid} -- acceso DENEGADO   "
                        f"(no participo en el FL -- Soberania IDS aplicada correctamente)"
                    )
                    _reason = parsed.get("reason") or parsed.get("ids:rejectionReason", "policy_enforcement")
                    field("Motivo de rechazo", str(_reason), indent=8)
                    field("Politica aplicada", "connector-restricted-policy (ids:rightOperand)", indent=8)
                else:
                    step("Resultado: Rejection Message (INESPERADO)")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    reason = parsed.get("ids:rejectionReason", "?")
                    fail(f"Worker-{target_wid} -- acceso DENEGADO al modelo (sorprendente, era participante)")
                    field("Rejection Reason", str(reason), indent=8)

            else:
                step("Resultado: Respuesta IDS no reconocida")
                _ids_log("in", "PolicyRejection", f"coordinator-{cid}", f"worker-{target_wid}")
                warn(f"Worker-{target_wid} -- respuesta IDS no reconocida: {ids_type!r}")
                field("raw_response", (raw[:200] + "...") if len(raw) > 200 else raw, indent=8)

        except Exception as e:
            warn(f"Error proxy Worker-{target_wid}: {e}")

        print()


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="PFG -- Demostracion IDS + Federated Learning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--coordinator", default="2", metavar="N",
                   help="Numero del worker coordinator (default: 2)")
    p.add_argument("--coordinator-port", type=int, default=0, metavar="PORT",
                   help=(
                       "Puerto localhost del dataapp coordinator "
                       "(default: 5000 + --coordinator, e.g. 5002 para coordinator=2)"
                   ))
    p.add_argument("--skip-fl", action="store_true",
                   help="No arrancar el entrenamiento (solo fases 0-3)")
    p.add_argument("--timeout", type=int, default=240, metavar="SEG",
                   help="Timeout HTTP en segundos (default: 240)")
    p.add_argument("--no-client-ws", action="store_true",
                   help="Desactiva el canal WebSocket cliente->DataApp y usa REST directo")
    return p.parse_args()


# =============================================================================
# RESET GLOBAL Y LISTENER DE TECLADO
# =============================================================================

def _cleanup_workers(coordinator_url, endpoints, req_timeout):
    """
    Recorre el coordinator y todos los workers conocidos y llama a
    POST /system/reset para devolverlos al estado inicial (sin archivos FL).
    """
    workers = [("coordinator", coordinator_url)]
    if endpoints and "peers" in endpoints:
        for w_name in endpoints["peers"]:
            num = w_name.replace("worker", "")
            try:
                w_url = f"https://localhost:{5000 + int(num)}"
                workers.append((w_name, w_url))
            except ValueError:
                pass
    for name, url in workers:
        try:
            r = SESSION.post(f"{url}/system/reset", timeout=req_timeout, verify=TLS_CERT)
            if r.ok:
                print(f"  {GREEN}[OK]{RESET} {name} restaurado.")
            else:
                print(f"  {RED}[FAIL]{RESET} {name} devolvio {r.status_code}")
        except Exception as exc:
            print(f"  {RED}[ERR ]{RESET} No se pudo contactar a {name}: {exc}")

    # -- Limpieza COMPLETA de artefactos Docker FL ------------------------------
    try:
        import subprocess

        # 1. Eliminar imagenes fl-algo del daemon Docker local
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=10
        )
        fl_images = [img.strip() for img in result.stdout.splitlines()
                     if "fl-algo" in img and img.strip()]

        for img in fl_images:
            rm = subprocess.run(
                ["docker", "rmi", "-f", img],
                capture_output=True, text=True, timeout=15
            )
            if rm.returncode == 0:
                print(f"  {GREEN}[OK]{RESET} Imagen Docker eliminada: {img}")
            else:
                print(f"  {YELLOW}[WARN]{RESET} No se pudo eliminar {img}: {rm.stderr.strip()}")

        # 2. Purgar el Registry privado (fl-registry) -- borrar catalogo de tags
        try:
            import requests as _req
            # Listar tags del repositorio fl-algo en el registry
            r_tags = _req.get("http://localhost:5050/v2/fl-algo/tags/list", timeout=5)
            if r_tags.ok:
                tags = r_tags.json().get("tags") or []
                for tag in tags:
                    # Obtener digest para poder borrar
                    r_digest = _req.head(
                        f"http://localhost:5050/v2/fl-algo/manifests/{tag}",
                        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
                        timeout=5
                    )
                    digest = r_digest.headers.get("Docker-Content-Digest")
                    if digest:
                        r_del = _req.delete(
                            f"http://localhost:5050/v2/fl-algo/manifests/{digest}",
                            timeout=5
                        )
                        if r_del.status_code in (200, 202):
                            print(f"  {GREEN}[OK]{RESET} Registry: tag fl-algo:{tag} purgado")
                        else:
                            print(f"  {YELLOW}[WARN]{RESET} Registry: no se pudo purgar fl-algo:{tag} (HTTP {r_del.status_code})")
                if not tags:
                    print(f"  {GRAY}[--]{RESET} Registry: no hay tags fl-algo pendientes.")
            else:
                print(f"  {GRAY}[--]{RESET} Registry: repositorio fl-algo no existe (limpio).")
        except Exception:
            print(f"  {GRAY}[--]{RESET} Registry fl-registry no accesible (puede estar parado).")

        # 3. Limpiar directorio _docker_build temporal dentro de cada worker
        worker_containers = ["be-dataapp-worker1", "be-dataapp-worker2",
                             "be-dataapp-worker3", "be-dataapp-worker4"]
        for cname in worker_containers:
            rm_build = subprocess.run(
                ["docker", "exec", cname, "rm", "-rf", "/home/nobody/data/_docker_build"],
                capture_output=True, text=True, timeout=10
            )
            if rm_build.returncode == 0:
                print(f"  {GREEN}[OK]{RESET} {cname}: _docker_build limpiado")

        if not fl_images:
            print(f"  {GRAY}[--]{RESET} No se encontraron imagenes Docker FL locales.")
    except Exception as exc:
        print(f"  {YELLOW}[WARN]{RESET} No se pudo limpiar artefactos Docker: {exc}")


def _start_keyboard_listener(coordinator_url_ref, endpoints_ref, req_timeout):
    """
    Hilo daemon que escucha el teclado. Al pulsar 'P' o 'p' (o Ctrl+C):
      1. Imprime un aviso coloreado.
      2. Llama a _cleanup_workers para limpiar los DataApps.
      3. Termina el proceso.
    Solo funciona en Windows (usa msvcrt). En Linux/Mac se ignora.
    """
    global _cancel_requested
    if not _HAS_MSVCRT:
        return
    while not _cancel_requested:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch.lower() == 'p':
                _cancel_requested = True
                print()
                print(f"  {RED}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
                print(f"  {RED}{BOLD}║  [P] CANCELACION MANUAL SOLICITADA           ║{RESET}")
                print(f"  {RED}{BOLD}║  Limpiando todos los Workers y Coordinator   ║{RESET}")
                print(f"  {RED}{BOLD}╚══════════════════════════════════════════════╝{RESET}")
                print()
                _cleanup_workers(
                    coordinator_url_ref[0],
                    endpoints_ref[0],
                    req_timeout,
                )
                print(f"  {GREEN}Sistema restaurado. Puedes volver a ejecutar pfg_ids_fl_flow.py.{RESET}")
                print()
                os._exit(0)
        time.sleep(0.1)


def fase1_verificar_catalogo_coordinator(coordinator_url, cid, req_timeout):
    """
    Tras la FASE 0, consulta el Catalogo IDS del Coordinator (/ids/self-description)
    y lista los Datasets CSV registrados de forma dinamica, sin hardcoding.
    """
    phase(
        1,
        "Catálogo IDS del Coordinador (Datasets Publicados)",
        "Antes de buscar nodos externos, el coordinador inspecciona su propio Catálogo\n"
        "Federado (IDS Self-Description) para verificar que dispone de Datasets publicados.\n"
        "Solo un nodo que tenga datos registrados puede actuar como orquestador legítimo."
    )
    step("Inspección del Catálogo local (GET /ids/self-description)")

    ecc_port = 8090 if int(cid) == 1 else 8090 + int(cid)
    # Mostramos rutas para debugging pero de forma mas limpia
    print(f"      {GRAY}[Ruta DAPS/ECC] https://localhost:{ecc_port}/api/selfDescription/{RESET}")
    print(f"      {GRAY}[Ruta DataApp]  https://localhost:5002/ids/self-description/{RESET}")

    try:
        sd  = http_get(f"{coordinator_url}/ids/self-description", timeout=req_timeout)
        cat = (sd.get("ids:resourceCatalog") or [{}])[0]
        resources = cat.get("ids:offeredResource", [])
        datasets = []
        for res in resources:
            t_node = res.get("ids:title", [{}])[0]
            title  = t_node.get("@value", "") if isinstance(t_node, dict) else str(t_node)
            if "Dataset:" in title:
                datasets.append(title.replace("Dataset: ", "").strip())
        if datasets:
            print("\n")
            print(f"      {GREEN}Catálogo IDS auto-descubierto localmente.{RESET}")
            print(f"      {GRAY}↳ Se encontraron {len(datasets)} Dataset(s) soberanos en el nodo coordinador:{RESET}")
            for d in datasets:
                print(f"         {CYAN}[CSV]{RESET} {BOLD}{d}{RESET}")
        else:
            warn("No se detectaron Datasets CSV en el catalogo IDS.")
    except Exception as exc:
        warn(f"No se pudo parsear el catalogo IDS: {exc}")


def main():
    global CLIENT_WS_ENABLED
    args = parse_args()
    cid  = args.coordinator
    if args.no_client_ws:
        CLIENT_WS_ENABLED = False

    try:
        cid_int = int(cid)
    except ValueError:
        print(f"{RED}Coordinator ID invalido: {cid!r}. Debe ser un numero entero (p.ej. 2).{RESET}")
        sys.exit(1)

    # Puerto del coordinator: argumento explicito o convencion 5000+N
    coordinator_port = args.coordinator_port if args.coordinator_port else 5000 + cid_int
    coordinator_url  = f"https://localhost:{coordinator_port}"
    req_timeout      = args.timeout

    banner(
        "PFG -- Demostracion Federated Learning sobre IDS",
        f"Worker-{cid} como coordinator  .  Broker Fuseki + DAPS omejdn  .  multi-CSV discovery"
    )
    print()
    field("Coordinator",     f"Worker-{cid}  ({coordinator_url})")
    field("coordinator_port", coordinator_port)
    field("Arrancar FL",     "No (--skip-fl)" if args.skip_fl else "Si")
    field("Timeout HTTP",    f"{req_timeout}s")
    field(
        "Cliente -> DataApp",
        "WebSocket /ws/client -> POST /proxy" if CLIENT_WS_ENABLED and _WS_AVAILABLE else "REST POST /proxy",
    )

    # Referencias mutables para que el listener las actualice en caliente
    _coord_ref     = [coordinator_url]
    _endpoints_ref = [None]

    # Arrancar el hilo de escucha del teclado (daemon => muere con el proceso)
    info("Pulsa [P] en cualquier momento para cancelar y resetear todos los Workers.")
    _listener = threading.Thread(
        target=_start_keyboard_listener,
        args=(_coord_ref, _endpoints_ref, req_timeout),
        daemon=True,
    )
    _listener.start()

    try:
        # Fases
        endpoints = fase0_resolver_endpoints(coordinator_url, cid, req_timeout)
        _endpoints_ref[0] = endpoints
        time.sleep(0.5)

        fase1_verificar_catalogo_coordinator(coordinator_url, cid, req_timeout)
        time.sleep(0.5)

        helper_solicitar_algoritmo(coordinator_url, cid, endpoints, req_timeout)
        time.sleep(1)

        fase2_descubrir_peers(coordinator_url, cid, endpoints, req_timeout)
        nego = fase3_negociar(coordinator_url, cid, endpoints, req_timeout)
        verificar_coordinator(coordinator_url, cid, endpoints, req_timeout)

        if not args.skip_fl:
            if not nego.get("accepted"):
                warn("No hay workers aceptados -- no se arranca el FL")
            else:
                fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout)
                fase5_monitorizar_fl(coordinator_url, cid, nego, endpoints, req_timeout)
                _mostrar_resultados_fl(coordinator_url, cid, req_timeout)
                fase6_test_acceso_modelo(coordinator_url, cid, nego, endpoints, req_timeout)

    except KeyboardInterrupt:
        print()
        print(f"  {RED}{BOLD}[CTRL+C] Ejecucion interrumpida. Limpiando Workers...{RESET}")
        _cleanup_workers(coordinator_url, _endpoints_ref[0], req_timeout)
        _close_ws_rpc_clients()
        print(f"  {GREEN}Sistema restaurado.{RESET}")
        sys.exit(0)

    # Resumen final
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{GREEN}  Demostracion completada{RESET}")
    _sep("=", color=BOLD + CYAN)
    print()

    for w in nego.get("accepted", []):
        uri  = w.get("connector_uri", "?")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        ecc  = peer.get("ecc_url", "(desconocido)")
        print(f"  {GREEN}PARTICIPA   Worker-{wid}   {GRAY}{ecc}{RESET}")

    for w in nego.get("rejected", []):
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        peer   = endpoints["peers"].get(f"worker{wid}", {})
        ecc    = peer.get("ecc_url", "(desconocido)")
        print(f"  {RED}RECHAZADO   Worker-{wid}   {GRAY}{ecc}  --  {reason}{RESET}")

    print()

    # --- METRICAS RENDIMIENTO ---
    if not args.skip_fl:
        try:
            import json
            perf = http_get(f"{coordinator_url}/metrics", timeout=req_timeout)

            print(f"  {CYAN}[RENDIMIENTO] DE TRANSFERENCIAS (WS directo - IDS por ECC){RESET}")
            print(f"  {CYAN}----------------------------------------------------------------------{RESET}")

            ws_sends  = perf.get("ws_sends", 0)
            ws_ms     = perf.get("ws_total_ms", 0.0)
            ws_bytes  = perf.get("ws_bytes", 0)

            ids_ecc_sends = perf.get("ids_ecc_sends", 0)
            ids_ecc_ms    = perf.get("ids_ecc_total_ms", 0.0)
            ids_ecc_bytes = perf.get("ids_ecc_bytes", 0)

            http_sends = perf.get("http_sends", 0)
            http_ms    = perf.get("http_total_ms", 0.0)
            http_bytes = perf.get("http_bytes", 0)

            ids_ecc_fails = perf.get("ids_ecc_failures", 0)
            http_fails = perf.get("http_failures", 0)

            print()
            print(f"  {BOLD}IDS vía ECC↔ECC (tramo externo WSS si está activo){RESET}")
            print(f"    Envíos exitosos : {ids_ecc_sends}   (Fallos: {ids_ecc_fails})")
            if ids_ecc_sends > 0:
                print(f"    Latencia Media  : {ids_ecc_ms / ids_ecc_sends:.1f} ms")
                print(f"    Volumen total   : {ids_ecc_bytes / 1024:.1f} KB")

            print()
            print(f"  {BOLD}HTTP fallback real{RESET}")
            print(f"    Envíos exitosos : {http_sends}   (Fallos: {http_fails})")
            if http_sends > 0:
                print(f"    Latencia Media  : {http_ms / http_sends:.1f} ms")
                print(f"    Volumen total   : {http_bytes / 1024:.1f} KB")

            print()
            if ids_ecc_sends > 0 and http_sends == 0 and ws_sends == 0:
                print(f"  {GREEN}► CONCLUSIÓN: El entrenamiento FL fue realizado 100% sobre IDS usando ECC↔ECC.{RESET}")
            elif ids_ecc_sends > 0 and http_sends > 0:
                print(f"  {YELLOW}► CONCLUSIÓN: El flujo principal usó IDS vía ECC, con algo de HTTP fallback real.{RESET}")
            print()
        except Exception as e:
            warn(f"No se pudieron cargar las métricas de rendimiento: {e}")

    # --- CLEARING HOUSE AUDIT ---
    try:
        import requests
        print(f"  {CYAN}[AUDITORÍA] CLEARING HOUSE (Notario IDS){RESET}")
        print(f"  {CYAN}----------------------------------------------------------------------{RESET}")

        try:
            r_integ = requests.get("http://localhost:8100/api/transactions/audit/integrity", timeout=req_timeout)
            if r_integ.ok:
                data = r_integ.json()
                status = data.get("status", "?")
                c = GREEN if status == "INTEGRITY_OK" else \
                   (YELLOW if status == "CORRUPTED" else RED)
                print(f"    {BOLD}Estado Cadena Hash (Integridad){RESET}: {c}{status}{RESET}")
        except:
            pass

        try:
            r_stats = requests.get("http://localhost:8100/api/stats/system", timeout=req_timeout)
            if r_stats.ok:
                s_data = r_stats.json().get("data", {}) if "data" in r_stats.json() else r_stats.json()
                total = s_data.get("total_transactions", "?")
                print(f"    {BOLD}Muestreo Auditado (Nº Logs){RESET}    : {total} transacciones IDS")
        except:
            pass

        print()
        print(f"  ► Explora el historial completo del notario digital en:")
        print(f"      {MAGENTA}http://localhost:8100/api/transactions?page_size=1000&sort_order=asc{RESET}")
        print(f"  ► Explora las métricas de uso aquí:")
        print(f"      {MAGENTA}http://localhost:8100/api/stats/system{RESET}")
        print(f"  ► Exportar base de datos a archivo:")
        print(f"      {MAGENTA}http://localhost:8100/api/export/json{RESET}")
        print()
    except Exception as e:
        warn(f"No se pudo consultar el Clearing House: {e}")

    # =============================================================================
    # DESCARGA AUTOMATIZADA DEL REGISTRO IDS (CLEARING HOUSE EXPORT)
    # =============================================================================
    try:
        import os, datetime
        exports_dir = os.path.join(os.getcwd(), "ClearingHouse", "exports")
        os.makedirs(exports_dir, exist_ok=True)

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        export_filename = f"fl_ids_audit_report_{timestamp_str}.json"
        export_path = os.path.join(exports_dir, export_filename)

        print(f"  {CYAN}[REPORTE] DESCARGANDO REPORTE DE AUDITORÍA (Notario IDS)...{RESET}")

        r_export = requests.get("http://localhost:8100/api/export/json", timeout=10)
        if r_export.ok:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(r_export.text)
            print(f"    {GREEN}OK  Reporte oficial guardado en: {export_path}{RESET}")
        else:
            print(f"    {YELLOW}WARN No se pudo descargar el reporte (HTTP {r_export.status_code}){RESET}")
    except Exception as e:
        print(f"    {YELLOW}WARN Error al automatizar la descarga del Clearing House: {e}{RESET}")
    print()

    info(f"GET {coordinator_url}/fl/status")
    info(f"GET {coordinator_url}/fl/results")
    info(f"GET {coordinator_url}/fl/model")
    info(f"GET {coordinator_url}/ids/self-description")
    info(f"GET {coordinator_url}/ids/contract?contractOffer=<fl_model_contract_id>")
    _close_ws_rpc_clients()
    print()


if __name__ == "__main__":
    main()
