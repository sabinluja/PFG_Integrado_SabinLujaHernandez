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
import textwrap
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

LOG_WIDTH = 78


def _sep(char="=", width=LOG_WIDTH, color=CYAN):
    print(f"{color}{char * width}{RESET}")


def _wrap_log_text(text, indent=4, width=LOG_WIDTH, color=GRAY):
    pad = " " * indent
    body_width = max(30, width - indent)
    normalized = textwrap.dedent(str(text)).strip()
    paragraphs = re.split(r"\n\s*\n", normalized)
    for p_idx, paragraph in enumerate(paragraphs):
        line = " ".join(part.strip() for part in paragraph.splitlines() if part.strip())
        if p_idx:
            print()
        for wrapped in textwrap.wrap(line, width=body_width, break_on_hyphens=False):
            print(f"{pad}{color}{wrapped}{RESET}")


def banner(title, subtitle=""):
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    if subtitle:
        print(f"{GRAY}  {subtitle}{RESET}")
    _sep("=", color=BOLD + CYAN)


def phase(num, title, description=""):
    print()
    _sep("=", color=BLUE)
    print(f"{BOLD}{BLUE}  PHASE {str(num).zfill(2)}{RESET}  {BOLD}{WHITE}{title}{RESET}")
    if description:
        _sep("-", color=GRAY)
        _wrap_log_text(description, indent=2, color=GRAY)
    _sep("=", color=BLUE)


def step(label):
    print(f"\n  {BOLD}{WHITE}STEP  {label}{RESET}")


def substep(msg):
    print(f"    {GRAY}[CALL] {msg}{RESET}")


def ok(msg):
    print(f"    {GREEN}[OK]   {msg}{RESET}")


def fail(msg):
    print(f"    {RED}[ERR]  {msg}{RESET}")
    sys.exit(1)


def warn(msg):
    print(f"    {YELLOW}[WARN] {msg}{RESET}")


def info(msg):
    print(f"    {GRAY}[INFO] {msg}{RESET}")


def field(label, value, indent=4):
    pad = " " * indent
    val = str(value)
    if len(val) > 110:
        val = val[:107] + "..."
    print(f"{pad}{MAGENTA}{label:<28}{RESET} {val}")


def _log_rule(indent=4, char="-", width=64, color=GRAY):
    print(f"{' ' * indent}{color}{char * width}{RESET}")


def _log_event(tag, title, detail="", status="", tag_color=WHITE,
               status_color=GREEN, indent=4):
    pad = " " * indent
    tag_txt = f"[{tag}]"
    title_txt = str(title)
    if len(title_txt) > 44:
        title_txt = title_txt[:41] + "..."
    status_txt = f" {status_color}{status:>9}{RESET}" if status else ""
    print(f"{pad}{tag_color}{tag_txt:<10}{RESET}"
          f"{BOLD}{WHITE}{title_txt:<44}{RESET}{status_txt}")
    if detail:
        for line in str(detail).splitlines():
            print(f"{pad}  {GRAY}{line}{RESET}")


def _log_kv(label, value, indent=6, label_width=28):
    pad = " " * indent
    val = str(value)
    if len(val) > 92:
        val = val[:89] + "..."
    print(f"{pad}{GRAY}{label:<{label_width}}{RESET}{WHITE}{val}{RESET}")


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
PRESENTATION_VERBOSE = os.getenv("PFG_PRESENTATION_VERBOSE", "false").lower() in ("1", "true", "yes")
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
        if PRESENTATION_VERBOSE:
            info(
                "[client->DataApp WS] connection open "
                f"transport=WSS url={ws_url} "
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
                        f"WS {method} {path} returned "
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


def _proxy_spec_for_ws_request(method, path):
    """
    Traduce la URL logica a una peticion IDS/proxy semantica.
    messageType conserva el tipo IDS real; la operacion local viaja aparte
    como proxyAction/payload.operation para que no se codifiquen endpoints
    dentro de messageType.
    """
    method = (method or "GET").upper()
    clean_path = (path or "/").split("?", 1)[0]
    mapping = {
        ("GET", "/health"): ("QueryMessage", "health"),
        ("GET", "/status"): ("QueryMessage", "status"),
        ("GET", "/metrics"): ("QueryMessage", "metrics"),
        ("GET", "/transport/status"): ("QueryMessage", "transport_status"),
        ("GET", "/ids/self-description"): ("DescriptionRequestMessage", "ids_self_description"),
        ("GET", "/ids/contract"): ("ContractRequestMessage", "ids_contract"),
        ("GET", "/broker/connectors"): ("QueryMessage", "broker_connectors"),
        ("POST", "/broker/discover"): ("DescriptionRequestMessage", "broker_discover"),
        ("POST", "/broker/discover/worker"): ("DescriptionRequestMessage", "broker_discover_worker"),
        ("GET", "/dataset/info"): ("DescriptionRequestMessage", "dataset_info"),
        ("GET", "/dataset/all-columns"): ("DescriptionRequestMessage", "dataset_all_columns"),
        ("GET", "/dataset/llm-recommend"): ("DescriptionRequestMessage", "dataset_llm_recommend"),
        ("POST", "/catalog/publish-datasets"): ("ResourceUpdateMessage", "catalog_publish_datasets"),
        ("POST", "/fl/fetch-algorithm"): ("ArtifactRequestMessage", "fl_fetch_algorithm"),
        ("POST", "/fl/start"): ("ArtifactRequestMessage", "fl_start"),
        ("GET", "/fl/status"): ("QueryMessage", "fl_status"),
        ("GET", "/fl/docker-image-status"): ("QueryMessage", "fl_docker_image_status"),
        ("GET", "/fl/results"): ("QueryMessage", "fl_results"),
        ("GET", "/fl/model"): ("ArtifactRequestMessage", "fl_model"),
        ("POST", "/fl/negotiate"): ("ContractRequestMessage", "fl_negotiate"),
        ("POST", "/fl/accept-negotiation"): ("ContractAgreementMessage", "fl_accept_negotiation"),
        ("POST", "/fl/receive-algorithm"): ("ArtifactRequestMessage", "fl_receive_algorithm"),
        ("POST", "/fl/receive-global-weights"): ("ArtifactRequestMessage", "fl_receive_global_weights"),
        ("POST", "/fl/receive-local-weights"): ("ArtifactRequestMessage", "fl_receive_local_weights"),
        ("POST", "/system/reset"): ("NotificationMessage", "system_reset"),
        ("POST", "/system/reset-all"): ("NotificationMessage", "system_reset_all"),
    }
    spec = mapping.get((method, clean_path))
    if not spec:
        return None
    message_type, operation = spec
    return {"messageType": message_type, "operation": operation}


def _proxy_message_for_ws_request(method, path):
    spec = _proxy_spec_for_ws_request(method, path)
    return spec.get("operation") if spec else None


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
    proxy_spec = _proxy_spec_for_ws_request(method, path)
    if not proxy_spec:
        return None
    proxy_action = proxy_spec["operation"]
    message_type = proxy_spec["messageType"]
    forward_to = os.getenv("PFG_PROXY_FORWARD_TO") or _proxy_wss_forward_for_base_url(base_url)
    forward_to_internal = os.getenv("PFG_PROXY_FORWARD_TO_INTERNAL") or forward_to
    requested_artifact, transfer_contract = _proxy_control_ids_refs(proxy_action)
    proxy_body = {
        "multipart": "wss",
        "Forward-To": forward_to,
        "Forward-To-Internal": forward_to_internal,
        "messageType": message_type,
        "proxyAction": proxy_action,
        "payload": {
            "type": "local_proxy_request",
            "operation": proxy_action,
            "body": body if body is not None else {},
            "logicalMethod": method,
            "logicalPath": path,
        },
        "timeout": timeout,
    }
    if message_type == "ArtifactRequestMessage":
        proxy_body["requestedArtifact"] = requested_artifact
        proxy_body["transferContract"] = transfer_contract
    elif message_type == "ContractRequestMessage":
        proxy_body["requestedElement"] = requested_artifact
    elif message_type == "ContractAgreementMessage":
        proxy_body["requestedArtifact"] = requested_artifact
        proxy_body["transferContract"] = transfer_contract
    return proxy_body


def _unwrap_proxy_body(parsed):
    if not isinstance(parsed, dict):
        return parsed
    if parsed.get("transport") not in ("proxy-artifact-dispatcher", "proxy-message-dispatcher"):
        return parsed
    if not parsed.get("ok"):
        raise RuntimeError(
            f"/proxy {parsed.get('action') or parsed.get('message') or parsed.get('messageType')} returned "
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
            f"/proxy {body.get('action') or body.get('message') or body.get('messageType')} returned "
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
            proxy_action = proxy_body.get("proxyAction") or payload.get("operation") or payload.get("action")
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


def _call_description(method, url):
    _, path = _url_parts_for_ws(url)
    path = (path or "").split("?", 1)[0]
    labels = {
        ("GET", "/health"): "Check DataApp health",
        ("GET", "/status"): "Inspect coordinator status",
        ("GET", "/metrics"): "Collect transport performance metrics",
        ("GET", "/transport/status"): "Verify active transport channel",
        ("GET", "/ids/self-description"): "Inspect the IDS self-description catalog",
        ("GET", "/ids/contract"): "Inspect IDS contract metadata",
        ("GET", "/broker/connectors"): "Read connector topology from the Metadata Broker",
        ("POST", "/broker/discover"): "Evaluate peer dataset catalogs",
        ("POST", "/broker/discover/worker"): "Evaluate peer dataset catalog",
        ("POST", "/fl/fetch-algorithm"): "Prepare the federated learning algorithm artifact",
        ("POST", "/fl/negotiate"): "Negotiate IDS contracts with compatible peers",
        ("POST", "/fl/start"): "Start federated learning execution",
        ("GET", "/fl/status"): "Read federated learning status",
        ("GET", "/fl/results"): "Collect final training results",
        ("GET", "/fl/model"): "Fetch final global model artifact",
        ("POST", "/proxy"): "Send an IDS control request through the DataApp proxy",
    }
    return labels.get((method, path), f"{method} request through the DataApp")


def http_get(url, timeout=240, quiet=False):
    if not quiet:
        substep(_call_description("GET", url))
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("GET", url, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" proxyAction={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                if PRESENTATION_VERBOSE and not quiet:
                    info(
                        "[client->DataApp WS] OK "
                        f"transport=WSS method=GET logical_url={url} "
                        f"dispatched_by=/ws/client{proxy_hop}{proxy_msg} "
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
        if ws_exc and PRESENTATION_VERBOSE and not quiet:
            info(f"[client->DataApp WS] unavailable; REST /proxy fallback OK ({ws_exc})")
        return result
    except requests.exceptions.ConnectionError:
        fail(f"Connection refused at {url} -- is the container running?")
    except requests.exceptions.ReadTimeout:
        fail(f"Timeout ({timeout}s) waiting for {url}")
    except requests.exceptions.HTTPError as exc:
        fail(f"HTTP {exc.response.status_code} at {url}")


def http_post(url, body, timeout=240, quiet=False):
    if not quiet:
        substep(_call_description("POST", url))
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("POST", url, body=body, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" proxyAction={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                if PRESENTATION_VERBOSE and not quiet:
                    info(
                        "[client->DataApp WS] OK "
                        f"transport=WSS method=POST logical_url={url} "
                        f"dispatched_by=/ws/client{proxy_hop}{proxy_msg} "
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
        if ws_exc and PRESENTATION_VERBOSE and not quiet:
            info(f"[client->DataApp WS] unavailable; REST /proxy fallback OK ({ws_exc})")
        return result
    except requests.exceptions.ConnectionError:
        fail(f"Connection refused at {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) waiting for {url}\n"
            f"      The ECC TRUE Connector can take longer on the first request (DAPS token).\n"
            f"      Use --timeout N to increase the limit."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} at {url}\n      {body_txt}")


def http_post_raw(url, body, timeout=240):
    substep(_call_description("POST", url))
    ws_exc = None
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        try:
            ws_resp = _ws_rpc("POST", url, body=body, timeout=timeout)
            if ws_resp is not None:
                proxy_hop = " -> /proxy" if ws_resp.get("proxy_action") else ""
                proxy_msg = f" proxyAction={ws_resp.get('proxy_action')}" if ws_resp.get("proxy_action") else ""
                if PRESENTATION_VERBOSE:
                    info(
                        "[client->DataApp WS] OK "
                        f"transport=WSS method=POST logical_url={url} "
                        f"dispatched_by=/ws/client{proxy_hop}{proxy_msg} "
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
                if ws_exc and PRESENTATION_VERBOSE:
                    info(f"[client->DataApp WS] unavailable; REST /proxy fallback OK ({ws_exc})")
                return result
            except Exception:
                pass
        if ws_exc and PRESENTATION_VERBOSE:
            info(f"[client->DataApp WS] unavailable; REST /proxy fallback OK ({ws_exc})")
        return r.text
    except requests.exceptions.ConnectionError:
        fail(f"Connection refused at {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) waiting for {url}\n"
            f"      The ECC TRUE Connector can take longer on the first request (DAPS token).\n"
            f"      Use --timeout N to increase the limit."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} at {url}\n      {body_txt}")


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
        "Network readiness and connector topology",
        "In this phase, the script verifies that the selected worker is reachable and ready to "
        "act as the coordinator. It then queries the Metadata Broker, discovers the IDS "
        "connectors currently registered in the federation, and builds the live topology used "
        "by the rest of the demonstration."
    )

    step(f"Check Worker-{cid} readiness")
    status = http_get(f"{coordinator_url}/status", timeout=req_timeout)
    ok(f"Worker-{cid} is reachable and ready")
    field("instance",        status.get("instance", "?"))
    field("current role",    status.get("role",     "worker"))
    print()
    print(f"    {BOLD}{GREEN}** Worker-{cid} is now the FL coordinator **{RESET}")

    step("Discover registered IDS connectors")
    bd    = http_get(f"{coordinator_url}/broker/connectors", timeout=req_timeout)
    raw_p = bd.get("connectors", [])
    count = bd.get("count", len(raw_p))

    ok(f"{count} connectors found in the Metadata Broker")
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
        field("  broker endpoint",   ep_raw, indent=8)
        field("  internal ECC URL",  ecc_url, indent=8)
        print()

        if not is_coord:
            peers[f"worker{wid}"] = entry
            all_peers.append(entry)

    if not all_entries:
        fail(
            "The broker did not return any connector.\n"
            "      Check that broker-core, broker-fuseki and broker-reverseproxy are running,\n"
            "      and that the workers have registered themselves."
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
            "The broker did not return any peer besides the coordinator.\n"
            "      Check that the other workers are running and registered."
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
        "Federated learning artifact preparation",
        "In this phase, the coordinator prepares the federated learning artifact that every "
        "accepted worker will execute. It packages the training code, the FL configuration "
        "and the Python dependencies into a versioned Docker image, publishes it in the "
        "private registry, and leaves it ready for IDS-controlled distribution after contract "
        "negotiation."
    )
    step("Build and register training artifact")

    try:
        data = http_post(f"{coordinator_url}/fl/fetch-algorithm", {}, timeout=req_timeout)

        mode  = data.get("delivery_mode", "ids_base64")
        image = data.get("docker_image")

        if mode == "docker_image":
            section("Artifact build result")
            _log_event(
                "IMAGE",
                "Docker training artifact registered",
                "The coordinator published a reproducible FL runtime in the private registry.",
                "PUSHED",
                tag_color=GREEN,
                indent=6,
            )
            print()
            _log_kv("Immutable image", image or "(not reported)", indent=8)
            _log_kv("Bundled files", "algorithm.py, fl_config.json, Python dependencies", indent=8)
            _log_kv("Distribution policy", "Only IDS-authorized workers after contract agreement", indent=8)
        else:
            section("Artifact build result")
            _log_event(
                "BASE64",
                "Legacy in-memory algorithm loaded",
                "The coordinator did not report a Docker image for this execution.",
                "READY",
                tag_color=YELLOW,
                status_color=YELLOW,
                indent=6,
            )
    except Exception as exc:
        fail(f"The coordinator could not prepare the algorithm artifact: {exc}")
        
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
    ecc      = peer.get("ecc_url") or w.get("ecc_url", "(unknown)")
    pl       = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
    compatible = w.get("compatible", match >= 0.80)

    color = GREEN if compatible else YELLOW
    tag   = "OK " if compatible else "--- (filtered out)"
    print(f"    {color}{tag}{RESET}  Worker-{wid}  {GRAY}{uri}{RESET}")
    print()

    # Handshake de metadatos (IDS Catalog fetch)
    ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
    ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)

    print(f"\n        {GRAY}Dynamic discovery -- reading the peer IDS catalog:{RESET}")
    for ev in w.get("all_evaluated", []):
        fname_ev = ev["filename"]
        ratio_ev = ev["ratio"]
        common_c = ev.get("common_cols_count", 0)
        total_c  = ev.get("total_cols", 0)
        print(f"          - Catalog resource: {fname_ev:<30}")

    llm_rec = w.get("llm_recommended")

    if llm_rec:
        llm_conf = w.get("llm_confidence", 0)
        llm_mod  = w.get("llm_model", "Ollama")
        llm_rsn  = w.get("llm_reasoning", "Decision based on semantic schema compatibility.")

        print(f"\n        {MAGENTA}-> Local AI ({llm_mod}) -- reasoning:{RESET}")
        print(f"          {GRAY}", end="", flush=True)
        for _ch in llm_rsn:
            print(_ch, end="", flush=True)
            _time.sleep(0.008)
        print(f"{RESET}\n")

        field(f"  AI ({llm_mod}) suggestion", f"{CYAN}{llm_rec} (confidence: {llm_conf:.0%}){RESET}", indent=8)

        if llm_conf >= 0.80:
            field("  Selected CSV", f"{GREEN}{sel_csv}{RESET}", indent=8)
        else:
            print(f"        {YELLOW}AI confidence below 80%. Falling back to column-based matching.{RESET}")
            field("  Column-based CSV", math_csv, indent=8)
            field("  Selected CSV", f"{GREEN}{sel_csv}{RESET}", indent=8)
    else:
        print(f"\n        {YELLOW}LLM fallback:{RESET} AI validation timed out or returned an invalid format.")
        print(f"        {YELLOW}Using the deterministic column-matching strategy instead.{RESET}")
        field("  Column-based CSV", math_csv, indent=8)
        field("  Selected CSV", f"{GREEN}{sel_csv}{RESET}", indent=8)

    if compatible:
        info(f"The coordinator will use {sel_csv!r} on worker-{wid} for FL training")
    print()


def fase2_descubrir_peers(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]
    # ECC URL del coordinator para excluirlo del bucle de forma fiable
    coord_ecc_url = endpoints["coordinator"]["ecc_url"]

    phase(
        3,
        "Peer discovery and dataset compatibility analysis",
        "In this phase, the coordinator discovers the available peers and reads each peer's IDS "
        "catalog. For every candidate dataset, it compares the schema with the coordinator's "
        "reference data and uses the local LLM recommendation as additional support before "
        "selecting the most suitable training resource."
    )

    step("Evaluate candidate peer datasets")

    bd       = http_get(f"{coordinator_url}/broker/connectors", timeout=req_timeout, quiet=True)
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
            substep("Evaluate peer dataset catalog")
            w = http_post(
                f"{coordinator_url}/broker/discover/worker",
                {"ecc_url": ecc_url, "connector_uri": uri},
                timeout=req_timeout,
                quiet=True,
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
    ok(f"{total} compatible workers out of {len(compatible) + len(incompatible)} analyzed")
    field("Coordinator columns", my_cols_count)

    if not compatible:
        warn(
            "No worker reached the 80% schema compatibility threshold.\n"
            "      Check that the workers expose at least one CSV with the same columns as the coordinator."
        )

    return compatible


# =============================================================================
# FASE 3 -- Negociacion IDS coordinator -> cada peer
# =============================================================================

def fase3_negociar(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]

    phase(
        4,
        "IDS contract negotiation",
        "In this phase, dataset compatibility is converted into an explicit IDS permission. The "
        "coordinator requests a contract from each compatible peer, records the Contract "
        "Agreement for accepted workers, and leaves rejected peers outside the federated "
        "training execution."
    )

    step("Negotiate participation contracts")
    substep("Negotiate IDS contracts with compatible peers")
    data     = http_post(f"{coordinator_url}/fl/negotiate", {}, timeout=req_timeout, quiet=True)
    accepted = data.get("accepted", [])
    rejected = data.get("rejected", [])

    print(f"\n  {BOLD}IDS negotiation detail:{RESET}\n")

    for w in accepted:
        uri  = w.get("connector_uri", "?")
        tc   = w.get("transfer_contract", "")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        pl   = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
        pe   = peer.get("ecc_url")   or f"https://ecc-worker{wid}:8889/data"

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        ids_arrow("out", "ids:DescriptionRequestMessage",        coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage",       pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",           coord_label, pl)
        ids_arrow("in",  "ids:ContractAgreementMessage",         pl, coord_label)
        print(f"    {GREEN}ACCEPTED -- IDS contract established{RESET}")
        print()
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
            "fl_opt_out"             : "(data sovereignty) -- IDS RejectionMessage",
            "fl_participation_denied": "FL_AUTHORIZED_URIS is empty (not authorized to participate)",
            "unauthorized_consumer"  : "consumer URI is not authorized",
            "error"                  : "communication error",
        }
        reason_explanations = {
            "fl_opt_out"             : f"Worker-{wid} has decided not to participate in the FL training.",
            "fl_participation_denied": f"Worker-{wid} is not authorized to participate in this federation.",
            "unauthorized_consumer"  : f"Worker-{wid} is not allowed by the connector policy.",
        }
        reason_text = reason_labels.get(actual_reason, actual_reason)
        reason_explanation = reason_explanations.get(actual_reason)
        print()

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",     coord_label, pl)
        ids_arrow("in",  "ids:RejectionMessage",           pl, coord_label)
        print(f"    {RED}REJECTED -- {reason_text}{RESET}")
        if reason_explanation:
            print(f"      {GRAY}{reason_explanation}{RESET}")
        if actual_reason != reason:
            field("reason (API)", f"{actual_reason}  (detected in IDS message)")
        print()

    # -- Resumen ---------------------------------------------------------------
    _sep("-", color=BLUE)
    print(f"  {BOLD}FL participation summary:{RESET}\n")

    for w in accepted:
        uri = w.get("connector_uri", "?")
        m   = re.search(r"worker(\d+)", uri)
        wid = m.group(1) if m else "?"
        print(f"    {GREEN}PARTICIPATES   Worker-{wid}   {GRAY}{uri}{RESET}")

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
            "fl_opt_out": "(IDS sovereignty)",
            "unauthorized_consumer": "unauthorized (IDS)",
        }.get(reason, reason)
        print(f"    {RED}REJECTED      Worker-{wid}   {GRAY}{uri}  --  {reason_label}{RESET}")

    print()

    return {"accepted": accepted, "rejected": rejected}


# =============================================================================
# Verificacion del coordinator
# =============================================================================

def verificar_coordinator(coordinator_url, cid, endpoints, req_timeout):
    print()
    _sep("-", color=BLUE)
    print(f"{BOLD}{BLUE}  Coordinator state after negotiation{RESET}")
    _sep("-", color=BLUE)

    step("Verify coordinator state")
    data = http_get(f"{coordinator_url}/status", timeout=req_timeout)

    role      = data.get("role", "?")
    algo_ok   = data.get("algorithm_loaded", False)
    config_ok = data.get("config_loaded", False)
    fl_status = data.get("fl_status", "?")
    peers     = data.get("peer_eccs", [])
    fl_cfg    = data.get("fl_config") or {}

    field("instance",         data.get("instance", "?"))
    field("role",             role)
    field("algorithm_loaded", "YES" if algo_ok  else "NO")
    field("config_loaded",    "YES" if config_ok else "NO")
    field("fl_status",        "ready")

    if fl_cfg:
        section("FL Config")
        for k, v in fl_cfg.items():
            field(f"  {k}", v, indent=6)

    if peers:
        section("Active peer ECCs (accepted workers)")
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
        ok("Coordinator is ready to start federated training")
    else:
        warn(f"Unexpected coordinator state: role={role}  algorithm={algo_ok}  config={config_ok}")


# =============================================================================
# FASE 4 -- Arranque del entrenamiento FL
# =============================================================================

def fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout):
    phase(
        5,
        "Federated training startup",
        "In this phase, the coordinator starts the controlled federated learning execution. It "
        "confirms the shared feature selection, activates only the workers that accepted the IDS "
        "contract, and then monitors each round as artifacts, model weights and aggregated "
        "metrics move through the federation."
    )

    step("Start the federated learning run")
    data   = http_post(f"{coordinator_url}/fl/start", {}, timeout=req_timeout)
    status = data.get("status", "?")
    peers  = data.get("peers", [])
    cfg    = data.get("fl_config", {}) or {}
    fs     = data.get("feature_selection", {}) or {}

    if status == "started":
        ok("Federated training process accepted by the coordinator")
    else:
        warn(f"Unexpected start response: status={status}")

    section("Execution summary")
    _log_kv("Coordinator", f"worker-{cid}")
    _log_kv("Rounds", cfg.get("rounds", "?"))
    _log_kv("Round timeout", f"{cfg.get('round_timeout', '?')}s")
    _log_kv("Minimum workers", cfg.get("min_workers", "?"))
    _log_kv("Accepted peers", len(peers))

    if fs.get("enabled"):
        source = fs.get("source") or "coordinator reference dataset"
        source = os.path.basename(str(source))
        count = fs.get("selected_count", "?")
        section("Shared feature selection")
        _log_kv("Reference dataset", source)
        strategy = fs.get("strategy", "unknown")
        method = "VarianceThreshold + SelectKBest(mutual_info_classif)"
        if strategy and strategy != "shared_runtime_coordinator":
            method = strategy
        _log_kv("Strategy", method)
        _log_kv("Shared numerical features", count)

    section("Participating workers")
    if peers:
        for p in peers:
            m   = re.search(r"worker(\d+)", p)
            wid = m.group(1) if m else "?"
            b   = endpoints["peers"].get(f"worker{wid}", {})
            b_ecc = b.get("ecc_url", "")
            status_note = "broker match" if b_ecc == p else (
                f"broker: {b_ecc}" if b_ecc else "registered")
            print(f"      {GREEN}[W{wid:<2}]{RESET} {WHITE}Worker-{wid:<3}{RESET}"
                  f"{GREEN}ACTIVE{RESET}  {GRAY}{p}  ({status_note}){RESET}")
    else:
        warn("No training peers were returned by /fl/start")


# =============================================================================
# FASE 5 -- Monitorizacion del entrenamiento en tiempo real
# =============================================================================

def _ids_log(direction, msg_type, src, dst):
    arrow = "->" if direction == "out" else "<-"
    tag = "->" if direction == "out" else "<-"
    color = CYAN if direction == "out" else GREEN
    short = msg_type.replace("ids:", "").replace("Message", "Msg")
    print(f"      {color}[IDS {tag}]{RESET}  {WHITE}{short:<40}{RESET}"
          f"{GRAY}{src} {arrow} {dst}{RESET}")


def _coord_ecc_label(cid):
    return f"ecc-worker{cid}:8889"


def _print_ronda_header(rnd_num, total_rounds, cid):
    total = total_rounds or "?"
    print()
    _log_rule(indent=4, char="-", width=64, color=CYAN)
    print(f"    {BOLD}{CYAN}ROUND {rnd_num}/{total:<5}{RESET}"
          f"{GRAY}coordinator-{cid:<8} IDS/ECC training cycle{RESET}")
    _log_rule(indent=4, char="-", width=64, color=CYAN)


def _print_handshake_algoritmo(rnd_num, wid, peer_lbl, cid):
    """
    Visual IDS contract negotiation trace and artifact delivery for a round.
    """
    coord_lbl = _coord_ecc_label(cid)
    print()
    _log_event(
        f"W{wid}",
        f"Worker-{wid} round contract and artifact delivery",
        f"Peer ECC: {peer_lbl}",
        "IDS",
        tag_color=WHITE,
        status_color=CYAN,
        indent=6,
    )
    _ids_log("out", "ids:DescriptionRequestMessage",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:DescriptionResponseMessage",
             peer_lbl, coord_lbl)
    _ids_log("out", "ids:ContractRequestMessage",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:ContractAgreementMessage",
             peer_lbl, coord_lbl)
    _ids_log("out", "ids:ContractAgreementMessage (confirmation)",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:MessageProcessedNotificationMessage",
             peer_lbl, coord_lbl)
    _ids_log("out", "ids:ArtifactRequestMessage",
             coord_lbl, peer_lbl)
    _ids_log("in",  "ids:ArtifactResponseMessage",
             peer_lbl, coord_lbl)
    _log_event(
        "ARTIFACT",
        " Docker image reference delivered",
        f"Round {rnd_num} Docker artifact received by {peer_lbl}.",
        "DONE",
        tag_color=GREEN,
        indent=6,
    )


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

    step("Monitor federated rounds")
    monitor_channel = "DataApp WebSocket control channel"
    if CLIENT_WS_ENABLED and _WS_AVAILABLE:
        ws_url = coordinator_url.replace("https://", "wss://").replace("http://", "ws://")
        if PRESENTATION_VERBOSE:
            print(f"      {GRAY}Control channel: WebSocket {ws_url}/ws/client{RESET}")
            print(f"      {GRAY}Internal RPC  : /proxy with QueryMessage + fl_status{RESET}")
    else:
        monitor_channel = "DataApp REST proxy"
        if PRESENTATION_VERBOSE:
            print(f"      {GRAY}Control channel: REST proxy at {coordinator_url}/proxy{RESET}")

    section("Monitoring context")
    _log_kv("Status channel", monitor_channel)
    _log_kv("Participating workers",
            ", ".join("worker-" + w for w in accepted_wids) or "(none)")
    try:
        td = http_get(f"{coordinator_url}/transport/status", timeout=10, quiet=True)
        ecc_wss_enabled = td.get("ecc_wss_enabled", False)
        ids_ecc_only = td.get("ids_ecc_only", False)
        weights_via_ecc = td.get("weights_via_ecc", False)
        transport = f"IDS ECC-to-ECC over {'WSS' if ecc_wss_enabled else 'HTTPS'}"
        if not (ids_ecc_only or weights_via_ecc):
            transport = "not reported as ECC-only"
        _log_kv("Weights transport", transport)
    except Exception as _te:
        warn(f"Could not read transport status: {_te}")

    _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids, req_timeout)

def _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids, req_timeout):
    """
    Monitorizacion por polling HTTP (GET /fl/status cada 5s).
    """
    poll_timeout = max(30, min(int(req_timeout or 240), 120))

    # Esperar a que el FL arranque
    for _ in range(30):
        try:
            fl = http_get(f"{coordinator_url}/fl/status", timeout=poll_timeout, quiet=True)
            if fl.get("status") not in ("idle", ""):
                print()
                ok("Federated learning is running"); break
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
            warn("Monitoring timeout reached (1h)"); break

        try:
            fl = http_get(f"{coordinator_url}/fl/status", timeout=poll_timeout, quiet=True)
        except Exception as e:
            warn(f"Could not read FL status: {e}"); time.sleep(poll_interval); continue

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
            pending_wids = [wid for wid in accepted_wids if wid not in already]
            if pending_wids:
                section("Weight collection")
            for wid in pending_wids:
                already.add(wid)
                n_exp = len(accepted_wids) + 1
                total_so_far = 1 + len(already)
                pe   = endpoints["peers"].get(f"worker{wid}", {})
                pl   = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                print()
                _log_event(
                    "WEIGHTS",
                    f"worker-{wid} weights received",
                    f"Weights payload: fl_weights::worker{wid}::round{rnd_num}\n"
                    f"Route: {pl} -> {_coord_ecc_label(cid)}",
                    "RECEIVED",
                    tag_color=GREEN,
                )
                _log_kv("Accumulated weights", f"{total_so_far}/{n_exp}", indent=6)
            weights_shown[rnd_num] = already

            section("Aggregation result")
            _log_event(
                "FEDAVG",
                f"Round {rnd_num} aggregation",
                f"{workers} workers contributed {samples:,} samples.",
                "DONE",
                tag_color=CYAN,
            )
            _log_kv("Elapsed", f"{elapsed}s")
            _log_kv("Accuracy", _fv("accuracy"))
            _log_kv("AUC", _fv("auc"))
            _log_kv("Loss", _fv("loss"))
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
                section("IDS contract negotiation and artifact delivery")
                for w in nego.get("accepted", []):
                    uri = w.get("connector_uri", "")
                    m   = re.search(r"worker(\d+)", uri)
                    wid = m.group(1) if m else "?"
                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                    _print_handshake_algoritmo(rnd_num, wid, pl, cid)

        if status == "completed" and seen_rounds >= (total_rounds or 0):
            ok(f"Federated learning completed -- {seen_rounds} rounds"); break
        elif status == "failed":
            warn("Federated learning finished with status=failed"); break

        time.sleep(poll_interval)

# =============================================================================
# FL training results.
# =============================================================================

def _mostrar_resultados_fl(coordinator_url, cid, req_timeout):
    """
    Show a complete summary after FL training finishes.
    """
    print()
    _sep("=", color=BOLD + GREEN)
    print(f"{BOLD}{GREEN}  FEDERATED TRAINING RESULTS{RESET}")
    _sep("=", color=BOLD + GREEN)

    # --- Obtener datos del coordinator ---
    fl_data = {}
    fl_results = []
    try:
        fl_data = http_get(f"{coordinator_url}/fl/status", timeout=req_timeout)
    except Exception as e:
        warn(f"Could not read FL status: {e}")

    try:
        fl_results = http_get(f"{coordinator_url}/fl/results", timeout=req_timeout)
    except Exception:
        pass

    history = fl_data.get("history", fl_results if isinstance(fl_results, list) else [])
    if not history:
        warn("No round history is available")
        return

    model_data = {}
    r_model = None
    try:
        model_data = http_get(f"{coordinator_url}/fl/model", timeout=req_timeout)
        r_model = True
    except Exception:
        r_model = None

    # Round evolution.
    step("Round-by-round evolution")
    header = f"  {'Round':>6}  {'Workers':>8}  {'Samples':>10}  {'Accuracy':>10}  {'AUC':>8}  {'F1-macro':>9}  {'MCC':>8}  {'Loss':>8}  {'Time':>8}"
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

    # Best global model.
    last = history[-1] if history else {}
    best_gm = model_data.get("metrics") or last.get("global_metrics", {})
    best_round = model_data.get("round") or fl_data.get("best_round") or last.get("round")

    step("Best global model metrics")
    if best_round:
        field("Best round", f"{BOLD}{best_round}{RESET}")
    field("Selection criterion", "F1-macro -> Focus F1 -> Accuracy")
    _log_rule(indent=4, char="-", width=50, color=GRAY)
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
        field("Mode", f"{mode} ({n_classes} classes)" if n_classes else mode)
    print()

    # Data distribution.
    step("Data distribution across workers")
    total_samples = sum(e.get("total_samples", 0) for e in history)
    if total_samples > 0 and history:
        last_entry = history[-1]
        n_workers = last_entry.get("workers_ok", "?")
        field("Participating workers", n_workers)
        field("Total samples (last round)", f"{last_entry.get('total_samples', 0):,}")
        field("Completed rounds", len(history))
    print()

    # Class distribution (UNSW-NB15).
    try:
        class_names = model_data.get("class_names", [])
        per_class = model_data.get("per_class_report", {})

        if class_names:
            step("Per-class performance (UNSW-NB15)")
            n_classes = len(class_names)
            field("Classification mode", f"Multiclass ({n_classes} classes)" if n_classes > 2 else "Binary")
            print()
            print(f"    {'Class':<20} {'F1-Score':>10}  {'Performance':>32}")
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
        "Final audit and data sovereignty",
        "In this phase, the final global model is treated as a protected IDS artifact. The script "
        "checks that workers which participated in the training can request the model, while "
        "non-participants are rejected by the connector policy, proving the data-sovereignty "
        "control at the end of the run."
    )

    try:
        fl_res = None
        info("Waiting for the global model resource to appear in the IDS catalog...")
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
            warn("The global model resource was not found in the IDS catalog after waiting")
            return

        cid_val = ((fl_res.get("ids:contractOffer") or [{}])[0]).get("@id", "")
        if not cid_val:
            warn("No ContractOffer was found for the model resource")
            return

    except Exception as e:
        warn(f"Could not prepare IDs for phase 6: {e}")
        return

    # Obtenemos las URLs directamente del broker sin hardcodear
    coord_ecc = endpoints["coordinator"].get("ecc_url")
    coord_uri = endpoints["coordinator"].get("connector_uri")

    if not coord_ecc or not coord_uri:
        warn("Could not extract the coordinator URL from the Broker for the access test.")
        return

    # -- Extraer TODOS los peers descubiertos (aceptados, rechazados Y descartados) --
    # De este modo worker-4 (schema incompatible -> descartado en discovery) tambien
    # se prueba y recibe un RejectionMessage real del coordinator porque su URI
    # no esta en la lista de autorizados del contrato FL.
    def _worker_id_from(*values):
        for value in values:
            m = re.search(r"worker(\d+)", str(value or ""))
            if m:
                return m.group(1)
        return None

    accepted_uris = set()
    workers_to_test = {}

    for w in nego.get("accepted", []):
        wid = _worker_id_from(
            w.get("connector_uri"),
            w.get("ecc_url"),
            w.get("endpoint"),
            w.get("endpoint_raw"),
        )
        if wid:
            accepted_uris.add(wid)
            workers_to_test.setdefault(wid, {}).update(w)

    for wid_key, peer in endpoints.get("peers", {}).items():   # worker1, worker2, ...
        wid = _worker_id_from(
            wid_key,
            peer.get("connector_uri"),
            peer.get("ecc_url"),
            peer.get("endpoint_raw"),
        )
        if wid:
            workers_to_test.setdefault(wid, {}).update(peer)

    # Anadir los rechazados aunque no esten en el snapshot inicial del broker.
    # Es importante para worker-4: su identidad puede venir como /connectors/<id>
    # en fase 0 y como URI IDS real en negociacion.
    for w in nego.get("rejected", []):
        wid = _worker_id_from(
            w.get("connector_uri"),
            w.get("ecc_url"),
            w.get("endpoint"),
            w.get("endpoint_raw"),
        )
        if wid:
            workers_to_test.setdefault(wid, {}).update(w)

    if not workers_to_test:
        warn("No discovered peers are available for the phase 6 access test.")
        return

    # -- Ejecutar el test de acceso global --
    for target_wid in sorted(workers_to_test, key=lambda x: int(x)):
        w_url = f"https://localhost:{5000 + int(target_wid)}"
        # Mantener la ruta IDS completa: Worker -> ECC local -> ECC coordinator -> DataApp.
        # Enviar aqui al /data interno saltaba el ECC remoto y podia devolver un
        # RejectionMessage antes de que la DataApp del coordinator evaluase el contrato.
        payload = {
            "Forward-To"      : coord_ecc,
            "connectorUri"    : coord_uri,   # URI IDS destino explicita -- evita inferencia incorrecta
            "messageType"     : "ContractRequestMessage",
            "requestedElement" : fl_res.get("@id", ""),
            "contractId"      : cid_val,
            "contractProvider": coord_uri,
        }

        step(f"Access test: Worker-{target_wid} requests the global model")
        _ids_log("out", "ids:ContractRequestMessage", f"worker-{target_wid}", f"coordinator-{cid}")

        try:
            raw = http_post_raw(f"{w_url}/proxy", payload, timeout=req_timeout)
            parsed = parse_ids(raw)
            if not parsed:
                parsed = parse_ids(raw, "Message") or {}

            ids_type = parsed.get("@type", "")

            if "ContractAgreement" in ids_type:
                step("Result: ACCESS GRANTED (Contract Agreement)")
                _ids_log("in", "ids:ContractAgreementMessage", f"coordinator-{cid}", f"worker-{target_wid}")

                transfer_contract = parsed.get("@id", "?")
                ok(f"Worker-{target_wid} -- model access granted")
                field("Target resource", fl_res.get("@id", "?"), indent=8)
                field("transferContract id", transfer_contract, indent=8)

            elif ("Rejection" in ids_type or "ContractRejection" in ids_type
                  or parsed.get("status") == "rejected"
                  or parsed.get("reason") in ("unauthorized_consumer", "fl_opt_out")):
                # Era un rechazo ESPERADO? -> worker no participo en el FL
                _is_expected_rejection = target_wid not in accepted_uris

                if _is_expected_rejection:
                    step("Result: ACCESS DENIED (data sovereignty enforced)")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    print(
                        f"    {RED}REJECTED  Worker-{target_wid} -- model access denied "
                        f"(non-participant; IDS sovereignty policy enforced){RESET}"
                    )
                    _reason = parsed.get("reason") or parsed.get("ids:rejectionReason", "policy_enforcement")
                    field("Rejection reason", str(_reason), indent=8)
                    field("Applied policy", "connector-restricted-policy (ids:rightOperand)", indent=8)
                else:
                    step("Result: UNEXPECTED RejectionMessage")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    reason = parsed.get("reason") or parsed.get("ids:rejectionReason", "?")
                    fail(f"Worker-{target_wid} -- model access denied, but this worker was a participant")
                    field("Rejection Reason", str(reason), indent=8)
                    field("raw_response", (raw[:200] + "...") if len(raw) > 200 else raw, indent=8)

            else:
                step("Result: Unrecognized IDS response")
                _ids_log("in", "PolicyRejection", f"coordinator-{cid}", f"worker-{target_wid}")
                warn(f"Worker-{target_wid} -- unrecognized IDS response: {ids_type!r}")
                field("raw_response", (raw[:200] + "...") if len(raw) > 200 else raw, indent=8)

        except Exception as e:
            warn(f"Worker-{target_wid} proxy access test failed: {e}")

        print()


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="PFG -- IDS + Federated Learning demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--coordinator", default="2", metavar="N",
                   help="Coordinator worker number (default: 2)")
    p.add_argument("--coordinator-port", type=int, default=0, metavar="PORT",
                   help=(
                       "Coordinator DataApp localhost port "
                       "(default: 5000 + --coordinator, e.g. 5002 for coordinator=2)"
                   ))
    p.add_argument("--skip-fl", action="store_true",
                   help="Do not start federated training; run only the IDS preparation phases")
    p.add_argument("--timeout", type=int, default=240, metavar="SEC",
                   help="HTTP timeout in seconds (default: 240)")
    p.add_argument("--no-client-ws", action="store_true",
                   help="Disable the client-to-DataApp WebSocket channel and use direct REST")
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
                print(f"  {GREEN}[OK]{RESET} {name} reset.")
            else:
                print(f"  {RED}[FAIL]{RESET} {name} returned HTTP {r.status_code}")
        except Exception as exc:
            print(f"  {RED}[ERR ]{RESET} Could not contact {name}: {exc}")

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
                print(f"  {GREEN}[OK]{RESET} Docker image removed: {img}")
            else:
                print(f"  {YELLOW}[WARN]{RESET} Could not remove {img}: {rm.stderr.strip()}")

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
                            print(f"  {GREEN}[OK]{RESET} Registry: fl-algo:{tag} tag purged")
                        else:
                            print(f"  {YELLOW}[WARN]{RESET} Registry: could not purge fl-algo:{tag} (HTTP {r_del.status_code})")
                if not tags:
                    print(f"  {GRAY}[--]{RESET} Registry: no pending fl-algo tags.")
            else:
                print(f"  {GRAY}[--]{RESET} Registry: fl-algo repository does not exist.")
        except Exception:
            print(f"  {GRAY}[--]{RESET} Registry fl-registry is not reachable.")

        # 3. Limpiar directorio _docker_build temporal dentro de cada worker
        worker_containers = ["be-dataapp-worker1", "be-dataapp-worker2",
                             "be-dataapp-worker3", "be-dataapp-worker4"]
        for cname in worker_containers:
            rm_build = subprocess.run(
                ["docker", "exec", cname, "rm", "-rf", "/home/nobody/data/_docker_build"],
                capture_output=True, text=True, timeout=10
            )
            if rm_build.returncode == 0:
                print(f"  {GREEN}[OK]{RESET} {cname}: _docker_build cleaned")

        if not fl_images:
            print(f"  {GRAY}[--]{RESET} No local FL Docker images were found.")
    except Exception as exc:
        print(f"  {YELLOW}[WARN]{RESET} Could not clean Docker artifacts: {exc}")


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
                print(f"  {RED}{BOLD}+------------------------------------------------+{RESET}")
                print(f"  {RED}{BOLD}|  [P] MANUAL CANCELLATION REQUESTED            |{RESET}")
                print(f"  {RED}{BOLD}|  Resetting all workers and the coordinator    |{RESET}")
                print(f"  {RED}{BOLD}+------------------------------------------------+{RESET}")
                print()
                _cleanup_workers(
                    coordinator_url_ref[0],
                    endpoints_ref[0],
                    req_timeout,
                )
                print(f"  {GREEN}System reset. You can run pfg_ids_fl_flow.py again.{RESET}")
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
        "Coordinator IDS catalog and sovereign datasets",
        "In this phase, the coordinator reads its own IDS Self-Description before contacting "
        "any external peer. The goal is to verify that it exposes sovereign CSV resources in "
        "its catalog and can therefore act as a valid coordinator for the federated learning "
        "run."
    )
    step("Inspect local IDS catalog")

    ecc_port = 8090 if int(cid) == 1 else 8090 + int(cid)
    if PRESENTATION_VERBOSE:
        print(f"      {GRAY}[DAPS/ECC route] https://localhost:{ecc_port}/api/selfDescription/{RESET}")
        print(f"      {GRAY}[DataApp route]  https://localhost:5002/ids/self-description/{RESET}")

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
            section("Catalog evidence")
            _log_event(
                "CATALOG",
                "Coordinator self-description resolved",
                " ",
                "OK",
                tag_color=GREEN,
                indent=6,
            )
            _log_kv("Endpoint", f"{coordinator_url}/ids/self-description", indent=8)
            _log_kv("Sovereign datasets", len(datasets), indent=8)
            _log_kv("Resource type", "CSV training datasets", indent=8)

            section("Published CSV resources")
            for idx, d in enumerate(datasets, 1):
                print(f"      {CYAN}[CSV {idx:02d}]{RESET} {BOLD}{d:<42}{RESET}"
                      f"{GRAY}IDS offeredResource{RESET}")
        else:
            warn("No CSV datasets were detected in the IDS catalog.")
    except Exception as exc:
        warn(f"Could not parse the IDS catalog: {exc}")


def main():
    global CLIENT_WS_ENABLED
    args = parse_args()
    cid  = args.coordinator
    if args.no_client_ws:
        CLIENT_WS_ENABLED = False

    try:
        cid_int = int(cid)
    except ValueError:
        print(f"{RED}Invalid coordinator ID: {cid!r}. It must be an integer, e.g. 2.{RESET}")
        sys.exit(1)

    # Puerto del coordinator: argumento explicito o convencion 5000+N
    coordinator_port = args.coordinator_port if args.coordinator_port else 5000 + cid_int
    coordinator_url  = f"https://localhost:{coordinator_port}"
    req_timeout      = args.timeout

    banner(
        "PFG IDS + Federated Learning Demonstration",
        f"Coordinator Worker-{cid}  |  Fuseki Broker  |  DAPS/Omejdn  |  multi-CSV discovery"
    )
    section("Execution profile")
    _log_kv("Coordinator", f"Worker-{cid}")
    _log_kv("DataApp endpoint", coordinator_url)
    _log_kv("FL execution", "disabled (--skip-fl)" if args.skip_fl else "enabled")
    _log_kv("HTTP timeout", f"{req_timeout}s")
    _log_kv(
        "Control channel",
        "WebSocket /ws/client" if CLIENT_WS_ENABLED and _WS_AVAILABLE else "REST proxy",
    )
    _log_kv("Cancellation", "Press [P] to reset coordinator and workers")

    # Referencias mutables para que el listener las actualice en caliente
    _coord_ref     = [coordinator_url]
    _endpoints_ref = [None]

    # Arrancar el hilo de escucha del teclado (daemon => muere con el proceso)
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
                warn("No workers accepted the contract; federated training will not start")
            else:
                fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout)
                fase5_monitorizar_fl(coordinator_url, cid, nego, endpoints, req_timeout)
                _mostrar_resultados_fl(coordinator_url, cid, req_timeout)
                fase6_test_acceso_modelo(coordinator_url, cid, nego, endpoints, req_timeout)

    except KeyboardInterrupt:
        print()
        print(f"  {RED}{BOLD}[CTRL+C] Execution interrupted. Resetting workers...{RESET}")
        _cleanup_workers(coordinator_url, _endpoints_ref[0], req_timeout)
        _close_ws_rpc_clients()
        print(f"  {GREEN}System reset.{RESET}")
        sys.exit(0)

    # Resumen final
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{WHITE}  Demonstration completed{RESET}")
    _sep("=", color=BOLD + CYAN)
    print()

    for w in nego.get("accepted", []):
        uri  = w.get("connector_uri", "?")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        ecc  = peer.get("ecc_url", "(unknown)")
        print(f"  {GREEN}PARTICIPATES   Worker-{wid}   {GRAY}{ecc}{RESET}")

    for w in nego.get("rejected", []):
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        peer   = endpoints["peers"].get(f"worker{wid}", {})
        ecc    = peer.get("ecc_url", "(unknown)")
        print(f"  {RED}REJECTED      Worker-{wid}   {GRAY}{ecc}  --  {reason}{RESET}")

    print()

    # --- METRICAS RENDIMIENTO ---
    if not args.skip_fl:
        try:
            import json
            perf = http_get(f"{coordinator_url}/metrics", timeout=req_timeout, quiet=True)

            print()
            print(f"  {CYAN}[PERFORMANCE] TRANSFER SUMMARY{RESET}")
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
            print(f"  {BOLD}IDS via ECC-to-ECC transport{RESET}")
            print(f"    Successful sends : {ids_ecc_sends}   (Failures: {ids_ecc_fails})")
            if ids_ecc_sends > 0:
                print(f"    Average latency : {ids_ecc_ms / ids_ecc_sends:.1f} ms")
                print(f"    Total volume    : {ids_ecc_bytes / 1024:.1f} KB")

            print()
            print(f"  {BOLD}HTTP fallback{RESET}")
            print(f"    Successful sends : {http_sends}   (Failures: {http_fails})")
            if http_sends > 0:
                print(f"    Average latency : {http_ms / http_sends:.1f} ms")
                print(f"    Total volume    : {http_bytes / 1024:.1f} KB")

            print()
            if ids_ecc_sends > 0 and http_sends == 0 and ws_sends == 0:
                print(f"  {GREEN}> CONCLUSION: FL training was performed 100% over IDS using ECC-to-ECC transport.{RESET}")
            elif ids_ecc_sends > 0 and http_sends > 0:
                print(f"  {YELLOW}> CONCLUSION: The main flow used IDS via ECC, with some HTTP fallback.{RESET}")
            print()
        except Exception as e:
            warn(f"Could not load performance metrics: {e}")

    # --- CLEARING HOUSE AUDIT ---
    try:
        import requests
        print(f"  {CYAN}[AUDIT] CLEARING HOUSE IDS NOTARY{RESET}")
        print(f"  {CYAN}----------------------------------------------------------------------{RESET}")

        try:
            r_integ = requests.get("http://localhost:8100/api/transactions/audit/integrity", timeout=req_timeout)
            if r_integ.ok:
                data = r_integ.json()
                status = data.get("status", "?")
                c = GREEN if status == "INTEGRITY_OK" else \
                   (YELLOW if status == "CORRUPTED" else RED)
                print(f"    {BOLD}Hash-chain integrity status{RESET}: {c}{status}{RESET}")
        except:
            pass

        print()
        print(f"  > Full digital-notary history:")
        print(f"      {MAGENTA}http://localhost:8100/api/transactions?page_size=1000&sort_order=asc{RESET}")
        print(f"  > System usage metrics:")
        print(f"      {MAGENTA}http://localhost:8100/api/stats/system{RESET}")
        print(f"  > JSON export endpoint:")
        print(f"      {MAGENTA}http://localhost:8100/api/export/json{RESET}")
        print()
    except Exception as e:
        warn(f"Could not query the Clearing House: {e}")

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

        print(f"  {CYAN}[REPORT] DOWNLOADING IDS AUDIT REPORT...{RESET}")

        r_export = requests.get("http://localhost:8100/api/export/json", timeout=10)
        if r_export.ok:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(r_export.text)
            print(f"    {GREEN}OK  Official audit report saved to: {export_path}{RESET}")
            try:
                export_data = r_export.json()
                total_exported = export_data.get("total_records")
                if total_exported is None:
                    exported_rows = export_data.get("data", [])
                    total_exported = len(exported_rows) if isinstance(exported_rows, list) else "?"
                print(f"    {BOLD}Audited sample size{RESET}    : {total_exported} IDS transactions")
            except Exception:
                pass
        else:
            print(f"    {YELLOW}WARN Could not download the report (HTTP {r_export.status_code}){RESET}")
    except Exception as e:
        print(f"    {YELLOW}WARN Could not automate the Clearing House export: {e}{RESET}")
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
