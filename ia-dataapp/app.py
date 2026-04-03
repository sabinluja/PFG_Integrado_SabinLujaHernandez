"""
app.py  --  IA DataApp Worker/Coordinator
=========================================

Cualquier worker puede ser coordinator -- se elige en Postman enviando el
algoritmo (fl_algorithm) al worker destino via IDS/TRUE Connector.

Flujo completo con Broker + DAPS (pasos Postman):
  Pasos 1-4  -- Negociacion IDS manual (proxy -> ecc destino)
               El worker receptor recibe algorithm.py + fl_config.json
               y se convierte en COORDINATOR.

  Paso 5a    -- POST /broker/discover   -> coordinator consulta Fuseki SPARQL
                                          y descubre workers compatibles.
  Paso 5b    -- POST /fl/negotiate      -> coordinator negocia contratos IDS
                                          con los workers compatibles del broker.
                                          Worker4 (FL_AUTHORIZED_URIS vacio) es
                                          rechazado automaticamente.
  Paso 5c    -- POST /fl/start          -> coordinator envia algoritmo + pesos
                                          a los workers aceptados y arranca FL.

  Pasos 13-17 -- Verificacion del modelo publicado y control de acceso.
               Worker4 no puede negociar contrato del recurso FL porque
               su CONNECTOR_URI no aparece en ids:rightOperand del constraint.

  El fl_config.json se guarda en /home/nobody/data/fl_config.json.
  Los parametros FL_ROUNDS y ROUND_TIMEOUT ya NO vienen de variables de entorno.
"""

import os
import sys
import json
import time
import uuid
import base64
import logging
import threading
import importlib.util
import datetime
import concurrent.futures

import numpy as np
import requests
import urllib3
import uvicorn

import asyncio

from fastapi import FastAPI, Form, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.multipart.decoder import MultipartDecoder

TLS_CERT = "/cert/daps/ca.crt" if os.path.exists("/cert/daps/ca.crt") else False
if not TLS_CERT:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Configuracion
# =============================================================================

INSTANCE_ID   = os.getenv("INSTANCE_ID", "1")
CONNECTOR_URI = os.getenv(
    "ISSUER_CONNECTOR_URI",
    f"http://w3id.org/engrd/connector/worker{INSTANCE_ID}"
)
ECC_HOSTNAME = os.getenv("ECC_HOSTNAME", f"ecc-worker{INSTANCE_ID}")

PEER_ECC_URLS = [
    u.strip()
    for u in os.getenv("PEER_ECC_URLS", "").split(",")
    if u.strip()
]
PEER_CONNECTOR_URIS = [
    u.strip()
    for u in os.getenv("PEER_CONNECTOR_URIS", "").split(",")
    if u.strip()
]

# Broker IDS -- para descubrimiento dinamico de workers
BROKER_URL = os.getenv("BROKER_URL", "https://broker-reverseproxy/infrastructure")
BROKER_SPARQL_URL = "http://broker-fuseki:3030/connectorData/sparql"

# Permite a un worker auto-excluirse del entrenamiento FL (Data Sovereignty)
FL_OPT_OUT = os.getenv("FL_OPT_OUT", "false").lower() == "true"

# Permite bypass de IDS (peticiones HTTP directas entre DataApps) si falla WebSockets
ALLOW_IDS_BYPASS = os.getenv("ALLOW_IDS_BYPASS", "false").lower() == "true"

# Credenciales para la API interna del ECC
API_USER = os.getenv("API_USER", "apiUser")
API_PASS = os.getenv("API_PASS", "passwordApiUser")

# Directorios
DATA_DIR   = "/home/nobody/data"
INPUT_DIR  = os.path.join(DATA_DIR, "input")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")

# Rutas de ficheros recibidos via IDS
ALGO_IDS_PATH   = os.path.join(DATA_DIR, "algorithm.py")
ALGO_BAKED_PATH = "/app/algorithm.py"
CONFIG_PATH     = os.path.join(DATA_DIR, "fl_config.json")

os.makedirs(INPUT_DIR,  exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# =============================================================================
# Configuracion LLM -- para recomendacion inteligente de datasets
# Unicamente usando Ollama (local, air-gapped) por temas de soberania de datos
# =============================================================================
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://ollama:11434/api/generate")
LLM_MODEL    = os.getenv("LLM_MODEL",    "llama3.2")


# =============================================================================
# Configuracion FL -- leida de fl_config.json (enviado desde Postman)
# =============================================================================

def _load_fl_config() -> dict:
    defaults = {
        "rounds"       : 5,
        "round_timeout": 180,
        "min_workers"  : 2,
        "epochs"       : 3,
        "batch_size"   : 32,
        "learning_rate": 0.001,
        "test_split"   : 0.2,
        "force_http_fallback": False, # Nuevo: fuerza pasar por IDS para benchmarking
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                cfg = json.load(f)
            defaults.update(cfg)
        except Exception:
            pass
    return defaults


# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s  [worker-{INSTANCE_ID}]  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


# =============================================================================
# Estado en memoria
# =============================================================================

is_coordinator       = False
_published_fl_contract: dict = {}
coordinator_ecc_url  = None
coordinator_conn_uri = None

_accepted_workers: list = []
_negotiate_lock = threading.Lock()

fl_state = {
    "status"       : "idle",
    "current_round": 0,
    "total_rounds" : 0,
    "history"      : [],
}
_fl_lock = threading.Lock()

_round_weights: dict = {}
_round_lock = threading.Lock()

_my_selected_csv: str | None = None   # CSV elegido por el coordinator para este worker
PEER_SELECTED_CSVS: list = []   # CSV seleccionado por cada peer (indice igual que PEER_ECC_URLS)

# Cache del ultimo discovery -- /fl/negotiate lo reutiliza sin relanzar el LLM
_compatible_workers_cache: list = []
_compatible_workers_lock = threading.Lock()

# =============================================================================
# Metricas de rendimiento WebSocket vs HTTP
# =============================================================================
_ws_perf_stats = {
    "ws_sends": 0,
    "ws_total_ms": 0.0,
    "ws_bytes": 0,
    "http_sends": 0,
    "http_total_ms": 0.0,
    "http_bytes": 0,
    "ws_failures": 0,
    "http_failures": 0,
    "history": [],   # ultimas 50 transferencias con detalle
}
_ws_perf_lock = threading.Lock()

global_event_loop = None


# =============================================================================
# FastAPI
# =============================================================================

app = FastAPI(
    title=f"IA DataApp -- Worker {INSTANCE_ID}",
    description=(
        "Sustituye al Java DataApp del TRUE Connector. "
        "POST /proxy para Postman. POST /data para el ECC."
    ),
    version="7.2.0",
)


@app.on_event("startup")
async def _startup_identity_log():
    """Log de identidad IDS al arrancar -- facilita debug con broker y DAPS."""
    global global_event_loop
    global_event_loop = asyncio.get_running_loop()
    log.info("=" * 60)
    log.info(f"  IA DataApp arrancando -- Worker {INSTANCE_ID}")
    log.info(f"  CONNECTOR_URI   : {CONNECTOR_URI}")
    log.info(f"  ECC_HOSTNAME    : {ECC_HOSTNAME}")
    log.info(f"  BROKER_URL      : {BROKER_URL}")
    log.info(f"  BROKER_SPARQL   : {BROKER_SPARQL_URL}")
    log.info(f"  PEER_ECC_URLS   : {PEER_ECC_URLS or '(vacio -- se rellenara via broker)'}")
    log.info(f"  PEER_CONN_URIS  : {PEER_CONNECTOR_URIS or '(vacio -- se rellenara via broker)'}")
    if FL_OPT_OUT:
        log.warning(
            f"  FL_OPT_OUT      : True -- "
            f"worker-{INSTANCE_ID} NO participara en FL. "
            "Los ContractRequestMessage de coordinators seran rechazados por politica de datos."
        )
    else:
        log.info("  FL_OPT_OUT      : False (Participara en entrenamientos FL validos).")
    log.info("=" * 60)

    # Publicar datasets automaticamente dando tiempo al ECC a arrancar
    asyncio.create_task(_delay_publish_datasets())

async def _delay_publish_datasets():
    import asyncio
    import requests
    from requests.auth import HTTPBasicAuth
    
    ecc_base = f"https://{ECC_HOSTNAME}:8449"
    basic_api = HTTPBasicAuth(API_USER, API_PASS)
    max_retries = 15
    
    log.info("[startup] Esperando a que el ECC inicie para publicar datasets...")
    for i in range(max_retries):
        await asyncio.sleep(5)
        try:
            # PING al catalog_id
            res = requests.get(f"{ecc_base}/api/selfDescription/", verify=TLS_CERT, auth=basic_api, timeout=5)
            if res.status_code == 200:
                log.info(f"[startup] ECC levantado (intento {i+1}). Publicando datasets locales...")
                _publish_local_csvs()
                return
        except Exception:
            pass
            
    log.error("[startup] Error: El ECC no arranco a tiempo. Datasets no publicados.")



# =============================================================================
# Utilidades IDS
# =============================================================================

def _now_iso() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _ids_context() -> dict:
    return {
        "ids" : "https://w3id.org/idsa/core/",
        "idsc": "https://w3id.org/idsa/code/",
    }


# =============================================================================
# Token DAT real
# =============================================================================

CERT_PATH      = "/cert/daps/worker.cert"
KEY_PATH       = "/cert/daps/worker.key"
DAPS_TOKEN_URL = "https://omejdn/auth/token"

_dat_cache: dict = {"token": None, "exp": 0}


def _get_dat_token() -> str:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend

    now = int(time.time())

    if _dat_cache["token"] and _dat_cache["exp"] > now + 30:
        return _dat_cache["token"]

    with open(CERT_PATH, "rb") as f:
        cert_pem = f.read()
    with open(KEY_PATH, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    cert = _x509.load_pem_x509_certificate(cert_pem, default_backend())
    ski_ext = cert.extensions.get_extension_for_class(_x509.SubjectKeyIdentifier)
    aki_ext = cert.extensions.get_extension_for_class(_x509.AuthorityKeyIdentifier)
    ski_fmt = ":".join(f"{b:02X}" for b in ski_ext.value.digest)
    aki_fmt = ":".join(f"{b:02X}" for b in aki_ext.value.key_identifier)
    client_id = f"{ski_fmt}:keyid:{aki_fmt}"

    assertion = pyjwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": "idsc:IDS_CONNECTORS_ALL",
            "iat": now,
            "exp": now + 60,
            "nbf": now,
            "jti": str(uuid.uuid4()),
        },
        private_key,
        algorithm="RS256",
    )

    resp = requests.post(
        DAPS_TOKEN_URL,
        data={
            "grant_type"           : "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion"     : assertion,
            "scope"                : "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL",
        },
        verify=TLS_CERT,
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]

    decoded = pyjwt.decode(token, options={"verify_signature": False})
    _dat_cache["token"] = token
    _dat_cache["exp"]   = decoded.get("exp", now + 3600)

    log.info(f"[DAPS] Token DAT obtenido para worker-{INSTANCE_ID} -- expira en {_dat_cache['exp'] - now}s")
    return token


def _security_token() -> dict:
    try:
        token_val = _get_dat_token()
    except Exception as e:
        log.error(f"[DAPS] No se pudo obtener token real: {e} -- Abortando mensaje IDS")
        raise RuntimeError(f"DAPS token unavailable: {e}")
    return {
        "@type"          : "ids:DynamicAttributeToken",
        "@id"            : f"https://w3id.org/idsa/autogen/dynamicAttributeToken/{uuid.uuid4()}",
        "ids:tokenValue" : token_val,
        "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
    }


def _get_self_description() -> dict:
    resp = requests.get(
        f"https://{ECC_HOSTNAME}:8449/api/selfDescription/",
        verify=TLS_CERT, timeout=10,
        auth=("apiUser", "passwordApiUser")
    )
    resp.raise_for_status()
    return resp.json()


def _multipart_response(header_dict: dict, payload_str: str | None = None) -> Response:
    import uuid as _uuid
    boundary = _uuid.uuid4().hex
    str_header = json.dumps(header_dict)
    header_bytes = str_header.encode("utf-8")

    header_part = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"header\"\r\n"
        f"Content-Type: application/json; charset=UTF-8\r\n"
        f"Content-Length: {len(header_bytes)}\r\n"
        f"\r\n"
        f"{str_header}\r\n"
    )

    body = header_part

    if payload_str is not None:
        payload_bytes = payload_str.encode("utf-8")
        body += (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"payload\"\r\n"
            f"Content-Type: text/plain; charset=UTF-8\r\n"
            f"Content-Length: {len(payload_bytes)}\r\n"
            f"\r\n"
            f"{payload_str}\r\n"
        )

    body += f"--{boundary}--\r\n"

    from starlette.responses import Response as StarletteResponse
    return StarletteResponse(
        content=body.encode("utf-8"),
        media_type=f"multipart/form-data; boundary={boundary}"
    )


def _base_response_header(mensaje: dict, msg_type: str,
                           extra_id: str, connector_id: str) -> dict:
    return {
        "@context"              : _ids_context(),
        "@type"                 : msg_type,
        "@id"                   : f"https://w3id.org/idsa/autogen/{extra_id}/{uuid.uuid4()}",
        "ids:modelVersion"      : mensaje.get("ids:modelVersion", "4.1.0"),
        "ids:issued"            : {
            "@value": _now_iso(),
            "@type" : "http://www.w3.org/2001/XMLSchema#dateTimeStamp",
        },
        "ids:issuerConnector"   : {"@id": connector_id},
        "ids:senderAgent"       : {"@id": connector_id},
        "ids:correlationMessage": {"@id": mensaje["@id"]},
        "ids:recipientConnector": [mensaje["ids:issuerConnector"]],
        "ids:securityToken"     : _security_token(),
    }


# =============================================================================
# POST /proxy
# =============================================================================

@app.post("/proxy")
async def proxy(request: Request):
    body = await request.json()

    forward_to        = body.get("Forward-To", "")
    message_type_raw  = body.get("messageType", "")
    payload_in        = body.get("payload", None)
    req_artifact      = body.get("requestedArtifact")
    req_element       = body.get("requestedElement")
    transfer_contract      = body.get("transferContract")
    explicit_connector_uri = body.get("connectorUri")   # URI IDS explicita (fase 6, bypass inferencia)

    contract_id_field  = body.get("contractId")
    contract_prov_field = body.get("contractProvider")
    if (message_type_raw.replace("ids:", "") == "ContractRequestMessage"
            and contract_id_field and not payload_in):
        payload_in = {
            "@context": {"ids": "https://w3id.org/idsa/core/", "idsc": "https://w3id.org/idsa/code/"},
            "@type"   : "ids:ContractRequest",
            "@id"     : contract_id_field,
            "ids:permission" : [],
            "ids:provider"   : {"@id": contract_prov_field or ""},
            "ids:obligation" : [],
            "ids:prohibition": [],
            "ids:consumer"   : {"@id": CONNECTOR_URI},
        }

    message_type = message_type_raw if message_type_raw.startswith("ids:") \
                   else f"ids:{message_type_raw}"

    dest_conn_uri = explicit_connector_uri or _infer_connector_uri(forward_to)

    log.info(f"[/proxy] {message_type} -> {forward_to}")

    try:
        corr_msg = body.get("correlationMessage") or transfer_contract or None

        fl_extra = {}
        if isinstance(payload_in, dict) and payload_in.get("type") == "fl_algorithm":
            algo_b64   = payload_in.get("content", "") or ""
            config_b64 = payload_in.get("config",  "") or ""
            combined   = f"{algo_b64}||fl_config::{config_b64}" if config_b64 else algo_b64
            fl_extra   = {"ids:contentVersion": combined}
            log.info(f"[/proxy] fl_algorithm detectado -- content+config -> ids:contentVersion (config={'present' if config_b64 else 'absent'})")

        result = _ids_send(
            forward_to_url       = forward_to,
            forward_to_connector = dest_conn_uri,
            message_type         = message_type,
            requested_artifact   = req_artifact,
            requested_element    = req_element,
            transfer_contract    = transfer_contract,
            payload              = payload_in,
            correlation_message  = corr_msg,
            header_content       = None,
            extra_header         = fl_extra,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        log.error(f"[/proxy] Error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=502,
            content={"error": str(exc), "forward_to": forward_to}
        )


def _infer_connector_uri(ecc_url: str) -> str:
    for url, uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
        if url in ecc_url or ecc_url in url:
            return uri
            
    # Inferencia dinamica usando el catalogo del Broker en lugar de regex estatica
    try:
        connectors = _get_registered_connectors()
        from urllib.parse import urlparse
        for c in connectors:
            ep = c.get("endpoint", "")
            if ep:
                hostname = urlparse(ep).hostname
                if hostname and hostname in ecc_url:
                    return c["connector_uri"]
            if c["connector_uri"] == ecc_url:
                return c["connector_uri"]
    except Exception as e:
        log.warning(f"Error infiriendo URI dinamicamente dinamicamente: {e}")
        
    return ecc_url


# =============================================================================
# Utilidades IDS -- envio saliente
# =============================================================================

def _build_outgoing_header(message_type: str, dest_connector_uri: str,
                            extra: dict | None = None) -> dict:
    h = {
        "@context"              : _ids_context(),
        "@type"                 : message_type,
        "@id"                   : (
            f"https://w3id.org/idsa/autogen/"
            f"{message_type.split(':')[-1]}/{uuid.uuid4()}"
        ),
        "ids:modelVersion"      : "4.1.0",
        "ids:issued"            : {
            "@value": _now_iso(),
            "@type" : "http://www.w3.org/2001/XMLSchema#dateTimeStamp",
        },
        "ids:issuerConnector"   : {"@id": CONNECTOR_URI},
        "ids:senderAgent"       : {"@id": CONNECTOR_URI},
        "ids:securityToken"     : _security_token(),
        "ids:recipientConnector": [{"@id": dest_connector_uri}],
    }
    if extra:
        h.update(extra)
    return h


def _ids_send(
    forward_to_url      : str,
    forward_to_connector: str,
    message_type        : str,
    requested_artifact  : str | None = None,
    requested_element   : str | None = None,
    transfer_contract   : str | None = None,
    payload             : dict | None = None,
    correlation_message : str | None = None,
    header_content      : str | None = None,
    header_content_type : str = "fl_algorithm",
    peer_algorithm      : bool = False,
    extra_header        : dict | None = None,
    use_local_ecc       : bool = False,
) -> dict:
    extra = {}
    if requested_artifact:  extra["ids:requestedArtifact"]  = {"@id": requested_artifact}
    if requested_element:   extra["ids:requestedElement"]   = {"@id": requested_element}
    if transfer_contract:   extra["ids:transferContract"]   = {"@id": transfer_contract}
    if correlation_message: extra["ids:correlationMessage"] = {"@id": correlation_message}
    if header_content:
        extra["ids:securityToken"] = {
            "@type"          : "ids:DynamicAttributeToken",
            "@id"            : "https://w3id.org/idsa/autogen/dynamicAttributeToken/fl",
            "ids:tokenValue" : (f"{header_content_type}::from_coordinator::{header_content}"
                                if peer_algorithm
                                else f"{header_content_type}::{header_content}"),
            "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
        }

    header_dict = _build_outgoing_header(message_type, forward_to_connector, extra)
    if extra_header:
        header_dict.update(extra_header)
    str_header  = json.dumps(header_dict)

    actual_url = forward_to_url
    if use_local_ecc:
        actual_url = f"https://ecc-worker{INSTANCE_ID}:8887/incoming-data-app/multipartMessageBodyFormData"
        header_dict["Forward-To"] = forward_to_url
        str_header = json.dumps(header_dict)

    fields = {"header": ("header", str_header, "application/json")}

    if payload is not None:
        payload_str = json.dumps(payload) if not isinstance(payload, str) else payload
        fields["payload"] = ("payload", payload_str, "application/json")

    encoder = MultipartEncoder(fields=fields)
    log.info(f"[IDS OUT] {message_type} -> {forward_to_url}")

    resp = requests.post(
        actual_url,
        data=encoder,
        headers={"Content-Type": encoder.content_type},
        verify=TLS_CERT,
        timeout=60,
    )
    resp.raise_for_status()

    content_type = resp.headers.get("Content-Type", "")
    if "multipart" in content_type:
        try:
            decoder = MultipartDecoder(resp.content, content_type)
            parts_by_name = {}
            for part in decoder.parts:
                disp = part.headers.get(b"Content-Disposition", b"").decode("utf-8", errors="ignore")
                text = part.content.decode("utf-8", errors="ignore").strip()
                if "\n\n" in text:
                    text = text.split("\n\n", 1)[-1].strip()
                name = ""
                for seg in disp.split(";"):
                    seg = seg.strip()
                    if seg.startswith("name="):
                        name = seg.split("=", 1)[1].strip().strip('"')
                parts_by_name[name] = text
            payload_text = parts_by_name.get("payload") or parts_by_name.get("header", "")
            if payload_text:
                try:
                    return json.loads(payload_text)
                except Exception:
                    pass
        except Exception as e:
            log.warning(f"No se pudo parsear multipart de respuesta: {e}")
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}


# =============================================================================
# Negociacion IDS completa -- coordinator -> peer
# =============================================================================

def _dataapp_url_from_ecc(peer_ecc_url: str) -> str:
    """
    Deriva la URL interna del DataApp del peer a partir de su ECC URL.
    Convencion: https://ecc-workerN:8889/data -> https://be-dataapp-workerN:8500
    """
    import re as _re_da
    m = _re_da.search(r"ecc-worker(\d+)", peer_ecc_url)
    if m:
        return f"https://be-dataapp-worker{m.group(1)}:8500"
    return ""


def _negotiate_and_send_algorithm(peer_ecc_url: str, peer_conn_uri: str,
                                   artifact_bytes: bytes,
                                   config_bytes: bytes,
                                   selected_csv: str | None = None,
                                   transfer_contract: str | None = None) -> bool:
    """
    Envia algorithm.py + fl_config.json al peer via IDS.

    Canal principal: ArtifactRequestMessage multipart a ecc-workerN:8889/data
    (el ECC del peer valida el DAT token y reenvía al DataApp del peer).
    El receptor procesa el payload en /data handler con artifact_type='fl_algorithm'.
    Fallback: POST directo a be-dataapp-workerN:8500/fl/receive-algorithm si el
    ECC no está disponible o devuelve error.
    """
    algo_b64   = base64.b64encode(artifact_bytes).decode("utf-8")
    config_b64 = base64.b64encode(config_bytes).decode("utf-8")
    combined   = f"{algo_b64}||fl_config::{config_b64}"

    payload_dict = {
        "type"            : "fl_algorithm",
        "content"         : algo_b64,
        "config"          : config_b64,
        "selected_csv"    : selected_csv,
        "coordinator_uri" : CONNECTOR_URI,
        "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data",
        "from_coordinator": True,
    }

    # --- Canal IDS: ArtifactRequestMessage direct to peer DataApp /data ---
    # Para la demo enviamos un mensaje IDS real multipart, pero entregándolo
    # directamente al endpoint /data del peer (como hace /fl/negotiate).
    peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
    if not peer_dataapp:
        log.error(f"[coordinator] No se pudo derivar DataApp URL de {peer_ecc_url}")
        return False
        
    forward_target = f"{peer_dataapp}/data"

    log.info(
        f"[coordinator->IDS] Enviando algoritmo via IDS ArtifactRequestMessage\n"
        f"  Destino IDS : {forward_target}\n"
        f"  Peer URI    : {peer_conn_uri}\n"
        f"  CSV asignado: {selected_csv or '(auto)'}"
    )
    try:
        ids_result = _ids_send(
            forward_to_url       = forward_target,
            forward_to_connector = peer_conn_uri,
            message_type         = "ids:ArtifactRequestMessage",
            transfer_contract    = transfer_contract,
            payload              = payload_dict,
            extra_header         = {"ids:contentVersion": f"fl_algorithm::{combined}"},
        )
        status_ok = (
            ids_result.get("status") in ("everything_received", "ok")
            or "ArtifactResponse" in ids_result.get("@type", "")
        )
        if status_ok:
            log.info(
                f"[coordinator->IDS] algorithm.py + fl_config.json entregados via IDS [OK]\n"
                f"  Peer   : {peer_conn_uri}\n"
                f"  CSV    : {selected_csv or '(auto)'}\n"
                f"  Status : {ids_result.get('status', ids_result.get('@type', '?'))}"
            )
            return True
        else:
            log.warning(
                f"[coordinator->IDS] Respuesta inesperada del peer via IDS: {str(ids_result)[:200]}\n"
                f"  Intentando fallback DataApp-to-DataApp..."
            )
    except Exception as exc:
        log.warning(
            f"[coordinator->IDS] Error enviando algoritmo via IDS a {forward_target}: {exc}\n"
            f"  Intentando fallback DataApp-to-DataApp..."
        )

    # --- Fallback: POST directo al DataApp (sin capa IDS multipart) ---
    if not ALLOW_IDS_BYPASS:
        log.error("[coordinator->IDS] Fallo el envio via IDS y ALLOW_IDS_BYPASS=false. No se hara bypass HTTP al DataApp.")
        return False

    peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
    if not peer_dataapp:
        log.error(f"[coordinator] No se pudo derivar DataApp URL de {peer_ecc_url}")
        return False
    try:
        resp = requests.post(
            f"{peer_dataapp}/fl/receive-algorithm",
            json={
                "algo_b64"        : algo_b64,
                "config_b64"      : config_b64,
                "selected_csv"    : selected_csv,
                "coordinator_uri" : CONNECTOR_URI,
                "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data",
            },
            timeout=30,
            verify=TLS_CERT,
        )
        resp.raise_for_status()
        log.info(
            f"[coordinator->HTTP] algorithm.py + fl_config.json -> {peer_dataapp} [OK (fallback)]"
            + (f"  (CSV: {selected_csv})" if selected_csv else "")
        )
        return True
    except Exception as exc:
        log.error(f"[coordinator] Error enviando algoritmo (fallback) a {peer_dataapp}: {exc}", exc_info=True)
        return False


def _activate_coordinator_from_local() -> bool:
    """
    Activa el rol coordinator cargando el algorithm.py que ya existe en
    este conector (baked en la imagen o previamente recibido via IDS).

    Este es el mecanismo correcto para el self-fetch del coordinator:
    el conector TIENE el artefacto (en el contexto IDS, esta disponible
    como recurso en su propio catalogo). No necesita pedirse a si mismo
    a traves del ECC (lo que causaria un self-loop rechazado por DAPS).

    El handshake IDS completo (Description -> Contract -> Artifact) tiene
    sentido cuando el consumer ES DIFERENTE del provider. Para la
    activacion del coordinator (mismo conector), la carga directa es
    semanticamente equivalente y arquitectonicamente correcta.
    """
    global is_coordinator
    algo_src = _algo_path()  # IDS path primero, luego baked
    if not os.path.exists(algo_src):
        log.error(
            f"[activate-coordinator] algorithm.py no encontrado en {algo_src}\n"
            f"  (ALGO_IDS_PATH={ALGO_IDS_PATH}, ALGO_BAKED_PATH={ALGO_BAKED_PATH})"
        )
        return False

    try:
        with open(algo_src, "rb") as f:
            algo_bytes = f.read()

        # Si ya esta en ALGO_IDS_PATH no hace falta copiar;
        # si viene de ALGO_BAKED_PATH, guardarlo en ALGO_IDS_PATH
        if algo_src == ALGO_BAKED_PATH and algo_src != ALGO_IDS_PATH:
            _save_algorithm(algo_bytes)

        # Cargar fl_config.json si existe
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "rb") as f:
                config_bytes = f.read()
            _save_config(config_bytes)

        is_coordinator = True
        log.info(
            f"~... algorithm.py cargado desde propio conector "
            f"({len(algo_bytes)} bytes) -- worker-{INSTANCE_ID} = COORDINATOR\n"
            f"  Fuente: {algo_src}"
        )
        return True

    except Exception as exc:
        log.error(f"[activate-coordinator] Error: {exc}", exc_info=True)
        return False


# =============================================================================
# Obtencion del algoritmo via IDS -- coordinator como CONSUMER (de otro conector)
# =============================================================================

def _fetch_algorithm_from_ecc(source_ecc_url: str, source_connector_uri: str) -> bool:
    """
    El worker que quiere ser coordinator actua como consumer IDS:
    ejecuta el handshake completo (Description -> ContractRequest -> Agreement ->
    ArtifactRequest) contra el ECC fuente para obtener algorithm.py +
    fl_config.json. Al terminar, activa is_coordinator = True.

    El ECC fuente debe tener un worker DataApp que responda al
    ArtifactRequestMessage con el algoritmo (modo 'source').
    """
    global is_coordinator
    log.info(f"[fetch-algorithm] Iniciando fetch desde {source_ecc_url} ({source_connector_uri})")
    try:
        desc     = _ids_send(source_ecc_url, source_connector_uri, "ids:DescriptionRequestMessage")
        catalogs = desc.get("ids:resourceCatalog", [{}])
        resource = (catalogs[0].get("ids:offeredResource", [{}]) or [{}])[0]
        contract = (resource.get("ids:contractOffer",   [{}]) or [{}])[0]
        repres   = (resource.get("ids:representation",  [{}]) or [{}])[0]
        instance = (repres.get("ids:instance",          [{}]) or [{}])[0]

        contract_id       = contract.get("@id", "")
        permission        = (contract.get("ids:permission", [{}]) or [{}])[0]
        provider_id       = contract.get("ids:provider", {}).get("@id", "")
        contract_artifact = instance.get(
            "@id", "http://w3id.org/engrd/connector/artifact/1"
        )
        log.info(f"[fetch-algorithm] 1/4 Description OK -- artifact={contract_artifact}")

        agreement = _ids_send(
            source_ecc_url, source_connector_uri, "ids:ContractRequestMessage",
            requested_element=contract_artifact,
            payload={
                "@context"      : _ids_context(),
                "@type"         : "ids:ContractRequest",
                "@id"           : contract_id,
                "ids:permission": [permission],
                "ids:provider"  : {"@id": provider_id},
                "ids:obligation": [], "ids:prohibition": [],
                "ids:consumer"  : {"@id": CONNECTOR_URI},
            },
        )
        transfer_contract = agreement.get("@id", "")
        log.info(f"[fetch-algorithm] 2/4 ContractAgreement OK -- transfer={transfer_contract}")

        _ids_send(
            source_ecc_url, source_connector_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
            payload=agreement,
        )
        log.info("[fetch-algorithm] 3/4 Acuerdo confirmado")

        resp = _ids_send(
            source_ecc_url, source_connector_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
        )
        log.info(f"[fetch-algorithm] 4/4 ArtifactResponse recibida -- type={resp.get('type','?')!r}")

        algo_b64   = resp.get("content", "")
        config_b64 = resp.get("config")

        if not algo_b64:
            log.error(f"[fetch-algorithm] Respuesta sin contenido: {str(resp)[:300]}")
            return False

        try:
            algo_bytes = base64.b64decode(algo_b64)
        except Exception:
            algo_bytes = algo_b64.encode() if isinstance(algo_b64, str) else b""

        _save_algorithm(algo_bytes)

        if config_b64:
            try:
                config_bytes = base64.b64decode(config_b64)
                _save_config(config_bytes)
            except Exception as e:
                log.warning(f"[fetch-algorithm] No se pudo guardar fl_config.json: {e}")
        else:
            log.warning(
                "[fetch-algorithm] fl_config.json no incluido en la respuesta -- "
                "guardando valores por defecto en disco"
            )
            _save_config(json.dumps(_load_fl_config()).encode())


        is_coordinator = True
        log.info(
            f"~... algorithm.py + config obtenidos via IDS desde {source_ecc_url} "
            f"-- worker-{INSTANCE_ID} = COORDINATOR"
        )
        return True

    except Exception as exc:
        log.error(f"[fetch-algorithm] Error: {exc}", exc_info=True)
        return False


# =============================================================================
# Logica FL
# =============================================================================

def _algo_path() -> str:
    return ALGO_IDS_PATH if os.path.exists(ALGO_IDS_PATH) else ALGO_BAKED_PATH


def _save_algorithm(data: bytes):
    os.makedirs(os.path.dirname(ALGO_IDS_PATH), exist_ok=True)
    with open(ALGO_IDS_PATH, "wb") as f:
        f.write(data)
    sys.modules.pop("algorithm", None)
    log.info(f"algorithm.py guardado ({len(data)} bytes)")


def _save_config(data: bytes):
    with open(CONFIG_PATH, "wb") as f:
        f.write(data)
    cfg = json.loads(data.decode())
    log.info(f"fl_config.json guardado: {cfg}")


def _load_algorithm():
    path = _algo_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"algorithm.py no encontrado en {path}")
    spec   = importlib.util.spec_from_file_location("algorithm", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algorithm"] = module
    spec.loader.exec_module(module)
    return module


def _csv_path() -> str:
    specific = os.path.join(INPUT_DIR, f"unsw_nb15_worker_{INSTANCE_ID}.csv")
    if os.path.exists(specific):
        return specific
    files = sorted(f for f in os.listdir(INPUT_DIR) if f.endswith(".csv"))
    if not files:
        raise FileNotFoundError(f"No hay CSV en {INPUT_DIR}")
    return os.path.join(INPUT_DIR, files[0])


def _weights_to_b64(weights: list) -> str:
    raw = json.dumps([w.tolist() for w in weights]).encode()
    return base64.b64encode(raw).decode()


def _b64_to_weights(b64: str) -> list:
    raw = base64.b64decode(b64.encode())
    return [np.array(w, dtype=np.float32) for w in json.loads(raw.decode())]


def _fedavg(results: list) -> list:
    total = sum(r["n_samples"] for r in results)
    agg   = None
    for r in results:
        w     = _b64_to_weights(r["weights_b64"])
        scale = r["n_samples"] / total
        if agg is None:
            agg = [layer * scale for layer in w]
        else:
            for i, layer in enumerate(w):
                agg[i] += layer * scale
    return agg


def _save_local_metrics(result: dict, round_num: int):
    metrics_path = os.path.join(OUTPUT_DIR, "local_metrics.json")
    try:
        if os.path.exists(metrics_path):
            with open(metrics_path) as f:
                history = json.load(f)
        else:
            history = []
        history.append({
            "round"       : round_num,
            "worker"      : INSTANCE_ID,
            "n_samples"   : result.get("n_samples"),
            "metrics"     : result.get("metrics"),
            "input_dim"   : result.get("input_dim"),
            "feature_cols": result.get("feature_cols"),
        })
        with open(metrics_path, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        log.error(f"Error guardando metricas locales: {e}")


def _train_local(global_weights_b64: str, round_num: int, csv_path: str | None = None) -> dict:
    _csv = csv_path or _my_selected_csv or _csv_path()
    log.info(f"[train] Ronda {round_num} -- usando CSV: {os.path.basename(_csv)}")
    result = _load_algorithm().run(
        _csv,
        global_weights_b64=global_weights_b64,
        config_path=CONFIG_PATH
    )
    log.info(
        f"Ronda {round_num} -- local OK  "
        f"acc={result['metrics']['accuracy']:.4f}  "
        f"auc={result['metrics']['auc']:.4f}"
    )
    _save_local_metrics(result, round_num)
    return result


def _send_global_weights(peer_ecc_url: str, peer_conn_uri: str,
                          weights_b64: str, round_num: int):
    import re as _re_gw
    peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
    if not peer_dataapp:
        log.error(f"No se pudo derivar DataApp URL de {peer_ecc_url}")
        return

    payload_size = len(weights_b64) if weights_b64 else 0

    # --- Canal WebSocket (data-plane): intentar primero si el túnel está activo ---
    _m_gw = _re_gw.search(r"worker(\d+)", peer_ecc_url) or _re_gw.search(r"worker(\d+)", peer_conn_uri)
    if _m_gw:
        _peer_wid = _m_gw.group(1)
        t_start = time.time()
        if _send_global_weights_ws(_peer_wid, weights_b64, round_num):
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos globales ronda {round_num} -> worker-{_peer_wid} "
                f"[OK WS]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("ws", elapsed_ms, payload_size, round_num, f"global->worker{_peer_wid}")
            return
        else:
            log.info(
                f"  [WS] Túnel no activo para worker-{_peer_wid} en ronda {round_num} "
                f"-- fallback HTTP DataApp-to-DataApp"
            )

    # --- Fallback: IDS Multipart o HTTP directo al DataApp del peer ---
    t_start = time.time()
    payload_dict = {
        "round"             : round_num,
        "global_weights_b64": weights_b64,
        "from_coordinator"  : INSTANCE_ID,
        "coordinator_ecc"   : f"https://{ECC_HOSTNAME}:8889/data",
        "coordinator_uri"   : CONNECTOR_URI,
    }
    try:
        if not ALLOW_IDS_BYPASS:
            payload_dict["type"] = "fl_global_weights"
            forward_target = f"{peer_dataapp}/data"
            _ids_send(
                forward_to_url       = forward_target,
                forward_to_connector = peer_conn_uri,
                message_type         = "ids:ArtifactRequestMessage",
                payload              = payload_dict,
                extra_header         = {"ids:contentVersion": f"fl_global_weights::{round_num}"},
            )
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos globales ronda {round_num} -> {forward_target} "
                f"[OK IDS fallback]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("http_ids", elapsed_ms, payload_size, round_num, f"global->{forward_target}")
        else:
            resp = requests.post(
                f"{peer_dataapp}/fl/receive-global-weights",
                json=payload_dict,
                timeout=60,
                verify=TLS_CERT,
            )
            resp.raise_for_status()
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos globales ronda {round_num} -> {peer_dataapp} "
                f"[OK HTTP fallback]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("http", elapsed_ms, payload_size, round_num, f"global->{peer_dataapp}")
    except Exception as exc:
        with _ws_perf_lock:
            _ws_perf_stats["http_failures"] += 1
        log.error(f"Error enviando pesos globales a {peer_dataapp}: {exc}")


def _send_local_weights(weights_b64: str, n_samples: int,
                         metrics: dict, round_num: int):
    if not coordinator_ecc_url:
        log.error("coordinator_ecc_url no definido")
        return

    coord_dataapp = _dataapp_url_from_ecc(coordinator_ecc_url)
    if not coord_dataapp:
        log.error(f"No se pudo derivar DataApp URL del coordinator: {coordinator_ecc_url}")
        return

    payload_size = len(weights_b64) if weights_b64 else 0
    _ws_payload = {
        "type"       : "fl_weights",
        "instance_id": INSTANCE_ID,
        "round"      : round_num,
        "weights_b64": weights_b64,
        "n_samples"  : n_samples,
        "metrics"    : metrics,
    }

    t_start = time.time()
    if _send_local_weights_ws(_ws_payload):
        elapsed_ms = (time.time() - t_start) * 1000
        log.info(
            f"  Pesos locales ronda {round_num} -> coordinator (WS) "
            f"[OK]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
        )
        _record_ws_perf("ws", elapsed_ms, payload_size, round_num, f"local-w{INSTANCE_ID}->coord")
        return

    t_start = time.time()
    try:
        if not ALLOW_IDS_BYPASS:
            if not coordinator_conn_uri:
                raise ValueError("coordinator_conn_uri no definido para enviar por IDS")
            forward_target = f"{coord_dataapp}/data"
            _ids_send(
                forward_to_url       = forward_target,
                forward_to_connector = coordinator_conn_uri,
                message_type         = "ids:ArtifactRequestMessage",
                payload              = _ws_payload,
                extra_header         = {"ids:contentVersion": f"fl_weights::{INSTANCE_ID}::{round_num}"},
            )
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos locales ronda {round_num} -> {forward_target} "
                f"[OK IDS fallback]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("ws_fallback", elapsed_ms, payload_size, round_num, f"local-w{INSTANCE_ID}->coord")
        else:
            resp = requests.post(
                f"{coord_dataapp}/fl/receive-local-weights",
                json=_ws_payload,
                timeout=60,
                verify=TLS_CERT,
            )
            resp.raise_for_status()
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos locales ronda {round_num} -> coordinator {coord_dataapp} "
                f"[OK]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("http", elapsed_ms, payload_size, round_num, f"local-w{INSTANCE_ID}->coord")
    except Exception as exc:
        with _ws_perf_lock:
            _ws_perf_stats["http_failures"] += 1
        log.error(f"Error enviando pesos locales a {coord_dataapp}: {exc}")


def _publish_fl_model_as_ids_resource(
    global_weights_b64: str,
    global_metrics: dict,
    n_rounds: int,
    peer_connector_uris: list | None = None,
):
    from requests.auth import HTTPBasicAuth
    basic_api = HTTPBasicAuth(API_USER, API_PASS)
    ecc_base  = f"https://{ECC_HOSTNAME}:8449"

    ts          = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    ts_readable = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    resource_id = f"https://w3id.org/idsa/autogen/textResource/fl_model_coordinator{INSTANCE_ID}_{ts}"
    artifact_id = f"http://w3id.org/engrd/connector/artifact/fl_model_final_coordinator{INSTANCE_ID}_{ts}"
    contract_id = f"https://w3id.org/idsa/autogen/contractOffer/{uuid.uuid4()}"
    repr_id     = f"https://w3id.org/idsa/autogen/representation/{uuid.uuid4()}"

    try:
        log.info("[publish] Obteniendo catalog ID del ECC...")
        sd       = requests.get(f"{ecc_base}/api/selfDescription/", verify=TLS_CERT, auth=basic_api, timeout=10).json()
        catalogs = sd.get("ids:resourceCatalog", [])
        if not catalogs:
            log.error("[publish] No se encontro ningun catalog")
            return
        catalog_id = catalogs[0].get("@id", "")

        log.info("[publish] Creando recurso IDS fl_model_final...")
        resource_body = {
            "@id"             : resource_id,
            "@type"           : "ids:TextResource",
            "ids:title"       : [{"@value": f"FL Global Model -- Coordinator {INSTANCE_ID} -- {ts_readable}",
                                  "@type": "http://www.w3.org/2001/XMLSchema#string"}],
            "ids:description" : [{"@value":
                f"Modelo federado final tras {n_rounds} rondas. "
                f"acc={global_metrics.get('accuracy','?')}  "
                f"auc={global_metrics.get('auc','?')}",
                "@type": "http://www.w3.org/2001/XMLSchema#string"
            }],
            "ids:keyword"     : [{"@value": "federated-learning", "@type": "http://www.w3.org/2001/XMLSchema#string"},
                                 {"@value": "fl-model",           "@type": "http://www.w3.org/2001/XMLSchema#string"}],
            "ids:version"     : f"round_{n_rounds}",
            "ids:language"    : [{"@id": "https://w3id.org/idsa/code/EN"}],
            "ids:contentType" : {"@id": "https://w3id.org/idsa/code/SCHEMA_DEFINITION"},
        }
        resp = requests.post(
            f"{ecc_base}/api/offeredResource/",
            headers={"catalog": catalog_id, "Content-Type": "application/json"},
            json=resource_body, verify=TLS_CERT, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando recurso: {resp.status_code}")
            return

        log.info("[publish] Anadiendo contrato restringido a peers...")
        # FIX 1: Usar snapshot inmutable de URIs aceptados en el momento del FL,
        # no el global PEER_CONNECTOR_URIS que puede haber cambiado (race condition).
        _authorized = peer_connector_uris if peer_connector_uris is not None else PEER_CONNECTOR_URIS
        if not _authorized:
            log.warning("[publish] peer_connector_uris vacio -- el contrato FL no tendra restriccion de peers")
        log.info(f"[publish] Peers autorizados en el contrato FL: {_authorized}")
        allowed_uris = [{"@value": u, "@type": "http://www.w3.org/2001/XMLSchema#anyURI"}
                        for u in _authorized]
        contract_body = {
            "@id"           : contract_id,
            "@type"         : "ids:ContractOffer",
            "ids:provider"  : {"@id": CONNECTOR_URI},
            "ids:permission": [{
                "@type"      : "ids:Permission",
                "@id"        : f"https://w3id.org/idsa/autogen/permission/{uuid.uuid4()}",
                "ids:action" : [{"@id": "https://w3id.org/idsa/code/USE"}],
                "ids:title"  : [{"@value": "FL Participants Only",
                                 "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:description": [{"@value": "connector-restricted-policy",
                                     "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:target" : {"@id": artifact_id},
                "ids:constraint": [{
                    "@type"             : "ids:Constraint",
                    "@id"               : f"https://w3id.org/idsa/autogen/constraint/{uuid.uuid4()}",
                    "ids:leftOperand"   : {"@id": "https://w3id.org/idsa/code/SYSTEM"},
                    "ids:operator"      : {"@id": "https://w3id.org/idsa/code/IN"},
                    "ids:rightOperand"  : allowed_uris,
                }],
            }],
            "ids:obligation": [], "ids:prohibition": [],
        }
        resp = requests.post(
            f"{ecc_base}/api/contractOffer/",
            headers={"resource": resource_id, "Content-Type": "application/json"},
            json=contract_body, verify=TLS_CERT, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando contrato: {resp.status_code}")
            return

        global _published_fl_contract
        _published_fl_contract = contract_body

        log.info("[publish] Anadiendo representacion con pesos finales...")
        repr_body = {
            "@id"          : repr_id,
            "@type"        : "ids:TextRepresentation",
            "ids:language" : {"@id": "https://w3id.org/idsa/code/EN"},
            "ids:instance" : [{
                "@type"           : "ids:Artifact",
                "@id"             : artifact_id,
                "ids:fileName"    : f"fl_global_model_coordinator{INSTANCE_ID}.json",
                "ids:byteSize"    : len(global_weights_b64),
                "ids:creationDate": {"@value": _now_iso(), "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"},
                "ids:checkSum"    : str(abs(hash(global_weights_b64)))[:16],
            }],
        }
        resp = requests.post(
            f"{ecc_base}/api/representation/",
            headers={"resource": resource_id, "Content-Type": "application/json"},
            json=repr_body, verify=TLS_CERT, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando representacion: {resp.status_code}")
            return

        log.info(
            f" Modelo FL publicado como recurso IDS en coordinator-{INSTANCE_ID}\n"
            f"   Resource  : {resource_id}\n"
            f"   Contrato  : {contract_id} (restringido a {len(_authorized)} peers)"
        )

    except Exception as exc:
        log.error(f"[publish] Error: {exc}", exc_info=True)


# =============================================================================
# Descubrimiento de workers via Broker IDS
# =============================================================================

def _get_all_local_csvs() -> list:
    """
    Devuelve [{filename, path, columns, rows, size_mb}] para todos los CSV disponibles en INPUT_DIR.
    Se usa tanto en el endpoint /dataset/all-columns como en el discovery del coordinator.
    """
    try:
        import pandas as pd
        files = sorted(f for f in os.listdir(INPUT_DIR) if f.endswith(".csv"))
        result = []
        for fname in files:
            fpath = os.path.join(INPUT_DIR, fname)
            try:
                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                df   = pd.read_csv(fpath, nrows=0, low_memory=False)
                cols = [c.lower().strip() for c in df.columns]
                
                # Fast row count
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    rows = sum(1 for _ in f) - 1
                    
                result.append({
                    "filename": fname, 
                    "path": fpath, 
                    "columns": cols,
                    "rows": max(0, rows),
                    "size_mb": round(size_mb, 2)
                })
                log.info(f"[dataset] {fname}: {len(cols)} columnas, {max(0, rows)} filas, {round(size_mb, 2)} MB")
            except Exception as e:
                log.warning(f"[dataset] No se pudo leer {fname}: {e}")
        return result
    except Exception as e:
        log.error(f"[dataset] Error listando CSVs en {INPUT_DIR}: {e}")
        return []


# =============================================================================
# LLM -- Recomendacion inteligente de datasets
# =============================================================================

def _llm_recommend_dataset(
    csvs: list,
    coordinator_cols: list | None = None,
    context: str = "",
    timeout: int = 180,
) -> dict | None:
    """
    Interroga al LLM configurado (Ollama local o OpenAI) para que elija
    el dataset mas adecuado para un entrenamiento de Federated Learning
    de deteccion de intrusiones de red.

    Parametros:
        csvs     : lista de {filename, columns, count} -- los candidatos
        context  : texto adicional de contexto (p.ej. worker de referencia)
        timeout  : segundos maximos de espera (default 30s)

    Devuelve:
        {"filename": str, "reasoning": str, "confidence": float}
        o None si el LLM no esta disponible (fallback a column-matching).
    """
    if not csvs:
        return None

    csv_descriptions = []
    for i, c in enumerate(csvs, 1):
        cols_preview = ", ".join(c.get("columns", []))
        n_cols = c.get("count", len(c.get("columns", [])))
        csv_descriptions.append(
            f"  [{i}] {c['filename']}\n"
            f"      Columnas ({n_cols}): {cols_preview}{''}"
        )

    datasets_text = "\n".join(csv_descriptions)
    context_text  = f"\nContexto adicional: {context}" if context else ""

    if coordinator_cols:
        coord_cols_str = ", ".join(sorted(coordinator_cols))
        task_instruction = (
            "Your task: evaluate the candidate datasets strictly by their column name overlap with the COORDINATOR reference columns.\n"
            "IGNORE filenames — they are misleading. ONLY the schema matters."
        )
        schema_instruction = (
            "CRITICAL RULE: Evaluate datasets STRICTLY by their column name overlap with the COORDINATOR reference columns.\n"
            f"COORDINATOR reference columns ({len(coordinator_cols)} total):\n  {coord_cols_str}\n\n"
            "HOW TO DECIDE:\n"
            "  1. Count exactly how many columns of each candidate match the COORDINATOR reference columns.\n"
            "  2. Select the candidate with the HIGHEST match count."
        )
    else:
        task_instruction = (
            "Your task: evaluate the candidate datasets based purely on their structural relevance to the given context.\n"
            "IGNORE filenames — use purely semantic NLP heuristics."
        )
        schema_instruction = (
            "HOW TO DECIDE:\n"
            "  - Select the dataset with the MOST RELEVANT schema constraints and features for the given analytical context.\n"
            "  - Give deep insight into why these selected columns are advantageous."
        )

    prompt = (
        "You are an AI assistant specialized in Federated Learning and dataset schema matching.\n"
        f"{task_instruction}\n\n"
        f"{context_text}\n"
        f"{schema_instruction}\n\n"
        "CANDIDATE datasets in this worker:\n"
        f"{datasets_text}\n\n"
        "RULES FOR RESPONSE:\n"
        "1. Do not use generic statements like 'The dataset with the highest match count'\n"
        "2. Break down your logical reasoning explicitly in your justification.\n"
        "3. Output MUST be ONLY a valid JSON object block. NO extra text, NO greetings.\n\n"
        "4. Always must mention which is the .csv that you have selected.\n\n"
        "```json\n"
        "{\n"
        "  \"filename\": \"<exact_name_from_list>\",\n"
        "  \"reasoning\": \"<Detailed paragraph including exact analysis and justification>\",\n"
        "  \"confidence\": <number between 0.0 and 1.0>\n"
        "}\n"
        "```"
    )

    log.info(
        f"[llm-recommend] Model={LLM_MODEL}  "
        f"Candidatos={[c['filename'] for c in csvs]}"
    )

    try:
        resp = requests.post(
            LLM_ENDPOINT,
            json={"model": LLM_MODEL, "prompt": prompt, "stream": False},
            timeout=timeout,
            verify=TLS_CERT,
        )
        resp.raise_for_status()
        raw_text = resp.json().get("response", "")

        import re as _re_llm
        # Extraer bloque JSON admitiendo razonamiento de texto alrededor
        match = _re_llm.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, _re_llm.DOTALL)
        if not match:
             match = _re_llm.search(r"(\{.*\})", raw_text, _re_llm.DOTALL)
             
        json_str = match.group(1) if match else raw_text.strip()
        result   = json.loads(json_str)

        filename   = result.get("filename", "")
        reasoning  = result.get("reasoning", "")
        confidence = float(result.get("confidence", 0.0))

        # Verificar que el filename devuelto existe en los candidatos
        valid_names = {c["filename"] for c in csvs}
        if filename not in valid_names:
            # Intento de correccion: buscar coincidencia parcial
            for vn in valid_names:
                if filename.lower() in vn.lower() or vn.lower() in filename.lower():
                    filename = vn
                    break
            else:
                log.warning(
                    f"[llm-recommend] LLM devolvio fichero desconocido: {filename!r} "
                    f"-- ignorando recomendacion (candidatos: {valid_names})"
                )
                return None

        log.info(
            f"[llm-recommend] [OK] Recomendacion: {filename!r} "
            f"(confianza={confidence:.0%})\n"
        )
        return {"filename": filename, "reasoning": reasoning, "confidence": confidence}

    except requests.exceptions.ConnectionError:
        log.warning(
            f"[llm-recommend] Error de conexion a Ollama en {LLM_ENDPOINT} "
            f"-- usando column-matching como fallback"
        )
        return None
    except requests.exceptions.Timeout:
        log.warning(f"[llm-recommend] Timeout ({timeout}s) esperando respuesta de Ollama")
        return None
    except Exception as e:
        log.warning(f"[llm-recommend] Error al consultar Ollama: {e}")
        return None


def _get_my_columns() -> list:
    """
    Devuelve las columnas del CSV local con mas columnas (referencia del coordinator).
    Si hay un unico CSV, lo usa directamente.
    """
    csvs = _get_all_local_csvs()
    if not csvs:
        log.error("[broker-discover] No hay CSVs disponibles en INPUT_DIR")
        return []
    best = max(csvs, key=lambda x: len(x["columns"]))
    log.info(
        f"[broker-discover] CSV de referencia: {best['filename']} "
        f"({len(best['columns'])} columnas): {best['columns'][:5]}..."
    )
    return best["columns"]


def _get_registered_connectors() -> list:
    query = """
    SELECT DISTINCT ?connector ?endpoint WHERE {
      GRAPH ?g {
        ?connector a <https://w3id.org/idsa/core/BaseConnector> .
        OPTIONAL { ?connector <https://w3id.org/idsa/core/hasDefaultEndpoint> ?endpoint . }
      }
    }
    """
    try:
        resp = requests.post(
            BROKER_SPARQL_URL,
            data={"query": query},
            headers={"Accept": "application/sparql-results+json"},
            timeout=10,
        )
        resp.raise_for_status()
        bindings = resp.json().get("results", {}).get("bindings", [])
        connectors = []
        for b in bindings:
            uri      = b.get("connector", {}).get("value", "")
            endpoint = b.get("endpoint",  {}).get("value", "")
            if uri and uri != CONNECTOR_URI:
                # El puerto 8889 (ECC-to-ECC) esta bloqueado en WS_ECC=true.
                # Se debe usar la API IDS publica en el 8449.
                connectors.append({"connector_uri": uri, "endpoint": endpoint})
        log.info(f"[broker-discover] {len(connectors)} conectores encontrados en el broker")
        return connectors
    except Exception as e:
        log.error(f"[broker-discover] Error consultando Fuseki: {e}")
        return []


def _get_peer_best_csv(ecc_url: str, connector_uri: str, my_set: set) -> tuple:
    """
    Escanea TODOS los recursos del catalogo IDS del peer y extrae
    su esquema semantico (CSV metadata representation) para elegir
    el que mayor coincidencia tenga con my_set.

    Devuelve (best_cols, real_uri, best_filename, best_ratio).
    """
    real_uri = connector_uri
    desc = {}
    try:
        # -- Obtener Catalogo del Peer via IDS DescriptionRequestMessage ---------
        # El puerto 8889 (ECC-to-ECC) puede estar bloqueado para DataApps por el
        # firewall del ECC. Si falla, usamos la REST API publica del peer (puerto 8449)
        # que esta accesible desde cualquier cliente en la red Docker.
        try:
            desc     = _ids_send(ecc_url, connector_uri, "ids:DescriptionRequestMessage")
            real_uri = desc.get("@id", "") or connector_uri
            log.info(f"[broker-discover] [OK] Catalogo IDS obtenido de {ecc_url}")
        except Exception as e:
            log.info(
                f"[broker-discover] Puerto ECC-to-ECC (8889) no accesible desde DataApp -- "
                f"usando REST API publica del peer (puerto 8449)"
            )
            # -- Fallback: REST API publica del ECC peer (puerto 8449) ---------
            try:
                from urllib.parse import urlparse
                from requests.auth import HTTPBasicAuth
                _hostname = urlparse(ecc_url).hostname
                _rest_url = f"https://{_hostname}:8449/api/selfDescription/"
                log.info(f"[broker-discover] GET {_rest_url}")
                _r = requests.get(
                    _rest_url, verify=TLS_CERT, timeout=10,
                    auth=HTTPBasicAuth(API_USER, API_PASS)
                )
                if _r.status_code == 200:
                    desc     = _r.json()
                    real_uri = desc.get("@id", "") or connector_uri
                    log.info(
                        f"[broker-discover] [OK] REST API OK para {_hostname} "
                        f"-- recursos: {len(desc.get('ids:resourceCatalog', []))}"
                    )
                else:
                    log.warning(
                        f"[broker-discover] REST API respondio HTTP {_r.status_code} "
                        f"para {_rest_url}"
                    )
            except Exception as e2:
                log.warning(
                    f"[broker-discover] Fallback REST tambien fallo para {ecc_url}: {e2}"
                )

        # -- Obtener lista completa de CSVs a traves del Information Model -------
        import re as _re
        all_csvs = []
        
        catalogs = desc.get("ids:resourceCatalog", [])
        for cat in catalogs:
            resources = cat.get("ids:offeredResource", [])
            for res in resources:
                meta_id = None
                # Buscamos la representacion semantica que contenga "meta_"
                for rep in res.get("ids:representation", []):
                    rep_uri = rep.get("@id", "")
                    if "meta_" in rep_uri:
                        meta_id = rep_uri
                        
                        # El catalogo base del TrueConnector ya incluye recursivamente las representaciones y sus descripciones
                        try:
                            desc_texts = rep.get("ids:description", [])
                            if desc_texts:
                                full_desc = desc_texts[0].get("@value", "")
                                # Extraemos usando Regex del texto semantico libre
                                m_n = _re.search(r"[-:]? Nombre de Fichero:\s*(.+?)\n", full_desc)
                                m_c = _re.search(r"[-:]? Nombres de Columnas:\s*(.+)", full_desc)
                                if m_n and m_c:
                                    fname = m_n.group(1).strip()
                                    cols_str = m_c.group(1).strip()
                                    cols_list = [c.strip() for c in cols_str.split(",") if c.strip()]
                                    all_csvs.append({"filename": fname, "columns": cols_list})
                        except Exception as e:
                            log.warning(f"[broker-discover] Error parseando MetadataRepresentation {meta_id}: {e}")
                            
                        break

        log.info(f"[broker-discover] {real_uri} -- {len(all_csvs)} CSV(s) descubiertos en catalogo IDS")

        if not all_csvs:
            log.warning(f"[broker-discover] No se pudo obtener ningun CSV de {real_uri}")
            return [], real_uri, None, 0.0, None, []

        best_cols, best_filename, best_ratio = [], None, 0.0
        all_evaluated = []
        for csv_info in all_csvs:
            fname  = csv_info.get("filename", "?")
            cols   = [c.lower().strip() for c in csv_info.get("columns", [])]
            p_set  = set(cols)
            common = my_set & p_set
            ratio  = len(common) / len(my_set) if my_set else 0.0
            is_best = ratio > best_ratio
            all_evaluated.append({
                "filename"         : fname,
                "ratio"            : ratio,
                "common_cols_count": len(common),
                "total_cols"       : len(my_set),
                "columns"          : cols,
                "count"            : len(cols),
            })
            log.info(
                f"[broker-discover]   {fname}: {len(p_set)} cols, "
                f"{len(common)} comunes, ratio={ratio:.0%}"
                + (" <- MEJOR" if is_best else "")
            )
            if is_best:
                best_ratio    = ratio
                best_cols     = cols
                best_filename = fname

        llm_candidates = [
            {"filename": c.get("filename", ""),
             "columns" : [col.lower().strip() for col in c.get("columns", [])],
             "count"   : len(c.get("columns", []))}
            for c in all_csvs
        ]
        llm_rec = _llm_recommend_dataset(
            llm_candidates,
            coordinator_cols=list(my_set),
            context=(
                f"Este es un entrenamiento de Federated Learning. El coordinator (worker-{INSTANCE_ID}) "
                f"ha proporcionado sus columnas de referencia. Selecciona el dataset del peer evaluado ({real_uri}) "
                f"que mejor coincida."
            ),
        )
        llm_rec_with_math = None

        if llm_rec:
            llm_filename   = llm_rec["filename"]
            llm_confidence = llm_rec["confidence"]
            llm_rec_with_math = dict(llm_rec)
            llm_rec_with_math["math_filename"] = best_filename

            if llm_confidence >= 0.80:
                # -- LLM tiene confianza suficiente -- validar ratio antes de sobrescribir --
                # El LLM puede hacer una eleccion semanticamente correcta pero cuyo schema
                # real no tiene columnas en comun con el coordinator. Verificamos el ratio
                # ANTES de sobrescribir: si no supera el umbral, la eleccion del LLM es
                # invalida para FL aunque la confianza sea alta.
                if llm_filename != best_filename:
                    llm_csv_info = next(
                        (c for c in all_csvs if c.get("filename") == llm_filename), None
                    )
                    llm_cols  = [col.lower().strip()
                                 for col in (llm_csv_info.get("columns", []) if llm_csv_info else [])]
                    llm_ratio = len(set(llm_cols) & my_set) / len(my_set) if my_set else 0.0

                    if llm_ratio >= MATCH_THRESHOLD:
                        # LLM elige un CSV con schema compatible -- puede sobrescribir
                        log.info(
                            f"[llm-recommend] [OK] LLM elige {llm_filename!r} "
                            f"(confianza={llm_confidence:.0%} >= 80%, ratio={llm_ratio:.0%} >= umbral) "
                            f"-- matematica sugeria {best_filename!r} -> LLM SOBRESCRIBE"
                        )
                        best_cols     = llm_cols
                        best_filename = llm_filename
                        best_ratio    = llm_ratio
                    else:
                        # LLM eligio un CSV cuyo schema es incompatible -- matematica gana
                        log.warning(
                            f"[llm-recommend] [WARN]  LLM eligio {llm_filename!r} "
                            f"(confianza={llm_confidence:.0%}) pero ratio={llm_ratio:.0%} < "
                            f"umbral {MATCH_THRESHOLD:.0%} -- schema incompatible para FL.\n"
                            f"  -> FALLBACK a matematica: {best_filename!r} ({best_ratio:.0%}).\n"
                            f"  (El LLM razono por nombre/semantica sin acceso al schema real)"
                        )
                else:
                    # LLM confirma la misma eleccion que la matematica
                    log.info(
                        f"[llm-recommend] [OK] LLM confirma la seleccion matematica: "
                        f"{best_filename!r} (confianza={llm_confidence:.0%}) -- LLM decide"
                    )
            else:
                # LLM sin confianza suficiente -- matematica gana
                log.info(
                    f"[llm-recommend] [WARN]  LLM sugiere {llm_filename!r} "
                    f"(confianza={llm_confidence:.0%} < 80%) -- "
                    f"FALLBACK a matematica: {best_filename!r} ({best_ratio:.0%})"
                )
        else:
            # LLM no disponible -- matematica es el fallback
            log.info(
                f"[llm-recommend] LLM no disponible -- "
                f"FALLBACK a seleccion matematica: {best_filename!r} ({best_ratio:.0%})"
            )

        return best_cols, real_uri, best_filename, best_ratio, llm_rec_with_math, all_evaluated

    except Exception as e:
        log.warning(f"[broker-discover] Error escaneando CSVs de {connector_uri}: {e}")
        return [], real_uri, None, 0.0, None, []


def _ecc_url_from_connector_uri(connector_uri: str, endpoint: str) -> str:
    from urllib.parse import urlparse
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname:
            return f"https://{parsed.hostname}:8889/data"
    
    # El regex rigido fue eliminado para favorecer la parametrizacion pura del DAPS/Broker.
    return ""


MATCH_THRESHOLD = 0.80  # 80% de coincidencia minima de columnas


def _discover_compatible_workers(my_columns: list) -> list:
    connectors = _get_registered_connectors()
    if not connectors:
        log.warning("[broker-discover] No hay conectores en el broker")
        return []

    compatible = []
    my_set     = set(c.lower() for c in my_columns)
    my_ecc_url = f"https://{ECC_HOSTNAME}:8889/data"

    for conn in connectors:
        uri      = conn["connector_uri"]
        endpoint = conn["endpoint"]
        ecc_url  = _ecc_url_from_connector_uri(uri, endpoint)

        if not ecc_url:
            log.warning(f"[broker-discover] No se pudo derivar ECC URL para {uri}")
            continue

        # Saltar propio coordinator (por URI o por ECC URL) -- dinamico via ECC_HOSTNAME
        if uri == CONNECTOR_URI or ecc_url == my_ecc_url:
            log.info(f"[broker-discover] Saltando propio connector: {uri}")
            continue

        log.info(f"[broker-discover] Evaluando {uri} -- escaneando todos sus CSVs...")
        best_cols, real_uri, best_filename, best_ratio, llm_rec, all_evaluated = _get_peer_best_csv(
            ecc_url, uri, my_set
        )
        if real_uri != uri:
            log.info(f"[broker-discover] URI broker {uri!r} -> URI IDS real {real_uri!r}")

        common = my_set & set(c.lower() for c in best_cols)
        log.info(
            f"[broker-discover] {real_uri}\n"
            f"  mejor CSV: {best_filename!r}  comunes: {len(common)}/{len(my_set)}  "
            f"ratio: {best_ratio:.0%}  (umbral: {MATCH_THRESHOLD:.0%})  "
            + ("[OK] COMPATIBLE" if best_ratio >= MATCH_THRESHOLD else "OK DESCARTADO")
        )

        if best_ratio >= MATCH_THRESHOLD:
            compatible.append({
                "connector_uri"  : real_uri,
                "ecc_url"        : ecc_url,
                "common_cols"    : sorted(common),
                "match_ratio"    : round(best_ratio, 3),
                "selected_csv"   : best_filename,
                "math_filename"  : llm_rec.get("math_filename") if llm_rec else best_filename,
                "llm_recommended": llm_rec.get("filename") if llm_rec else None,
                "llm_reasoning"  : llm_rec.get("reasoning") if llm_rec else None,
                "llm_confidence" : llm_rec.get("confidence") if llm_rec else 0.0,
                "llm_model"      : LLM_MODEL,
                "all_evaluated"  : all_evaluated,
            })

    log.info(
        f"[broker-discover] {len(compatible)} workers compatibles "
        f"(umbral {MATCH_THRESHOLD:.0%})"
    )
    return compatible


def _run_fl(n_rounds: int, round_timeout: int, min_workers: int,
             algo_bytes: bytes = None, config_bytes: bytes = None):
    global fl_state
    # Evita race condition si PEER_CONNECTOR_URIS cambia durante el entrenamiento.
    _peers_snapshot = list(PEER_CONNECTOR_URIS)

    with _fl_lock:
        fl_state.update({"status": "running", "current_round": 0,
                          "total_rounds": n_rounds, "history": []})

    _notify_ws_clients({
        "event": "fl_started",
        "total_rounds": n_rounds,
        "min_workers": min_workers,
        "status": "running"
    })

    global_weights_b64 = None
    best_accuracy      = -1.0
    best_weights_b64   = None
    best_metrics       = None
    best_round         = -1
    model_path         = os.path.join(OUTPUT_DIR, "global_model.json")

    if os.path.exists(model_path):
        try:
            with open(model_path) as f:
                global_weights_b64 = json.load(f).get("weights_b64")
            log.info("Checkpoint previo cargado")
        except Exception:
            pass

    for round_num in range(1, n_rounds + 1):
        log.info(f"{'='*56}")
        log.info(f"  RONDA {round_num}/{n_rounds}  [coordinator-{INSTANCE_ID}]")
        log.info(f"{'='*56}")

        with _fl_lock:
            fl_state["current_round"] = round_num
            fl_state["status"]        = f"round_{round_num}"

        _notify_ws_clients({
            "event": "round_started",
            "round": round_num,
            "total_rounds": n_rounds,
            "status": f"round_{round_num}"
        })

        _round_weights.clear()
        t0 = time.time()

        if algo_bytes:
            log.info(f"[ronda {round_num}] Distribuyendo algorithm.py + fl_config.json a peers...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(PEER_ECC_URLS), 1)) as ex:
                _peer_csvs = PEER_SELECTED_CSVS if PEER_SELECTED_CSVS else [None] * len(PEER_ECC_URLS)
                futures = {
                    ex.submit(_negotiate_and_send_algorithm, p, u, algo_bytes,
                              config_bytes or b"{}", csv,
                              next((w.get("transfer_contract") for w in _accepted_workers if w["connector_uri"] == u), None)
                              ): p
                    for p, u, csv in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS, _peer_csvs)
                }
                for fut in concurrent.futures.as_completed(futures):
                    peer = futures[fut]
                    try:
                        ok = fut.result()
                        log.info(f"  [ronda {round_num}] -> {peer}: {'[OK]' if ok else 'OK'}")
                    except Exception as exc:
                        log.error(f"  [ronda {round_num}] -> {peer}: OK {exc}")

        if algo_bytes:
            time.sleep(3)

        # -- Enviar pesos globales: WS high-speed primero, HTTP como fallback --
        import re as _re_gw
        for peer_url, peer_uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
            _m_gw  = _re_gw.search(r"worker(\d+)", peer_url)
            _wid_gw = _m_gw.group(1) if _m_gw else None
            _t0_gw  = time.time()
            _used_ws_gw = bool(_wid_gw and _send_global_weights_ws(
                _wid_gw, global_weights_b64, round_num
            ))
            if _used_ws_gw:
                _ms_gw = (time.time() - _t0_gw) * 1000
                _kb_gw = len(global_weights_b64) / 1024 if global_weights_b64 else 0
                log.info(
                    f"  Pesos globales ronda {round_num} "
                    f"-> be-dataapp-worker{_wid_gw}:8500 "
                    f"[OK]  {_kb_gw:.0f} KB en {_ms_gw:.1f}ms [WS]"
                )
                _record_ws_perf(
                    "ws", _ms_gw, len(global_weights_b64 or ""),
                    round_num, f"global->worker{_wid_gw}"
                )
            else:
                threading.Thread(
                    target=_send_global_weights,
                    args=(peer_url, peer_uri, global_weights_b64, round_num),
                    daemon=True,
                ).start()

        try:
            local = _train_local(global_weights_b64, round_num)
            with _round_lock:
                _round_weights[INSTANCE_ID] = {
                    "weights_b64": local["weights_b64"],
                    "n_samples"  : local["n_samples"],
                    "metrics"    : local["metrics"],
                }
        except Exception as exc:
            log.error(f"Error en entrenamiento local ronda {round_num}: {exc}")

        expected = len(PEER_ECC_URLS) + 1
        deadline = time.time() + round_timeout
        while time.time() < deadline:
            with _round_lock:
                if len(_round_weights) >= expected:
                    break
            log.info(f"Esperando pesos... {len(_round_weights)}/{expected}")
            time.sleep(2)

        with _round_lock:
            results = list(_round_weights.values())

        if len(results) < min_workers:
            log.error(f"Ronda {round_num}: solo {len(results)}/{min_workers} workers respondieron -- abortando")
            with _fl_lock:
                fl_state["status"] = "failed"
            _notify_ws_clients({
                "event": "fl_failed",
                "round": round_num,
                "reason": "min_workers_not_reached",
                "status": "failed"
            })
            return

        global_weights_b64 = _weights_to_b64(_fedavg(results))
        elapsed            = round(time.time() - t0, 2)
        total_samples      = sum(r["n_samples"] for r in results)

        global_metrics = {}
        for key in ("loss", "accuracy", "auc", "precision", "recall"):
            try:
                global_metrics[key] = round(
                    sum(r["metrics"][key] * r["n_samples"] / total_samples
                        for r in results), 6
                )
            except KeyError:
                pass

        with _fl_lock:
            fl_state["history"].append({
                "round"          : round_num,
                "workers_ok"     : len(results),
                "total_samples"  : total_samples,
                "elapsed_seconds": elapsed,
                "global_metrics" : global_metrics,
            })
            _round_snapshot = dict(fl_state)

        # Notificar a clientes WebSocket conectados
        _notify_ws_clients({
            "event"         : "round_completed",
            "round"         : round_num,
            "total_rounds"  : n_rounds,
            "workers_ok"    : len(results),
            "total_samples" : total_samples,
            "elapsed_seconds": elapsed,
            "global_metrics": global_metrics,
            "status"        : _round_snapshot["status"],
        })

        acc = global_metrics.get("accuracy", 0)
        if acc > best_accuracy:
            best_accuracy = acc
            best_weights_b64 = global_weights_b64
            best_metrics = global_metrics
            best_round = round_num

            with open(model_path, "w") as f:
                json.dump({"round": best_round, "weights_b64": best_weights_b64, "metrics": best_metrics}, f)
            log.info(f"\u2728 Nueva mejor ronda encontrada ({best_round}) con acc={best_accuracy} \u2014 guardada en disco")

        log.info(
            f"Ronda {round_num} OK en {elapsed}s  "
            f"acc={global_metrics.get('accuracy','?')}  "
            f"auc={global_metrics.get('auc','?')}"
        )

    with _fl_lock:
        fl_state["status"] = "completed"

    # Notificar fin del FL a clientes WebSocket
    _notify_ws_clients({
        "event"      : "fl_completed",
        "status"     : "completed",
        "n_rounds"   : n_rounds,
        "best_round" : best_round,
        "best_metrics": best_metrics,
    })

    with open(os.path.join(OUTPUT_DIR, "fl_results.json"), "w") as f:
        json.dump(fl_state["history"], f, indent=2)

    log.info(f"[OK] FL completado -- {n_rounds} rondas. Mejor ronda: {best_round}")

    try:
        last_metrics = best_metrics if best_metrics else (fl_state["history"][-1]["global_metrics"] if fl_state["history"] else {})
        _publish_fl_model_as_ids_resource(
            best_weights_b64 or global_weights_b64,
            last_metrics,
            best_round if best_round > 0 else n_rounds,
            peer_connector_uris=_peers_snapshot
        )
    except Exception as exc:
        log.error(f"Error publicando modelo IDS: {exc}")

# =============================================================================
# POST /data -- mensajes IDS entrantes del ECC
# =============================================================================

@app.post("/data")
async def ids_data(request: Request):
    global is_coordinator, coordinator_ecc_url, coordinator_conn_uri

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")
    log.info(f"[/data] IN  Content-Type: {content_type}")

    header_val  = None
    payload_val = None

    if "multipart" in content_type:
        try:
            decoder = MultipartDecoder(raw_body, content_type)
            for part in decoder.parts:
                disp = part.headers.get(b"Content-Disposition", b"").decode("utf-8", errors="ignore")
                text = part.content.decode("utf-8", errors="ignore").strip()
                if "\n\n" in text:
                    text = text.split("\n\n", 1)[-1].strip()
                if 'name="header"' in disp:
                    header_val = text
                elif 'name="payload"' in disp:
                    payload_val = text
                    log.info(f"[/data] payload_val (100 chars): {repr(payload_val[:100])}")
                elif not header_val and (text.startswith("{") or text.startswith("[")):
                    header_val = text
        except Exception as e:
            log.error(f"[/data] Error parseando multipart: {e}")
            return JSONResponse(status_code=400, content={"error": f"multipart parse error: {e}"})
    else:
        try:
            form        = await request.form()
            header_val  = form.get("header")
            payload_val = form.get("payload")
        except Exception as e:
            log.error(f"[/data] Error leyendo form: {e}")

    if not header_val:
        return JSONResponse(status_code=400, content={"error": "missing IDS header field"})

    mensaje = json.loads(header_val)
    tipo    = mensaje.get("@type", "")
    log.info(f"<- Mensaje IDS: {tipo}")

    try:
        self_desc    = _get_self_description()
        connector_id = self_desc.get("@id", CONNECTOR_URI)
    except Exception:
        connector_id = CONNECTOR_URI
        self_desc    = {"@id": connector_id}

    from requests.auth import HTTPBasicAuth
    basic_api = HTTPBasicAuth(API_USER, API_PASS)

    def _resp(msg_type, extra_id, extra=None):
        h = _base_response_header(mensaje, msg_type, extra_id, connector_id)
        if extra:
            h.update(extra)
        return h

    if tipo == "ids:DescriptionRequestMessage":
        if "ids:requestedElement" not in mensaje:
            body_resp = self_desc
        else:
            url  = f"https://{ECC_HOSTNAME}:8449/api/offeredResource/"
            hdrs = {"resource": mensaje["ids:requestedElement"]["@id"]}
            body_resp = requests.get(url, headers=hdrs, verify=TLS_CERT, auth=basic_api, timeout=10).json()

        return _multipart_response(
            _resp("ids:DescriptionResponseMessage", "descriptionResponseMessage"),
            json.dumps(body_resp)
        )

    elif tipo == "ids:ContractRequestMessage":
        payload_dict      = json.loads(payload_val) if payload_val else {}
        contract_offer_id = payload_dict.get("@id", "")

        consumer_uri = mensaje.get("ids:issuerConnector", {}).get("@id", "")

        if FL_OPT_OUT:
            log.warning(
                f"[ContractRequest] PARTICIPACION DENEGADA -- "
                f"worker-{INSTANCE_ID} ha optado por no compartir datos (Soberania)\n"
                f"  Solicitante: {consumer_uri!r}"
            )
            rejection_header = _resp(
                "ids:RejectionMessage", "rejectionMessage",
                {"ids:rejectionReason": {"@id": "https://w3id.org/idsa/code/NOT_AUTHORIZED"}}
            )
            return _multipart_response(rejection_header, json.dumps({
                "status"  : "rejected",
                "reason"  : "fl_opt_out",
                "worker"  : INSTANCE_ID,
                "message" : (
                    f"Worker {INSTANCE_ID} ha optado por no participar voluntariamente en el entrenamiento del FL."
                )
            }))

        # -- Verificar si el consumer esta autorizado en el contrato FL restringido --
        # El modelo FL publicado usa connector-restricted-policy con ids:constraint IN [peers].
        # Si el solicitante no esta en esa lista, rechazamos con unauthorized_consumer.
        if _published_fl_contract and consumer_uri:
            _perms      = _published_fl_contract.get("ids:permission", [])
            _perm       = (_perms or [{}])[0]
            _desc_list  = _perm.get("ids:description", [{}])
            _desc_val   = (_desc_list[0].get("@value", "") if _desc_list else "")
            if _desc_val == "connector-restricted-policy":
                _constraints  = _perm.get("ids:constraint", [])
                _constraint   = (_constraints or [{}])[0]
                _allowed_uris = [
                    v.get("@value") or v.get("@id", "")
                    for v in _constraint.get("ids:rightOperand", [])
                ]
                if _allowed_uris and consumer_uri not in _allowed_uris:
                    log.warning(
                        f"[ContractRequest] ACCESO DENEGADO -- {consumer_uri!r} "
                        f"no esta en la lista de peers autorizados del modelo FL.\n"
                        f"  Autorizados: {_allowed_uris}"
                    )
                    _rej_header = _resp(
                        "ids:RejectionMessage", "rejectionMessage",
                        {"ids:rejectionReason": {"@id": "https://w3id.org/idsa/code/NOT_AUTHORIZED"}}
                    )
                    return _multipart_response(_rej_header, json.dumps({
                        "status"  : "rejected",
                        "reason"  : "unauthorized_consumer",
                        "consumer": consumer_uri,
                        "message" : (
                            f"Consumer {consumer_uri!r} is not in the authorized peer list "
                            "for this FL model contract (connector-restricted-policy)."
                        ),
                    }))

        if not contract_offer_id:
            try:
                sd        = _get_self_description()
                catalogs  = sd.get("ids:resourceCatalog", [{}])
                resource  = (catalogs[0].get("ids:offeredResource", [{}]) or [{}])[0]
                contract  = (resource.get("ids:contractOffer", [{}]) or [{}])[0]
                contract_offer_id = contract.get("@id", "")
            except Exception as e:
                log.error(f"[ContractRequest] No se pudo inferir contract_id: {e}")

        url      = f"https://{ECC_HOSTNAME}:8449/api/contractOffer/"
        hdrs     = {"contractOffer": contract_offer_id}
        contrato = requests.get(url, headers=hdrs, verify=TLS_CERT, auth=basic_api, timeout=10).json()

        contrato["@type"]        = "ids:ContractAgreement"
        contrato["ids:consumer"] = mensaje["ids:issuerConnector"]
        orig_id = contrato.get("@id", "")
        if "contractOffer" in orig_id or not orig_id:
            import uuid as _uuid
            contrato["@id"] = f"https://w3id.org/idsa/autogen/contractAgreement/{_uuid.uuid4()}"

        return _multipart_response(
            _resp("ids:ContractAgreementMessage", "contractAgreementMessage"),
            json.dumps(contrato)
        )

    elif tipo == "ids:ContractAgreementMessage":
        return _multipart_response(
            _resp("ids:MessageProcessedNotificationMessage", "messageProcessedNotificationMessage")
        )

    elif tipo == "ids:ArtifactRequestMessage":
        try:
            payload_dict = json.loads(payload_val) if payload_val else {}
        except Exception:
            payload_dict = {}

        # -- FIX BUG 1: Solo parsear ids:contentVersion como fl_algorithm
        #    si NO es fl_global_weights:: ni fl_weights::
        #    Antes este bloque asumia que CUALQUIER contentVersion era fl_algorithm,
        #    lo que causaba que los pesos globales sobreescribieran algorithm.py
        #    y convirtieran al worker en coordinator erroneamente.
        if not payload_dict.get("type"):
            content_version = mensaje.get("ids:contentVersion", "")
            if content_version and isinstance(content_version, str):
                if (content_version.startswith("fl_global_weights::") or
                        content_version.startswith("fl_weights::")):
                    # El tipo y datos vienen del payload JSON -- parsear explicitamente
                    log.info(f"[ArtifactRequest] ids:contentVersion={content_version[:40]}... -- parseando payload JSON")
                    if payload_val:
                        try:
                            payload_dict = json.loads(payload_val)
                            log.info(f"[ArtifactRequest] payload_dict parseado desde payload_val: type={payload_dict.get('type','?')!r}")
                        except Exception as _pe:
                            log.error(f"[ArtifactRequest] Error parseando payload_val para {content_version[:30]}: {_pe}")
                    # Si payload_val esta vacio o fallo el parse, intentar extraer
                    # el payload serializado en base64 dentro del contentVersion
                    # (canal de respaldo usado por _send_local_weights y _send_global_weights)
                    if not payload_dict.get("type"):
                        _cv = content_version
                        # fl_weights::workerX::roundN::payload::<b64>
                        if "::payload::" in _cv:
                            try:
                                _b64_payload = _cv.split("::payload::", 1)[1]
                                payload_dict = json.loads(base64.b64decode(_b64_payload).decode())
                                log.info(f"[ArtifactRequest] payload recuperado desde contentVersion b64: type={payload_dict.get('type','?')!r}")
                            except Exception as _e:
                                log.error(f"[ArtifactRequest] Error decodificando payload b64 de contentVersion: {_e}")
                    # Ultimo recurso: inferir solo el tipo desde el prefijo
                    if not payload_dict.get("type"):
                        if content_version.startswith("fl_global_weights::"):
                            payload_dict["type"] = "fl_global_weights"
                            log.warning("[ArtifactRequest] type inferido desde contentVersion: fl_global_weights (payload vacio)")
                        elif content_version.startswith("fl_weights::"):
                            payload_dict["type"] = "fl_weights"
                            log.warning("[ArtifactRequest] type inferido desde contentVersion: fl_weights (payload vacio -- pesos perdidos)")
                else:
                    # Es fl_algorithm SOLO si parece payload IDS-FL valido:
                    # el codec IDS-FL incluye siempre al menos "||from_coordinator"
                    # o "||fl_config::" o un base64 largo (> 50 chars) sin "::" adicionales.
                    # Si el ECC anade su propia value (p.ej. una URI o token corto),
                    # lo ignoramos y dejamos artifact_type vacio -> modo fuente.
                    _looks_like_fl_algo = (
                        "||from_coordinator" in content_version
                        or "||fl_config::" in content_version
                        or (len(content_version) > 100 and "::" not in content_version[:20])
                    )
                    if _looks_like_fl_algo:
                        from_coord = False
                        if "||from_coordinator::1" in content_version:
                            content_version = content_version.replace("||from_coordinator::1", "")
                            from_coord = True
                        if "||fl_config::" in content_version:
                            algo_part, config_part = content_version.split("||fl_config::", 1)
                        else:
                            algo_part, config_part = content_version, None
                        payload_dict = {
                            "type"            : "fl_algorithm",
                            "content"         : algo_part,
                            "config"          : config_part,
                            "from_coordinator": from_coord,
                    }
                    log.info(f"[ArtifactRequest] fl_algorithm recuperado desde ids:contentVersion | config={'present' if config_part else 'absent'} | from_coordinator={from_coord}")

        # Fallback: intentar recuperar desde ids:securityToken.ids:tokenValue
        if not payload_dict.get("type"):
            token     = mensaje.get("ids:securityToken", {})
            token_val = token.get("ids:tokenValue", "") if isinstance(token, dict) else ""
            import base64 as _b64
            for prefix in ("fl_algorithm", "fl_global_weights", "fl_weights"):
                if token_val.startswith(f"{prefix}::"):
                    rest = token_val[len(f"{prefix}::"):]
                    from_coord  = rest.startswith("from_coordinator::")
                    payload_b64 = rest[len("from_coordinator::"):] if from_coord else rest

                    if prefix == "fl_algorithm":
                        if "||fl_config::" in payload_b64:
                            algo_part, config_part = payload_b64.split("||fl_config::", 1)
                        else:
                            algo_part, config_part = payload_b64, None
                        payload_dict = {
                            "type"            : "fl_algorithm",
                            "content"         : algo_part,
                            "config"          : config_part,
                            "from_coordinator": from_coord,
                        }
                        log.info(f"[ArtifactRequest] fl_algorithm recuperado desde tokenValue | config={'present' if config_part else 'absent'}")
                    else:
                        try:
                            payload_dict = json.loads(_b64.b64decode(payload_b64).decode())
                        except Exception as e:
                            log.error(f"[ArtifactRequest] Error decodificando tokenValue {prefix}: {e}")
                    break

        # Intentar extraer config del payload JSON si falta
        if payload_dict.get("type") == "fl_algorithm" and not payload_dict.get("config"):
            if payload_val:
                try:
                    pv = json.loads(payload_val)
                    if pv.get("config"):
                        payload_dict["config"] = pv["config"]
                except Exception:
                    pass

        artifact_type = payload_dict.get("type", "")
        log.info(f"[ArtifactRequest] artifact_type={artifact_type!r}")
        resp_h = _resp(
            "ids:ArtifactResponseMessage", "artifactResponseMessage",
            {"ids:transferContract": mensaje.get("ids:transferContract", {})}
        )

        # fl_weights -- pesos locales de un worker -> coordinator acumula
        if artifact_type == "fl_weights":
            sender      = payload_dict.get("instance_id", "?")
            round_num   = payload_dict.get("round", 0)
            weights_b64 = payload_dict.get("weights_b64")
            n_samples   = payload_dict.get("n_samples")
            metrics     = payload_dict.get("metrics")
            log.info(f"Pesos de worker-{sender} (ronda {round_num})")
            if not weights_b64 or n_samples is None or metrics is None:
                log.error(
                    f"[fl_weights] Payload incompleto desde worker-{sender} ronda {round_num} -- "
                    f"weights={'present' if weights_b64 else 'MISSING'}  "
                    f"n_samples={n_samples}  metrics={'present' if metrics else 'MISSING'}"
                )
                return _multipart_response(resp_h, json.dumps({
                    "status": "error",
                    "reason": "incomplete_payload",
                    "from"  : sender,
                }))
            with _round_lock:
                _round_weights[sender] = {
                    "weights_b64": weights_b64,
                    "n_samples"  : n_samples,
                    "metrics"    : metrics,
                }
            log.info(f"[fl_weights] [OK] Pesos de worker-{sender} ronda {round_num} acumulados ({len(_round_weights)} total)")
            return _multipart_response(resp_h, json.dumps({"status": "weights_received", "from": sender}))

        # fl_global_weights -- worker entrena localmente
        if artifact_type == "fl_global_weights":
            round_num          = payload_dict.get("round", 1)
            global_weights_b64 = payload_dict.get("global_weights_b64")

            if not coordinator_ecc_url:
                # Intentar desde payload JSON primero
                _coord_ecc  = payload_dict.get("coordinator_ecc")
                _coord_uri  = payload_dict.get("coordinator_uri")
                # Fallback: inferir desde issuerConnector del mensaje IDS (siempre disponible)
                if not _coord_ecc:
                    _issuer = mensaje.get("ids:issuerConnector", {})
                    if isinstance(_issuer, dict):
                        _issuer_id = _issuer.get("@id", "")
                    else:
                        _issuer_id = str(_issuer)
                    import re as _re2
                    m = _re2.search(r"worker(\d+)", _issuer_id)
                    if m:
                        cid = m.group(1)
                        _coord_ecc = f"https://ecc-worker{cid}:8889/data"
                        _coord_uri = f"http://w3id.org/engrd/connector/worker{cid}"
                        log.info(f"[fl_global_weights] coordinator_ecc_url inferido del issuerConnector: {_coord_ecc}")
                coordinator_ecc_url  = _coord_ecc
                coordinator_conn_uri = _coord_uri
                _start_worker_ws_client()

            def _train_and_reply():
                try:
                    deadline_algo = time.time() + 15
                    while time.time() < deadline_algo:
                        if os.path.exists(ALGO_IDS_PATH) or os.path.exists(ALGO_BAKED_PATH):
                            break
                        log.info(f"[fl_global_weights] Esperando algorithm.py... (ronda {round_num})")
                        time.sleep(1)
                    else:
                        log.error(f"[fl_global_weights] algorithm.py no disponible tras 15s -- ronda {round_num} abortada")
                        return
                    result = _train_local(global_weights_b64, round_num, _my_selected_csv)
                    _send_local_weights(result["weights_b64"], result["n_samples"],
                                        result["metrics"], round_num)
                except Exception as exc:
                    log.error(f"Error ronda {round_num}: {exc}")

            threading.Thread(target=_train_and_reply, daemon=True).start()
            return _multipart_response(resp_h, json.dumps({"status": "training_started", "round": round_num}))

        # fl_algorithm -- guardar algorithm.py + fl_config.json
        if artifact_type == "fl_algorithm":
            content_b64 = payload_dict.get("content", "")
            config_b64  = payload_dict.get("config")

            try:
                algo_bytes = base64.b64decode(content_b64)
            except Exception:
                algo_bytes = content_b64.encode() if isinstance(content_b64, str) else b""

            _save_algorithm(algo_bytes)

            if config_b64:
                try:
                    config_bytes = base64.b64decode(config_b64)
                    _save_config(config_bytes)
                except Exception as e:
                    log.warning(f"No se pudo guardar fl_config.json: {e}")
            else:
                log.warning("fl_config.json no recibido -- usando valores por defecto")

            if payload_dict.get("from_coordinator"):
                global _my_selected_csv
                sel_csv = payload_dict.get("selected_csv")
                if sel_csv:
                    full_path = os.path.join(INPUT_DIR, sel_csv)
                    if os.path.exists(full_path):
                        _my_selected_csv = full_path
                        log.info(
                            f"[fl_algorithm] CSV seleccionado por coordinator: "
                            f"{sel_csv} -> {full_path}"
                        )
                    else:
                        log.warning(
                            f"[fl_algorithm] CSV '{sel_csv}' no encontrado en {INPUT_DIR}"
                            f" -- se usara seleccion automatica"
                        )
                log.info(f"OK algorithm.py + config recibidos del coordinator -- worker-{INSTANCE_ID} = WORKER")
            else:
                is_coordinator = True
                log.info(f"~... algorithm.py + config recibidos desde Postman -- worker-{INSTANCE_ID} = COORDINATOR")

            cfg = _load_fl_config()
            return _multipart_response(
                resp_h,
                json.dumps({
                    "status"      : "everything_received",
                    "coordinator" : INSTANCE_ID,
                    "fl_config"   : {
                        "rounds"       : cfg["rounds"],
                        "round_timeout": cfg["round_timeout"],
                        "epochs"       : cfg["epochs"],
                        "batch_size"   : cfg["batch_size"],
                        "learning_rate": cfg["learning_rate"],
                    },
                    "next_step": "POST /fl/start to begin training"
                }),
            )

        # -- Modo fuente: servir algorithm.py a otro coordinator que lo solicita --
        # Cuando el artifact_type es desconocido/vacio y el artefacto solicitado
        # no es de tipo fl_weights/fl_global_weights, este DataApp actua como
        # PROVEEDOR y devuelve su algorithm.py (baked o recibido previamente).
        req_art_hdr = mensaje.get("ids:requestedArtifact", {})
        req_art_id  = req_art_hdr.get("@id", "") if isinstance(req_art_hdr, dict) else str(req_art_hdr)
        is_algo_request = (
            not artifact_type
            and req_art_id
            and "fl_weights" not in req_art_id
            and "fl_global" not in req_art_id
        )

        if is_algo_request:
            algo_src = _algo_path()
            if os.path.exists(algo_src):
                try:
                    with open(algo_src, "rb") as f:
                        algo_bytes_src = f.read()
                    algo_b64_src = base64.b64encode(algo_bytes_src).decode()

                    config_b64_src = None
                    if os.path.exists(CONFIG_PATH):
                        with open(CONFIG_PATH, "rb") as f:
                            config_b64_src = base64.b64encode(f.read()).decode()

                    requester = mensaje.get("ids:issuerConnector", {}).get("@id", "?")
                    log.info(
                        f"[ArtifactRequest SOURCE] Sirviendo algorithm.py "
                        f"({len(algo_bytes_src)} bytes) -> {requester}"
                    )
                    return _multipart_response(resp_h, json.dumps({
                        "type"    : "fl_algorithm",
                        "filename": "algorithm.py",
                        "content" : algo_b64_src,
                        "config"  : config_b64_src,
                        "source"  : INSTANCE_ID,
                    }))
                except Exception as e:
                    log.error(f"[ArtifactRequest SOURCE] Error sirviendo algoritmo: {e}")
            else:
                log.error(f"[ArtifactRequest SOURCE] algorithm.py no encontrado en {algo_src}")

        log.warning(f"Tipo de artefacto desconocido: {artifact_type!r}")
        return _multipart_response(resp_h, json.dumps({"status": "unknown_artifact_type"}))

    log.warning(f"Mensaje no manejado: {tipo}")
    return JSONResponse(status_code=200, content={"status": "ignored", "type": tipo})


@app.get("/data")
async def ids_data_get():
    return {"instance": INSTANCE_ID, "role": "coordinator" if is_coordinator else "worker"}


# =============================================================================
# Endpoints de control y monitorizacion
# =============================================================================

# =============================================================================
# POST /fl/fetch-algorithm -- coordinator solicita el algoritmo via IDS
# =============================================================================

@app.post("/fl/fetch-algorithm")
async def fl_fetch_algorithm(request: Request):
    """
    El worker que quiere ser coordinator llama a este endpoint.
    Ejecuta el handshake IDS completo contra el ECC fuente para obtener
    algorithm.py + fl_config.json y activar el rol coordinator.

    Por defecto (body vacio) hace un **IDS self-fetch**:
      el coordinator actua como CONSUMER Y PROVIDER de su propio ECC.
      DescriptionRequestMessage -> ContractRequestMessage
      -> ContractAgreementMessage -> ArtifactRequestMessage
      El ECC reenvia al /data local que sirve el algorithm.py baked.

    Body JSON (todos opcionales):
      source_ecc_url:       URL del ECC fuente. Si se omite, se usa el
                            propio ECC del coordinator (self-fetch IDS).
      source_connector_uri: URI IDS del conector fuente.
                            Si se omite, se usa el propio CONNECTOR_URI.
    """
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    source_ecc_url       = body.get("source_ecc_url", "")
    source_connector_uri = body.get("source_connector_uri", "")

    global is_coordinator

    if not source_ecc_url:
        log.info(f"[/fl/fetch-algorithm] Coordinator nativo asumiendo rol. Cargando ficheros locales.")
        import shutil
        if os.path.exists(ALGO_BAKED_PATH) and ALGO_BAKED_PATH != ALGO_IDS_PATH:
            shutil.copy(ALGO_BAKED_PATH, ALGO_IDS_PATH)
            
        CONFIG_BAKED = "/app/fl_config.json"
        if os.path.exists(CONFIG_BAKED) and CONFIG_BAKED != CONFIG_PATH:
            shutil.copy(CONFIG_BAKED, CONFIG_PATH)
        
        is_coordinator = True
        success = True
        source_ecc_url = "local_filesystem"
    else:
        # -- MODO IDS: Fetch desde otro conector (Si fuera necesario) ---------
        log.info(
            f"[/fl/fetch-algorithm] Iniciando fetch via IDS --\n"
            f"  source_ecc_url       : {source_ecc_url}\n"
            f"  source_connector_uri : {source_connector_uri}"
        )
        import asyncio
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(
            None, _fetch_algorithm_from_ecc, source_ecc_url, source_connector_uri
        )

    if success:
        cfg = _load_fl_config()
        return JSONResponse(
            status_code=200,
            content={
                "status"      : "everything_received",
                "coordinator" : INSTANCE_ID,
                "source_ecc"  : source_ecc_url,
                "fl_config"   : {
                    "rounds"       : cfg["rounds"],
                    "round_timeout": cfg["round_timeout"],
                    "epochs"       : cfg["epochs"],
                    "batch_size"   : cfg["batch_size"],
                    "learning_rate": cfg["learning_rate"],
                },
                "next_step": "POST /broker/discover -> POST /fl/negotiate -> POST /fl/start",
            }
        )
    else:
        return JSONResponse(
            status_code=502,
            content={
                "error"     : "No se pudo obtener el algoritmo via IDS.",
                "source_ecc": source_ecc_url,
                "hint"      : (
                    "Self-fetch: comprueba que el ECC acepta mensajes del propio conector "
                    "y que algorithm.py esta disponible en el DataApp fuente."
                ),
            }
        )


@app.post("/fl/start")
async def fl_start(request: Request):
    global is_coordinator

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Este worker no es coordinator. Envia el algoritmo primero (pasos 1-4)."}
        )

    algo_path = ALGO_IDS_PATH if os.path.exists(ALGO_IDS_PATH) else ALGO_BAKED_PATH
    if not os.path.exists(algo_path):
        return JSONResponse(
            status_code=400,
            content={"error": "algorithm.py no encontrado. Envia el algoritmo primero (pasos 1-4)."}
        )

    cfg           = _load_fl_config()
    rounds        = int(cfg["rounds"])
    round_timeout = int(cfg["round_timeout"])
    min_workers   = int(cfg["min_workers"])

    with open(algo_path, "rb") as f:
        algo_bytes = f.read()

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            config_bytes = f.read()
    else:
        config_bytes = json.dumps(cfg).encode()

    with _negotiate_lock:
        peers_to_use = list(_accepted_workers)

    if peers_to_use:
        peer_urls = [w["ecc_url"]          for w in peers_to_use]
        peer_uris = [w["connector_uri"]    for w in peers_to_use]
        peer_csvs = [w.get("selected_csv") for w in peers_to_use]
        log.info(
            f"[/fl/start] Usando {len(peers_to_use)} workers aceptados del paso /fl/negotiate:\n" +
            "\n".join(
                f"  {w['connector_uri']}  (CSV: {w.get('selected_csv') or 'auto'})"
                for w in peers_to_use
            )
        )
    else:
        peer_urls = PEER_ECC_URLS
        peer_uris = PEER_CONNECTOR_URIS
        peer_csvs = PEER_SELECTED_CSVS if PEER_SELECTED_CSVS else [None] * len(peer_urls)
        log.warning(
            f"[/fl/start] /fl/negotiate no fue ejecutado -- usando PEER_ECC_URLS del .env: {peer_urls}"
        )

    if not peer_urls:
        return JSONResponse(
            status_code=400,
            content={
                "error": "No hay workers disponibles. Ejecuta /fl/negotiate primero.",
                "hint" : "POST /broker/discover -> POST /fl/negotiate -> POST /fl/start"
            }
        )

    log.info(
        f"[/fl/start] Arrancando FL -- coordinator-{INSTANCE_ID}\n"
        f"  rounds={rounds}  round_timeout={round_timeout}s  min_workers={min_workers}\n"
        f"  peers={peer_urls}"
    )

    def _launch():
        global PEER_ECC_URLS, PEER_CONNECTOR_URIS, PEER_SELECTED_CSVS
        PEER_ECC_URLS       = peer_urls
        PEER_CONNECTOR_URIS = peer_uris
        PEER_SELECTED_CSVS  = peer_csvs
        _run_fl(rounds, round_timeout, min_workers, algo_bytes, config_bytes)

    threading.Thread(target=_launch, daemon=True).start()

    return JSONResponse(
        status_code=202,
        content={
            "status"     : "started",
            "coordinator": INSTANCE_ID,
            "peers"      : peer_urls,
            "fl_config"  : {
                "rounds"       : rounds,
                "round_timeout": round_timeout,
                "min_workers"  : min_workers,
            },
        }
    )





@app.get("/dataset/llm-recommend")
def dataset_llm_recommend():
    """
    Endpoint de prueba para verificar la recomendacion del LLM.
    Devuelve la sugerencia del LLM evaluando todos los CSVs locales.
    """
    csvs = _get_all_local_csvs()
    if not csvs:
        return JSONResponse(
            status_code=404,
            content={"error": f"No hay CSVs en {INPUT_DIR}"}
        )
    
    candidates = [
        {"filename": c["filename"], "columns": c["columns"], "count": len(c["columns"])}
        for c in csvs
    ]
    
    coordinator_cols = _get_my_columns()
    rec = _llm_recommend_dataset(
        candidates, 
        coordinator_cols=coordinator_cols,
        context="Selecciona el dataset que mejor coincida con el dataset de referencia de este worker.",
        timeout=15,
    )
    
    if not rec:
        return JSONResponse(
            status_code=503,
            content={"error": "LLM no disponible o fallo la recomendacion. Revisa los logs y asegurate de que OPENAI_API_KEY este configurada."}
        )
    
    return {
        "instance": INSTANCE_ID,
        "recommended": rec["filename"],
        "reasoning": rec["reasoning"],
        "confidence": rec["confidence"],
        "all_candidates": [c["filename"] for c in candidates]
    }


@app.websocket("/ws/llm-recommend")
async def ws_llm_recommend(websocket: WebSocket):
    """
    Realiza una consulta a Ollama simulando streaming y envia la salida
    token a token por el WebSocket, mejorando drasticamente el User Experience
    y simulando una IA "pensando en tiempo real".

    Query params opcionales:
        peer_worker_id : ID numerico del worker peer que se esta evaluando
                         (p.ej. "1", "3"). Si se omite, usa los CSVs locales.
        peer_csvs      : JSON con lista de {filename, columns, count} del peer,
                         serializado y URL-encoded. Tiene prioridad sobre
                         peer_worker_id cuando esta presente.

    Con peer_csvs el coordinator puede pasar exactamente la lista de candidatos
    que ya obtuvo durante el discovery, sin necesidad de que el peer tenga
    un endpoint de CSVs accesible directamente.
    """
    await websocket.accept()

    peer_worker_id = websocket.query_params.get("peer_worker_id", "")
    peer_csvs_raw  = websocket.query_params.get("peer_csvs", "")

    # Prioridad: peer_csvs (JSON inline) > peer_worker_id > CSVs propios
    candidates: list = []

    if peer_csvs_raw:
        # El coordinator pasa los candidatos del peer directamente como JSON
        try:
            import urllib.parse as _urlparse
            decoded = _urlparse.unquote(peer_csvs_raw)
            candidates = json.loads(decoded)
            log.info(
                f"[ws/llm-recommend] Usando {len(candidates)} CSVs del peer "
                f"(recibidos por query param peer_csvs)"
            )
        except Exception as e:
            log.warning(f"[ws/llm-recommend] Error parseando peer_csvs: {e} -- usando CSVs locales")

    if not candidates and peer_worker_id:
        # Intentar leer los CSVs del peer desde su DataApp (misma red Docker)
        # Puerto convencion: 8500 interno, be-dataapp-workerN como hostname
        try:
            _peer_url = f"https://be-dataapp-worker{peer_worker_id}:8500/dataset/all-columns"
            _r = requests.get(_peer_url, timeout=8, verify=TLS_CERT)
            if _r.status_code == 200:
                _data = _r.json()
                candidates = [
                    {
                        "filename": c["filename"],
                        "columns" : c.get("columns", []),
                        "count"   : c.get("count", len(c.get("columns", []))),
                    }
                    for c in _data.get("csvs", _data if isinstance(_data, list) else [])
                ]
                log.info(
                    f"[ws/llm-recommend] {len(candidates)} CSVs obtenidos del peer "
                    f"worker-{peer_worker_id} via REST interno"
                )
        except Exception as e:
            log.warning(
                f"[ws/llm-recommend] No se pudo obtener CSVs de peer worker-{peer_worker_id}: {e}"
                f" -- usando CSVs locales como fallback"
            )

    if not candidates:
        # Fallback: CSVs propios (comportamiento original)
        local_csvs = _get_all_local_csvs()
        candidates = [
            {"filename": c["filename"], "columns": c["columns"], "count": len(c["columns"])}
            for c in local_csvs
        ]
        if peer_worker_id:
            log.warning(
                f"[ws/llm-recommend] Fallback a CSVs locales (worker-{INSTANCE_ID}) "
                f"para peer worker-{peer_worker_id} -- los resultados mostraran los "
                f"ficheros correctos del peer si los nombres contienen 'worker_{peer_worker_id}'"
            )

    if not candidates:
        await websocket.send_json({"error": f"No hay CSVs disponibles"})
        await websocket.close()
        return

    target_worker = peer_worker_id or INSTANCE_ID
    context_str   = (
        f"El coordinator (worker-{INSTANCE_ID}) usa UNSW-NB15 como referencia. "
        f"Estas evaluando los datasets del worker-{target_worker}."
    )

    csv_descriptions = [
        f"  [{i}] {c['filename']}\n"
        f"      Columnas ({c['count']}): {', '.join(str(col) for col in c.get('columns', [])[:12])}"
        + ("..." if c['count'] > 12 else "")
        for i, c in enumerate(candidates, 1)
    ]

    prompt = (
        "Eres un experto en Machine Learning y Federated Learning para ciberseguridad.\n"
        "Tu tarea es seleccionar el dataset MAS ADECUADO para un entrenamiento de "
        "deteccion de intrusiones de red (Network Intrusion Detection) en un entorno "
        "de Federated Learning basado en el ecosistema IDS.\n"
        f"Contexto adicional: {context_str}\n\n"
        f"A continuacion tienes los datasets disponibles en el worker-{target_worker}:\n"
        f"{chr(10).join(csv_descriptions)}\n\n"
        "Razona tu respuesta paso a paso detalladamente de forma concisa y SIEMPRE termina tu respuesta "
        "con un bloque en formato JSON EXACTAMENTE asi:\n"
        "```json\n"
        "{\"filename\": \"<nombre_exacto>\", \"reasoning\": \"<explicacion>\", \"confidence\": <numero_0_1>}\n"
        "```\n"
        "No anadas texto despues del JSON."
    )
    
    log.info(
        f"[ws/llm-recommend] Iniciando streaming con {LLM_MODEL} "
        f"-- evaluando CSVs de worker-{target_worker} ({len(candidates)} candidatos)"
    )
    
    loop = asyncio.get_running_loop()
    def _stream_llm():
        try:
            with requests.post(LLM_ENDPOINT, json={"model": LLM_MODEL, "prompt": prompt, "stream": True}, stream=True, verify=TLS_CERT, timeout=60) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if line:
                        try:
                            # Verify valid JSON block from Ollama before yielding
                            json.loads(line.decode())
                            yield line.decode()
                        except json.JSONDecodeError:
                            continue
        except requests.exceptions.RequestException as req_err:
            log.warning(f"[LLM] Error de conexion con Ollama en ws_llm_recommend: {req_err}")
            yield json.dumps({"error": f"Error de conexion con Ollama: {req_err}"})

    import queue
    q = queue.Queue()
    def _run_req():
        try:
            for l in _stream_llm():
                q.put(l)
            q.put(None)
        except Exception as e:
            q.put(e)
            
    threading.Thread(target=_run_req, daemon=True).start()
    
    try:
        while True:
            item = await loop.run_in_executor(None, q.get)
            if item is None:
                break
            if isinstance(item, Exception):
                await websocket.send_json({"error": "Error de conexion con Ollama", "detail": str(item)})
                break
            try:
                chunk = json.loads(item)
                if "response" in chunk:
                    await websocket.send_json({"type": "token", "token": chunk["response"]})
                if chunk.get("done"):
                    break
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning(f"Error WS LLM: {e}")
    finally:
        await websocket.close()


def _publish_local_csvs() -> dict:
    """Registra todos los CSVs locales como recursos en el catalogo del worker."""
    from requests.auth import HTTPBasicAuth
    
    basic_api = HTTPBasicAuth(API_USER, API_PASS)
    ecc_base  = f"https://{ECC_HOSTNAME}:8449"
    csvs = _get_all_local_csvs()
    
    if not csvs:
        return {"error": "No hay CSVs locales para publicar"}
        
    try:
        sd = requests.get(f"{ecc_base}/api/selfDescription/", verify=TLS_CERT, auth=basic_api, timeout=10).json()
        catalogs = sd.get("ids:resourceCatalog", [])
        if not catalogs:
            return {"error": "No se encontro ningun resourceCatalog en el ECC"}
        catalog_id = catalogs[0].get("@id", "")
    except Exception as e:
        return {"error": f"Error obteniendo catalogo: {e}"}

    published = []
    
    for c in csvs:
        fname = c["filename"]
        try:
            # 1. Resource
            import uuid
            import datetime
            ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            resource_id = f"https://w3id.org/idsa/autogen/textResource/dataset_{uuid.uuid4()}"
            artifact_id = f"http://w3id.org/engrd/connector/artifact/dataset_{fname}"
            
            res_body = {
                "@context": {"ids": "https://w3id.org/idsa/core/", "idsc": "https://w3id.org/idsa/code/"},
                "@id": resource_id,
                "@type": "ids:TextResource",
                "ids:title": [{"@value": f"Dataset: {fname}", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:description": [{"@value": f"Dataset CSV con {len(c['columns'])} columnas para Federated Learning.", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:keyword": [{"@value": "dataset", "@type": "http://www.w3.org/2001/XMLSchema#string"}, {"@value": "csv", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:language": [{"@id": "https://w3id.org/idsa/code/EN"}],
                "ids:version": "1.0.0",
                "ids:contentType": {"@id": "https://w3id.org/idsa/code/SCHEMA_DEFINITION"}
            }
            resp_res = requests.post(f"{ecc_base}/api/offeredResource/", headers={"catalog": catalog_id, "Content-Type": "application/json"}, json=res_body, verify=TLS_CERT, auth=basic_api, timeout=10)
            
            # 2. Representation: Metadata
            metadata_repr_id = f"https://w3id.org/idsa/autogen/representation/meta_{uuid.uuid4()}"
            cols_str = ", ".join(c["columns"])
            metadata_desc = (
                f"Informacion exhaustiva del Dataset para evaluacion IA/Ollama:\n"
                f"- Nombre de Fichero: {fname}\n"
                f"- Numero Total de Filas (Registros): {c.get('rows', 'Desconocido')}\n"
                f"- Tamano en Disco: {c.get('size_mb', '0')} MB\n"
                f"- Total de Columnas (Features): {len(c['columns'])}\n"
                f"- Nombres de Columnas: {cols_str}"
            )
            meta_body = {
                "@context": {"ids": "https://w3id.org/idsa/core/", "idsc": "https://w3id.org/idsa/code/"},
                "@id": metadata_repr_id,
                "@type": "ids:TextRepresentation",
                "ids:title": [{"@value": "Metadata Representation (Schema & Stats)", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:description": [{"@value": metadata_desc, "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:mediaType": {"@id": "https://w3id.org/idsa/code/JSON"},
                "ids:instance": [{
                    "@type": "ids:Artifact",
                    "@id": f"http://w3id.org/engrd/connector/artifact/metadata_{fname}",
                    "ids:fileName": f"{fname}_metadata.json",
                    "ids:creationDate": {"@value": ts, "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"}
                }]
            }
            requests.post(f"{ecc_base}/api/representation/", headers={"resource": resource_id, "Content-Type": "application/json"}, json=meta_body, verify=TLS_CERT, auth=basic_api, timeout=10)

            # 3. Representation: Execution
            exec_repr_id = f"https://w3id.org/idsa/autogen/representation/exec_{uuid.uuid4()}"
            exec_body = {
                "@context": {"ids": "https://w3id.org/idsa/core/", "idsc": "https://w3id.org/idsa/code/"},
                "@id": exec_repr_id,
                "@type": "ids:TextRepresentation",
                "ids:title": [{"@value": "Execution Representation", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:description": [{"@value": "Instancia del dataset en si para entrenamiento FL", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                "ids:mediaType": {"@id": "https://w3id.org/idsa/code/CSV"},
                "ids:instance": [{
                    "@type": "ids:Artifact",
                    "@id": artifact_id,
                    "ids:fileName": fname,
                    "ids:creationDate": {"@value": ts, "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"}
                }]
            }
            requests.post(f"{ecc_base}/api/representation/", headers={"resource": resource_id, "Content-Type": "application/json"}, json=exec_body, verify=TLS_CERT, auth=basic_api, timeout=10)
            
            # 4. Contract Offer (USE with Constraints)
            contract_id = f"https://w3id.org/idsa/autogen/contractOffer/dataset_{uuid.uuid4()}"
            c_body = {
                "@id": contract_id,
                "@type": "ids:ContractOffer",
                "ids:provider": {"@id": CONNECTOR_URI},
                "ids:permission": [{
                    "@type": "ids:Permission",
                    "@id": f"https://w3id.org/idsa/autogen/permission/{uuid.uuid4()}",
                    "ids:action": [{"@id": "https://w3id.org/idsa/code/USE"}],
                    "ids:title": [{"@value": "Local FL Training Only", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                    "ids:description": [{"@value": "Data strictly restricted for Federated Learning algorithms. No raw data access or transfer allowed.", "@type": "http://www.w3.org/2001/XMLSchema#string"}],
                    "ids:target": {"@id": artifact_id},
                    "ids:constraint": [{
                        "@type": "ids:Constraint",
                        "@id": f"https://w3id.org/idsa/autogen/constraint/local_only_{uuid.uuid4()}",
                        "ids:leftOperand": {"@id": "https://w3id.org/idsa/code/PURPOSE"},
                        "ids:operator": {"@id": "https://w3id.org/idsa/code/SAME_AS"},
                        "ids:rightOperand": {"@value": "Federated_Learning_Local_Only", "@type": "http://www.w3.org/2001/XMLSchema#string"}
                    }]
                }],
                "ids:obligation": [],
                "ids:prohibition": [{
                    "@type": "ids:Prohibition",
                    "@id": f"https://w3id.org/idsa/autogen/prohibition/no_dist_dataset_{uuid.uuid4()}",
                    "ids:action": [{"@id": "https://w3id.org/idsa/code/DISTRIBUTE"}],
                    "ids:target": {"@id": artifact_id}
                }]
            }
            requests.post(f"{ecc_base}/api/contractOffer/", headers={"resource": resource_id, "Content-Type": "application/json"}, json=c_body, verify=TLS_CERT, auth=basic_api, timeout=10)
            
            published.append({"filename": fname, "resource_id": resource_id})
            log.info(f"[publish-datasets] Publicado {fname}: {resource_id}")
            
        except Exception as e:
            log.error(f"[publish-datasets] Error publicando {fname}: {e}")
            
    return {"status": "success", "published_count": len(published), "published": published}


@app.post("/catalog/publish-datasets")
async def catalog_publish_datasets():
    """
    Endpoint manual para forzar la publicacion de los CSVs locales
    en el catalogo IDS (con las 2 representaciones pedidas).
    """
    import asyncio
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, _publish_local_csvs)
    if "error" in res:
        return JSONResponse(status_code=500, content=res)
    return res


@app.get("/dataset/info")
def dataset_info():
    try:
        import pandas as pd
        csv = _csv_path()
        df  = pd.read_csv(csv, low_memory=False)
        df.columns = [c.lower().strip() for c in df.columns]
        cols = list(df.columns)
        return {
            "instance" : INSTANCE_ID,
            "csv_file" : os.path.basename(csv),
            "rows"     : len(df),
            "columns"  : cols,
            "count"    : len(cols),
        }
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "CSV no encontrado"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/dataset/all-columns")
def dataset_all_columns():
    """
    Devuelve todos los CSVs locales con sus columnas, filas y tamano.
    Usado por /ws/llm-recommend de otros workers para obtener los candidatos
    del peer sin necesidad de pasar por el ECC (red Docker interna, puerto 8500).
    """
    csvs = _get_all_local_csvs()
    if not csvs:
        return JSONResponse(status_code=404, content={"error": f"No hay CSVs en {INPUT_DIR}"})
    return {
        "instance": INSTANCE_ID,
        "count"   : len(csvs),
        "csvs"    : [
            {
                "filename": c["filename"],
                "columns" : c["columns"],
                "count"   : len(c["columns"]),
                "rows"    : c.get("rows", 0),
                "size_mb" : c.get("size_mb", 0),
            }
            for c in csvs
        ],
    }



@app.get("/broker/connectors")
def broker_connectors():
    connectors = _get_registered_connectors()
    return {
        "coordinator" : INSTANCE_ID,
        "count"       : len(connectors),
        "connectors"  : connectors,
    }

@app.get("/metrics")
def get_metrics():
    with _ws_perf_lock:
        return _ws_perf_stats


@app.post("/broker/discover")
async def broker_discover_post():
    global _compatible_workers_cache

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Solo el coordinator puede hacer descubrimiento. Envia el algoritmo primero (pasos 1-4)."}
        )

    my_cols    = _get_my_columns()
    compatible = _discover_compatible_workers(my_cols)

    # Guardar resultado en cache para que /fl/negotiate no repita el discovery
    with _compatible_workers_lock:
        _compatible_workers_cache = compatible

    return {
        "coordinator"        : INSTANCE_ID,
        "my_columns_count"   : len(my_cols),
        "compatible_workers" : compatible,
        "count"              : len(compatible),
        "next_step"          : "POST /fl/negotiate para negociar contratos con los compatibles",
    }


@app.post("/fl/receive-algorithm")
async def fl_receive_algorithm(request: Request):
    """
    Recibe algorithm.py + fl_config.json del coordinator via DataApp-to-DataApp.
    Equivale al ArtifactRequestMessage IDS pero por canal interno Docker.
    """
    global is_coordinator, coordinator_ecc_url, coordinator_conn_uri
    body = await request.json()

    algo_b64    = body.get("algo_b64", "")
    config_b64  = body.get("config_b64", "")
    selected_csv = body.get("selected_csv")
    coord_ecc   = body.get("coordinator_ecc", "")
    coord_uri   = body.get("coordinator_uri", "")

    if not algo_b64:
        return JSONResponse(status_code=400, content={"error": "algo_b64 requerido"})

    try:
        algo_bytes   = base64.b64decode(algo_b64.encode())
        _save_algorithm(algo_bytes)
        if config_b64:
            config_bytes = base64.b64decode(config_b64.encode())
            _save_config(config_bytes)
        if selected_csv:
            global _my_selected_csv
            _my_selected_csv = os.path.join(INPUT_DIR, selected_csv)
        if coord_ecc:
            coordinator_ecc_url  = coord_ecc
        if coord_uri:
            coordinator_conn_uri = coord_uri

        log.info(
            f"[/fl/receive-algorithm] [OK] algorithm.py recibido del coordinator\n"
            f"  CSV asignado: {selected_csv or '(auto)'}  |  coordinator: {coord_uri}"
        )
        return {"status": "ok", "worker_id": INSTANCE_ID}
    except Exception as exc:
        log.error(f"[/fl/receive-algorithm] Error: {exc}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.post("/fl/receive-global-weights")
async def fl_receive_global_weights(request: Request):
    """
    Recibe los pesos globales del coordinator para una ronda FL.
    Dispara el entrenamiento local y devuelve los pesos locales al coordinator.
    """
    global coordinator_ecc_url, coordinator_conn_uri
    body = await request.json()

    round_num       = body.get("round", 0)
    global_weights  = body.get("global_weights_b64")
    coord_ecc       = body.get("coordinator_ecc", "")
    coord_uri       = body.get("coordinator_uri", "")

    if coord_ecc:
        coordinator_ecc_url  = coord_ecc
    if coord_uri:
        coordinator_conn_uri = coord_uri

    log.info(f"[/fl/receive-global-weights]  Pesos globales ronda {round_num} recibidos del coordinator")

    def _train_and_reply():
        try:
            result = _train_local(global_weights, round_num, _my_selected_csv)
            _send_local_weights(
                result["weights_b64"], result["n_samples"], result["metrics"], round_num
            )
        except Exception as exc:
            log.error(f"[/fl/receive-global-weights] Error entrenamiento ronda {round_num}: {exc}")

    threading.Thread(target=_train_and_reply, daemon=True).start()
    return {"status": "training_started", "round": round_num, "worker_id": INSTANCE_ID}


@app.post("/fl/receive-local-weights")
async def fl_receive_local_weights(request: Request):
    """
    Recibe los pesos locales de un worker (endpoint del coordinator).
    Almacena los pesos en _round_weights para la agregacion FedAvg.
    """
    body = await request.json()

    sender      = str(body.get("instance_id", "?"))
    round_num   = body.get("round", 0)
    weights_b64 = body.get("weights_b64")
    n_samples   = body.get("n_samples")
    metrics     = body.get("metrics", {})

    if not weights_b64:
        return JSONResponse(status_code=400, content={"error": "weights_b64 requerido"})

    with _round_lock:
        _round_weights[sender] = {
            "weights_b64": weights_b64,
            "n_samples"  : n_samples,
            "metrics"    : metrics,
        }

    log.info(
        f"[/fl/receive-local-weights]  Pesos locales recibidos: "
        f"worker-{sender} ronda {round_num}  ({n_samples} samples)"
    )
    return {"status": "ok", "round": round_num, "worker_id": INSTANCE_ID}


@app.post("/fl/accept-negotiation")
async def fl_accept_negotiation(request: Request):
    """
    Endpoint interno Docker (puerto 8500) -- usado por el coordinator para
    negociar la participacion en FL sin pasar por el ECC ni el puerto 8889.

    El coordinator llama a http://be-dataapp-workerN:8500/fl/accept-negotiation
    directamente por la red Docker interna. El peer responde con su decision
    basandose en FL_OPT_OUT y devuelve su connector_uri real.

    Body JSON (opcional):
        coordinator_uri  : URI IDS del coordinator
        coordinator_ecc  : ECC URL del coordinator
        selected_csv     : CSV que el coordinator quiere usar de este peer
    """
    global coordinator_ecc_url, coordinator_conn_uri

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    coord_uri = body.get("coordinator_uri", "")
    coord_ecc = body.get("coordinator_ecc", "")
    sel_csv   = body.get("selected_csv", "")

    if FL_OPT_OUT:
        log.warning(
            f"[/fl/accept-negotiation] RECHAZADO -- FL_OPT_OUT=true en worker-{INSTANCE_ID}\n"
            f"  Coordinator: {coord_uri}"
        )
        return JSONResponse(content={
            "accepted"     : False,
            "reason"       : "fl_opt_out",
            "worker_id"    : INSTANCE_ID,
            "connector_uri": CONNECTOR_URI,
            "message"      : (
                f"Worker-{INSTANCE_ID} ha optado por no participar en FL "
                "(FL_OPT_OUT=true -- soberania del dato)."
            ),
        })

    # Guardar referencia al coordinator para que el worker pueda enviarle pesos
    if coord_ecc:
        coordinator_ecc_url  = coord_ecc
    if coord_uri:
        coordinator_conn_uri = coord_uri

    # Iniciar tunel WS hacia el coordinator en background (si no esta ya activo)
    _start_worker_ws_client()

    log.info(
        f"[/fl/accept-negotiation] ACEPTADO -- worker-{INSTANCE_ID} participara en FL\n"
        f"  Coordinator: {coord_uri}  |  CSV asignado: {sel_csv or '(auto)'}"
    )
    return JSONResponse(content={
        "accepted"     : True,
        "worker_id"    : INSTANCE_ID,
        "connector_uri": CONNECTOR_URI,
        "ecc_url"      : f"https://{ECC_HOSTNAME}:8889/data",
        "selected_csv" : sel_csv,
        "message"      : f"Worker-{INSTANCE_ID} acepta participar en el entrenamiento FL.",
    })


@app.post("/fl/negotiate")
async def fl_negotiate():
    global _accepted_workers, PEER_ECC_URLS, PEER_CONNECTOR_URIS, PEER_SELECTED_CSVS

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Solo el coordinator puede negociar. Envia el algoritmo primero (pasos 1-4)."}
        )

    # Reutilizar el resultado del /broker/discover -- NO relanzar el LLM ni el discovery.
    # Si el cache esta vacio (se llamo /fl/negotiate sin /broker/discover previo),
    # ejecutar el discovery una sola vez sin LLM como fallback.
    with _compatible_workers_lock:
        compatible = list(_compatible_workers_cache)

    if not compatible:
        log.warning("[/fl/negotiate] Cache de discovery vacio -- ejecutando discovery sin LLM como fallback")
        my_cols    = _get_my_columns()
        compatible = _discover_compatible_workers(my_cols)
        with _compatible_workers_lock:
            _compatible_workers_cache[:] = compatible

    if not compatible:
        return JSONResponse(
            status_code=404,
            content={"error": "No hay workers compatibles en el broker."}
        )

    accepted = []
    rejected = []

    my_ecc_url = f"https://{ECC_HOSTNAME}:8889/data"

    for worker in compatible:
        uri      = worker["connector_uri"]
        ecc_url  = worker["ecc_url"]
        sel_csv  = worker.get("selected_csv")

        import re as _re_neg
        _m = _re_neg.search(r"ecc-worker(\d+)", ecc_url)
        if not _m:
            _m = _re_neg.search(r"worker(\d+)", uri)

        if _m:
            peer_worker_id   = _m.group(1)
            peer_dataapp_url = f"https://be-dataapp-worker{peer_worker_id}:8500"
        else:
            log.warning(
                f"[/fl/negotiate] No se pudo derivar worker_id de {uri} / {ecc_url} "
                f"-- saltando peer"
            )
            rejected.append({
                "connector_uri": uri,
                "ecc_url"      : ecc_url,
                "reason"       : "error",
                "message"      : "No se pudo derivar el worker_id del peer para contactar su DataApp.",
            })
            continue

        log.info(
            f"[/fl/negotiate] Negociando con worker-{peer_worker_id} "
            f"via IDS ContractRequestMessage -> {peer_dataapp_url}/data"
        )

        try:
            # El peer aplica FL_OPT_OUT en su handler ContractRequestMessage
            # y responde con ContractAgreementMessage (aceptado) o
            # RejectionMessage (rechazado / opt-out).
            # Usamos be-dataapp-workerN:8500/data como destino (no ECC 8889).
            ids_result = _ids_send(
                forward_to_url       = f"{peer_dataapp_url}/data",
                forward_to_connector = uri,
                message_type         = "ids:ContractRequestMessage",
                payload={
                    "@context"      : _ids_context(),
                    "@type"         : "ids:ContractRequest",
                    "@id"           : f"https://w3id.org/idsa/autogen/contractRequest/fl_nego_{uuid.uuid4()}",
                    "ids:permission": [],
                    "ids:provider"  : {"@id": uri},
                    "ids:obligation": [], "ids:prohibition": [],
                    "ids:consumer"  : {"@id": CONNECTOR_URI},
                },
            )

            ids_type = ids_result.get("@type", "")

            if "ContractAgreement" in ids_type:
                transfer_contract_id = ids_result.get("@id", f"ids-agreement-worker{peer_worker_id}")
                log.info(f"[/fl/negotiate] worker-{peer_worker_id} ACEPTO [OK]  IDS ContractAgreement={transfer_contract_id}")
                accepted.append({
                    "connector_uri"    : uri,
                    "ecc_url"          : ecc_url,
                    "match_ratio"      : worker["match_ratio"],
                    "transfer_contract": transfer_contract_id,
                    "selected_csv"     : sel_csv,
                })
                # -- Notificar al peer sus datos de coordinator para que abra el tunel WS --
                # (solo si el peer lo soporta -- ignorar errores)
                try:
                    requests.post(
                        f"{peer_dataapp_url}/fl/accept-negotiation",
                        json={
                            "coordinator_uri": CONNECTOR_URI,
                            "coordinator_ecc": my_ecc_url,
                            "selected_csv"   : sel_csv,
                        },
                        timeout=10,
                        verify=TLS_CERT,
                    )
                except Exception:
                    pass   # El tunel WS se iniciara en /fl/start de todos modos

            elif ("Rejection" in ids_type
                  or "rejection" in ids_result.get("reason", "")
                  or ids_result.get("status") == "rejected"):
                reason = ids_result.get("reason", "ids_rejection")
                msg    = ids_result.get("message", str(ids_result.get("ids:rejectionReason", "")))
                log.info(
                    f"[/fl/negotiate] worker-{peer_worker_id} RECHAZO (IDS) -- {reason}: {msg}"
                )
                rejected.append({
                    "connector_uri": uri,
                    "ecc_url"      : ecc_url,
                    "reason"       : reason,
                    "message"      : msg,
                })

            else:
                # Respuesta inesperada -- tratar como error
                log.warning(
                    f"[/fl/negotiate] worker-{peer_worker_id} respuesta IDS inesperada: "
                    f"{ids_type!r} -- {str(ids_result)[:200]}"
                )
                rejected.append({
                    "connector_uri": uri,
                    "ecc_url"      : ecc_url,
                    "reason"       : "unexpected_ids_response",
                    "message"      : str(ids_result)[:200],
                })

        except requests.exceptions.ConnectionError as ce:
            log.error(
                f"[/fl/negotiate] No se pudo conectar con DataApp de worker-{peer_worker_id} "
                f"en {peer_dataapp_url}: {ce}"
            )
            rejected.append({
                "connector_uri": uri,
                "ecc_url"      : ecc_url,
                "reason"       : "error",
                "message"      : str(ce),
            })
        except Exception as exc:
            log.error(f"[/fl/negotiate] Error negociando con worker-{peer_worker_id}: {exc}")
            rejected.append({
                "connector_uri": uri,
                "ecc_url"      : ecc_url,
                "reason"       : "error",
                "message"      : str(exc),
            })

    with _negotiate_lock:
        _accepted_workers   = accepted
        PEER_ECC_URLS       = [w["ecc_url"]          for w in accepted]
        PEER_CONNECTOR_URIS = [w["connector_uri"]    for w in accepted]
        PEER_SELECTED_CSVS  = [w.get("selected_csv") for w in accepted]

    log.info(
        f"[/fl/negotiate] {len(accepted)} aceptados, {len(rejected)} rechazados\n"
        f"  Aceptados : {[w['connector_uri'] for w in accepted]}\n"
        f"  Rechazados: {[w['connector_uri'] for w in rejected]}"
    )

    return {
        "coordinator"   : INSTANCE_ID,
        "accepted"      : accepted,
        "rejected"      : rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "next_step"     : "POST /fl/start para enviar algoritmo y arrancar FL" if accepted else "No hay workers disponibles",
    }



@app.get("/ids/self-description")
def ids_self_description():
    try:
        return JSONResponse(content=_get_self_description())
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.get("/ids/contract")
def ids_contract(contractOffer: str | None = None, request: Request = None):
    try:
        contract_id = contractOffer
        if not contract_id and request:
            contract_id = request.headers.get("contractOffer")
        if not contract_id:
            return JSONResponse(status_code=400, content={"error": "contractOffer requerido"})
        if not _published_fl_contract:
            return JSONResponse(status_code=404, content={"error": "No hay contrato FL publicado"})
        return JSONResponse(content=_published_fl_contract)
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.get("/health")
def health():
    return {
        "status"  : "ok",
        "instance": INSTANCE_ID,
        "role"    : "coordinator" if is_coordinator else "worker",
    }


@app.get("/status")
def status():
    cfg = _load_fl_config()
    csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    try:
        csv_sel = _csv_path()
    except FileNotFoundError:
        csv_sel = None
    return {
        "instance"        : INSTANCE_ID,
        "role"            : "coordinator" if is_coordinator else "worker",
        "algorithm_loaded": os.path.exists(ALGO_IDS_PATH),
        "config_loaded"   : os.path.exists(CONFIG_PATH),
        "fl_config"       : cfg if os.path.exists(CONFIG_PATH) else None,
        "csv_available"   : csv_files,
        "csv_selected"    : csv_sel,
        "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data" if is_coordinator else coordinator_ecc_url,
        "peer_eccs"       : PEER_ECC_URLS,
        "fl_status"       : fl_state["status"],
        "fl_round"        : fl_state["current_round"],
        "fl_total_rounds" : fl_state["total_rounds"],
    }


@app.get("/fl/status")
def fl_status():
    with _fl_lock:
        return dict(fl_state)


@app.get("/fl/results")
def fl_results():
    results_path = os.path.join(OUTPUT_DIR, "fl_results.json")
    with _fl_lock:
        if fl_state["history"]:
            return fl_state["history"]
    if os.path.exists(results_path):
        with open(results_path) as f:
            return json.load(f)
    return JSONResponse(status_code=404, content={"error": "Sin resultados todavia"})


@app.get("/fl/model")
def fl_model():
    model_path = os.path.join(OUTPUT_DIR, "global_model.json")
    if not os.path.exists(model_path):
        return JSONResponse(status_code=404, content={"error": "Sin modelo todavia"})
    with open(model_path) as f:
        data = json.load(f)
    return {
        "coordinator_id"   : INSTANCE_ID,
        "round"            : data.get("round"),
        "metrics"          : data.get("metrics"),
        "weights_available": data.get("weights_b64") is not None,
    }


# =============================================================================
# WebSocket -- Gestion de conexiones en tiempo real
# =============================================================================

# Tunel High-Speed para Federacion de Pesos (Bypass IDS payload bottleneck)
class FLTrainingWSManager:
    def __init__(self):
        self.active_workers: dict[str, WebSocket] = {}

    async def connect(self, worker_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_workers[worker_id] = websocket
        log.info(
            f"[WS FL-Train]  TUNEL ESTABLECIDO: Worker-{worker_id} -> Coordinator-{INSTANCE_ID}\n"
            f"  Tuneles activos: {list(self.active_workers.keys())}\n"
            f"  Total: {len(self.active_workers)} worker(s) en data-plane WS"
        )

    def disconnect(self, worker_id: str):
        if worker_id in self.active_workers:
            del self.active_workers[worker_id]
            log.info(
                f"[WS FL-Train] [WARN] TUNEL CERRADO: Worker-{worker_id}\n"
                f"  Tuneles activos restantes: {list(self.active_workers.keys())}"
            )

fl_ws_manager = FLTrainingWSManager()


def _record_ws_perf(channel: str, elapsed_ms: float, payload_bytes: int,
                    round_num: int, label: str):
    """Registra una transferencia en las metricas de rendimiento WS vs HTTP."""
    with _ws_perf_lock:
        key = "ws" if channel == "ws" else "http"
        _ws_perf_stats[f"{key}_sends"] += 1
        _ws_perf_stats[f"{key}_total_ms"] += elapsed_ms
        _ws_perf_stats[f"{key}_bytes"] += payload_bytes
        entry = {
            "channel": channel,
            "elapsed_ms": round(elapsed_ms, 2),
            "payload_kb": round(payload_bytes / 1024, 1),
            "round": round_num,
            "label": label,
            "ts": datetime.datetime.utcnow().strftime("%H:%M:%S"),
        }
        _ws_perf_stats["history"].append(entry)
        if len(_ws_perf_stats["history"]) > 50:
            _ws_perf_stats["history"] = _ws_perf_stats["history"][-50:]

@app.websocket("/ws/fl-training/{worker_id}")
async def ws_fl_training(websocket: WebSocket, worker_id: str):
    await fl_ws_manager.connect(worker_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "fl_weights":
                sender      = data.get("instance_id", "?")
                round_num   = data.get("round", 0)
                weights_b64 = data.get("weights_b64")
                n_samples   = data.get("n_samples")
                metrics     = data.get("metrics")
                
                with _round_lock:
                    _round_weights[sender] = {
                        "weights_b64": weights_b64,
                        "n_samples"  : n_samples,
                        "metrics"    : metrics,
                    }
                log.info(f"[WS FL-Train]  Pesos locales recibidos via WS: worker-{sender} ronda {round_num}")
    except WebSocketDisconnect:
        fl_ws_manager.disconnect(worker_id)
    except Exception as e:
        log.error(f"[WS FL-Train] Error en conexion WS para worker-{worker_id}: {e}")
        fl_ws_manager.disconnect(worker_id)

def _send_global_weights_ws(worker_id: str, weights_b64: str, round_num: int) -> bool:
    global global_event_loop
    if worker_id in fl_ws_manager.active_workers and global_event_loop:
        ws = fl_ws_manager.active_workers[worker_id]
        payload = {
            "type"              : "fl_global_weights",
            "round"             : round_num,
            "global_weights_b64": weights_b64,
            "from_coordinator"  : INSTANCE_ID
        }
        asyncio.run_coroutine_threadsafe(ws.send_json(payload), global_event_loop)
        return True
    return False

# Client WS logic for Workers connecting to Coordinator
fl_ws_client_conn = None

async def _fl_worker_ws_client_connect():
    global fl_ws_client_conn, coordinator_ecc_url
    if not coordinator_ecc_url:
        return
    import re
    import websockets
    m = re.search(r"worker(\d+)", coordinator_ecc_url)
    if not m:
        return
    coord_id = m.group(1)
    if str(coord_id) == str(INSTANCE_ID):
        return # Auto-loop
    # wss:// -- el DataApp corre con TLS tambien dentro de Docker (start.sh + ECDHE).
    # Las DataApps internas usan certificados auto-firmados en /cert/dataapp/
    # ssl_ctx con verify=TLS_CERT para aceptar certificados auto-firmados.
    ws_url = f"wss://be-dataapp-worker{coord_id}:8500/ws/fl-training/{INSTANCE_ID}"
    import ssl as _ssl_worker
    _ssl_ctx_worker = _ssl_worker.SSLContext(_ssl_worker.PROTOCOL_TLS_CLIENT)
    _ssl_ctx_worker.check_hostname = False
    _ssl_ctx_worker.verify_mode    = _ssl_worker.CERT_NONE
    try:
        fl_ws_client_conn = await websockets.connect(
            ws_url, ssl=_ssl_ctx_worker, max_size=None, ping_timeout=None
        )
        log.info(
            f"[WS FL-Train]  TUNEL WORKER->COORDINATOR ESTABLECIDO\n"
            f"  Worker-{INSTANCE_ID} --WS---> Coordinator (worker{coord_id})\n"
            f"  URL: {ws_url}\n"
            f"  Canal: ws:// (data-plane interno Docker, sin TLS overhead)\n"
            f"  Modo: Bypass IDS -- pesos viajaran por WS en lugar de HTTP multipart"
        )
        
        while True:
            try:
                data = await fl_ws_client_conn.recv()
                payload = json.loads(data)
                if payload.get("type") == "fl_global_weights":
                    round_num = payload.get("round", 1)
                    global_weights = payload.get("global_weights_b64")
                    log.info(f"[WS FL-Train]  Pesos globales recibidos via WS -- ronda {round_num}")
                    
                    def _train_and_reply_ext():
                        try:
                            result = _train_local(global_weights, round_num, _my_selected_csv)
                            _send_local_weights(result["weights_b64"], result["n_samples"], result["metrics"], round_num)
                        except Exception as exc:
                            log.error(f"Error WS training local ronda {round_num}: {exc}")
                    threading.Thread(target=_train_and_reply_ext, daemon=True).start()
            except Exception as loop_e:
                log.warning(f"[WS FL-Train] [WARN] Enlace websocket interrumpido: {loop_e}")
                break
                
    except Exception as e:
        log.warning(
            f"[WS FL-Train] OK TUNEL WS NO DISPONIBLE\n"
            f"  URL: {ws_url}\n"
            f"  Error: {e}\n"
            f"  Fallback: Los pesos se enviaran por IDS/HTTP multipart (mas lento)"
        )
        fl_ws_client_conn = None

def _start_worker_ws_client():
    global global_event_loop
    if global_event_loop:
        asyncio.run_coroutine_threadsafe(_fl_worker_ws_client_connect(), global_event_loop)

def _send_local_weights_ws(payload: dict) -> bool:
    global fl_ws_client_conn, global_event_loop
    if fl_ws_client_conn and global_event_loop:
        asyncio.run_coroutine_threadsafe(fl_ws_client_conn.send(json.dumps(payload)), global_event_loop)
        return True
    return False


class _WSConnectionManager:
    """
    Gestor de conexiones WebSocket activas.
    Permite broadcast a todos los clientes conectados simultaneamente.
    Usa threading.Lock para compatibilidad con Python 3.12+ donde
    asyncio.Lock() no puede crearse fuera del event loop.
    """
    def __init__(self):
        self._clients: list[WebSocket] = []
        self._lock = threading.Lock()  # threading.Lock es seguro fuera del event loop

    async def connect(self, ws: WebSocket):
        await ws.accept()
        with self._lock:
            self._clients.append(ws)
        log.info(f"[WS] Cliente conectado -- total activos: {len(self._clients)}")

    async def disconnect(self, ws: WebSocket):
        with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)
        log.info(f"[WS] Cliente desconectado -- total activos: {len(self._clients)}")

    async def broadcast(self, data: dict):
        """Envia el mismo JSON a todos los clientes conectados."""
        dead = []
        with self._lock:
            clients_snapshot = list(self._clients)
        for ws in clients_snapshot:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


_ws_manager = _WSConnectionManager()


def _notify_ws_clients(data: dict):
    """
    Helper sincrono para notificar desde codigo no-async (p.ej. _run_fl).
    Crea una tarea asyncio si hay un event loop corriendo.
    """
    try:
        global global_event_loop
        if global_event_loop and global_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(_ws_manager.broadcast(data), global_event_loop)
    except Exception as exc:
        log.warning(f"Error WS notify: {exc}")


# =============================================================================
# WebSocket endpoint -- /ws/fl-status
# Monitorizacion en tiempo real del estado del Federated Learning.
# El cliente recibe un JSON por cada cambio de ronda / estado.
#
# Uso desde Postman:
#   ws://localhost:500N/ws/fl-status
#
# Uso desde Python:
#   import websockets, asyncio
#   async def monitor():
#       async with websockets.connect("wss://localhost:500N/ws/fl-status") as ws:
#           async for msg in ws:
#               print(msg)
#   asyncio.run(monitor())
# =============================================================================

@app.get("/ws/tunnel-status")
def ws_tunnel_status():
    """
    Observabilidad de los tuneles WebSocket activos.
    Permite a pfg_ids_fl_flow.py verificar si los canales
    de alta velocidad estan realmente establecidos.
    """
    return {
        "instance"                : INSTANCE_ID,
        "fl_status_clients"       : len(_ws_manager._clients),
        "worker_tunnels_active"   : list(fl_ws_manager.active_workers.keys()),
        "coordinator_tunnel_active": fl_ws_client_conn is not None,
        "role"                    : "coordinator" if is_coordinator else "worker",
    }


@app.get("/ws/performance")
def ws_performance():
    """
    Metricas de rendimiento comparando WebSocket vs HTTP para
    la transferencia de pesos del modelo en Federated Learning.
    Permite demostrar la ventaja del data-plane WS frente al
    control-plane IDS/HTTP multipart.
    """
    with _ws_perf_lock:
        stats = dict(_ws_perf_stats)
        history = list(stats.pop("history", []))

    ws_avg = (stats["ws_total_ms"] / stats["ws_sends"]) if stats["ws_sends"] > 0 else 0
    http_avg = (stats["http_total_ms"] / stats["http_sends"]) if stats["http_sends"] > 0 else 0
    speedup = (http_avg / ws_avg) if ws_avg > 0 and http_avg > 0 else None

    return {
        "instance": INSTANCE_ID,
        "role": "coordinator" if is_coordinator else "worker",
        "summary": {
            "ws": {
                "sends": stats["ws_sends"],
                "avg_ms": round(ws_avg, 2),
                "total_kb": round(stats["ws_bytes"] / 1024, 1),
                "failures": stats["ws_failures"],
            },
            "http": {
                "sends": stats["http_sends"],
                "avg_ms": round(http_avg, 2),
                "total_kb": round(stats["http_bytes"] / 1024, 1),
                "failures": stats["http_failures"],
            },
            "ws_speedup_factor": round(speedup, 2) if speedup else "N/A (datos insuficientes)",
        },
        "recent_transfers": history[-20:],
    }


@app.websocket("/ws/fl-status")
async def ws_fl_status(websocket: WebSocket):
    """
    Stream WebSocket del estado del Federated Learning.
    - Envia el estado inicial al conectar.
    - Emite un JSON cada vez que cambia la ronda o el estado.
    - Cierra la conexion cuando el FL termina (completed / failed).
    """
    await _ws_manager.connect(websocket)
    last_snapshot = None
    try:
        # Estado inicial inmediato al conectar
        with _fl_lock:
            current = dict(fl_state)
        await websocket.send_json({
            "event"   : "connected",
            "instance": INSTANCE_ID,
            "role"    : "coordinator" if is_coordinator else "worker",
            **current,
        })
        last_snapshot = current.copy()

        while True:
            with _fl_lock:
                current = dict(fl_state)

            # Emitir solo si hay cambio real
            if current != last_snapshot:
                await websocket.send_json({
                    "event": "fl_update",
                    **current,
                })
                last_snapshot = current.copy()

                # Notificar progreso cuando el FL concluye (sin break para historial final)
                if current.get("status") in ("completed", "failed"):
                    await websocket.send_json({"event": "fl_finished", **current})

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        log.info("[WS /fl-status] Cliente desconectado")
    except Exception as exc:
        log.warning(f"[WS /fl-status] Error: {exc}")
    finally:
        await _ws_manager.disconnect(websocket)


# =============================================================================
# WebSocket endpoint -- /ws/ids-data
# Canal de entrada para mensajes IDS enviados via WebSocket por el ECC.
# Activo cuando WS_EDGE=true en el ECC (la DataApp se pone en modo WSS).
#
# El ECC envia un JSON {"header": "...", "payload": "..."} por el WebSocket
# en lugar de usar HTTP POST /data.
# Este endpoint lo deserializa y delega en la misma logica que /data.
# =============================================================================

@app.websocket("/ws/ids-data")
async def ws_ids_data(websocket: WebSocket):
    """
    Receptor WebSocket de mensajes IDS (equivalente a POST /data pero por WSS).
    El ECC conecta aqui cuando application.dataApp.websocket.isEnabled=true.
    """
    await websocket.accept()
    client_host = websocket.client.host if websocket.client else "unknown"
    log.info(f"[WS /ids-data] Conexion aceptada desde {client_host}")
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                await websocket.send_text(json.dumps({"error": "invalid JSON"}))
                continue

            header_val  = msg.get("header", "")
            payload_val = msg.get("payload", None)

            if not header_val:
                await websocket.send_text(json.dumps({"error": "missing header"}))
                continue

            # -- Reutiliza la logica de /data creando un Request sintetico ----
            # Para no duplicar codigo, construimos un multipart encoder
            # simulando un POST request valido compatible con ids_data.
            _fields = {"header": ("header", header_val, "application/json")}
            if payload_val is not None:
                _fields["payload"] = ("payload", payload_val, "text/plain")
            _encoder = MultipartEncoder(fields=_fields)
            _raw_body_bytes = _encoder.to_string()

            class _FakeRequest:
                """Adapta el mensaje WS a la interfaz que espera ids_data."""
                async def body(self):
                    return _raw_body_bytes

                @property
                def headers(self):
                    return {"content-type": _encoder.content_type}

            # Procesar con la misma logica que el endpoint HTTP /data
            response = await ids_data(_FakeRequest())
            if hasattr(response, "body"):
                await websocket.send_text(response.body.decode())
            else:
                await websocket.send_text(json.dumps({"status": "processed"}))

    except WebSocketDisconnect:
        log.info(f"[WS /ids-data] ECC/cliente desconectado ({client_host})")
    except Exception as exc:
        log.error(f"[WS /ids-data] Error inesperado: {exc}", exc_info=True)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500, access_log=False)