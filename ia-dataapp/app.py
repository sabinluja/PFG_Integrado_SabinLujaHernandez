"""
app.py  —  IA DataApp Worker/Coordinator
=========================================

Cualquier worker puede ser coordinator — se elige en Postman enviando el
algoritmo (fl_algorithm) al worker destino via IDS/TRUE Connector.

Flujo completo con Broker + DAPS (pasos Postman):
  Pasos 1-4  — Negociación IDS manual (proxy → ecc destino)
               El worker receptor recibe algorithm.py + fl_config.json
               y se convierte en COORDINATOR.

  Paso 5a    — POST /broker/discover   → coordinator consulta Fuseki SPARQL
                                          y descubre workers compatibles.
  Paso 5b    — POST /fl/negotiate      → coordinator negocia contratos IDS
                                          con los workers compatibles del broker.
                                          Worker4 (FL_AUTHORIZED_URIS vacío) es
                                          rechazado automáticamente.
  Paso 5c    — POST /fl/start          → coordinator envía algoritmo + pesos
                                          a los workers aceptados y arranca FL.

  Pasos 13-17 — Verificación del modelo publicado y control de acceso.
               Worker4 no puede negociar contrato del recurso FL porque
               su CONNECTOR_URI no aparece en ids:rightOperand del constraint.

  El fl_config.json se guarda en /home/nobody/data/fl_config.json.
  Los parámetros FL_ROUNDS y ROUND_TIMEOUT ya NO vienen de variables de entorno.
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

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import JSONResponse
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.multipart.decoder import MultipartDecoder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Configuración
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

# Broker IDS — para descubrimiento dinámico de workers
BROKER_URL = os.getenv("BROKER_URL", "https://broker-reverseproxy/infrastructure")
BROKER_SPARQL_URL = "http://broker-fuseki:3030/connectorData/sparql"

# Permite a un worker auto-excluirse del entrenamiento FL (Data Sovereignty)
FL_OPT_OUT = os.getenv("FL_OPT_OUT", "false").lower() == "true"

# Credenciales para la API interna del ECC
API_USER = "apiUser"
API_PASS = "passwordApiUser"

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
# Configuración FL — leída de fl_config.json (enviado desde Postman)
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
PEER_SELECTED_CSVS: list = []   # CSV seleccionado por cada peer (índice igual que PEER_ECC_URLS)


# =============================================================================
# FastAPI
# =============================================================================

app = FastAPI(
    title=f"IA DataApp — Worker {INSTANCE_ID}",
    description=(
        "Sustituye al Java DataApp del TRUE Connector. "
        "POST /proxy para Postman. POST /data para el ECC."
    ),
    version="7.2.0",
)


@app.on_event("startup")
async def _startup_identity_log():
    """Log de identidad IDS al arrancar — facilita debug con broker y DAPS."""
    log.info("=" * 60)
    log.info(f"  IA DataApp arrancando — Worker {INSTANCE_ID}")
    log.info(f"  CONNECTOR_URI   : {CONNECTOR_URI}")
    log.info(f"  ECC_HOSTNAME    : {ECC_HOSTNAME}")
    log.info(f"  BROKER_URL      : {BROKER_URL}")
    log.info(f"  BROKER_SPARQL   : {BROKER_SPARQL_URL}")
    log.info(f"  PEER_ECC_URLS   : {PEER_ECC_URLS or '(vacío — se rellenará via broker)'}")
    log.info(f"  PEER_CONN_URIS  : {PEER_CONNECTOR_URIS or '(vacío — se rellenará via broker)'}")
    if FL_OPT_OUT:
        log.warning(
            f"  FL_OPT_OUT      : True — "
            f"worker-{INSTANCE_ID} NO participará en FL. "
            "Los ContractRequestMessage de coordinators serán rechazados por política de datos."
        )
    else:
        log.info("  FL_OPT_OUT      : False (Participará en entrenamientos FL válidos).")
    log.info("=" * 60)


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
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]

    decoded = pyjwt.decode(token, options={"verify_signature": False})
    _dat_cache["token"] = token
    _dat_cache["exp"]   = decoded.get("exp", now + 3600)

    log.info(f"[DAPS] Token DAT obtenido para worker-{INSTANCE_ID} — expira en {_dat_cache['exp'] - now}s")
    return token


def _security_token() -> dict:
    try:
        token_val = _get_dat_token()
    except Exception as e:
        log.warning(f"[DAPS] No se pudo obtener token real: {e} — usando DummyTokenValue")
        token_val = "DummyTokenValue"
    return {
        "@type"          : "ids:DynamicAttributeToken",
        "@id"            : f"https://w3id.org/idsa/autogen/dynamicAttributeToken/{uuid.uuid4()}",
        "ids:tokenValue" : token_val,
        "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
    }


def _get_self_description() -> dict:
    resp = requests.get(
        f"https://{ECC_HOSTNAME}:8449/api/selfDescription/",
        verify=False, timeout=10,
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
    transfer_contract = body.get("transferContract")

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

    dest_conn_uri = _infer_connector_uri(forward_to)

    log.info(f"[/proxy] {message_type} → {forward_to}")

    try:
        corr_msg = body.get("correlationMessage") or transfer_contract or None

        fl_extra = {}
        if isinstance(payload_in, dict) and payload_in.get("type") == "fl_algorithm":
            algo_b64   = payload_in.get("content", "") or ""
            config_b64 = payload_in.get("config",  "") or ""
            combined   = f"{algo_b64}||fl_config::{config_b64}" if config_b64 else algo_b64
            fl_extra   = {"ids:contentVersion": combined}
            log.info(f"[/proxy] fl_algorithm detectado — content+config → ids:contentVersion (config={'present' if config_b64 else 'absent'})")

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
            
    # Inferencia dinámica usando el catálogo del Broker en lugar de regex estática
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
        log.warning(f"Error infiriendo URI dinámicamente dinámicamente: {e}")
        
    return ecc_url


# =============================================================================
# Utilidades IDS — envío saliente
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
    log.info(f"[IDS OUT] {message_type} → {forward_to_url}")

    resp = requests.post(
        actual_url,
        data=encoder,
        headers={"Content-Type": encoder.content_type},
        verify=False,
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
# Negociación IDS completa — coordinator → peer
# =============================================================================

def _negotiate_and_send_algorithm(peer_ecc_url: str, peer_conn_uri: str,
                                   artifact_bytes: bytes,
                                   config_bytes: bytes,
                                   selected_csv: str | None = None) -> bool:
    log.info(f"[coordinator] Negociación con {peer_ecc_url}")
    try:
        desc     = _ids_send(peer_ecc_url, peer_conn_uri, "ids:DescriptionRequestMessage")
        catalogs = desc.get("ids:resourceCatalog", [{}])
        resource = (catalogs[0].get("ids:offeredResource", [{}]) or [{}])[0]
        contract = (resource.get("ids:contractOffer",   [{}]) or [{}])[0]
        repres   = (resource.get("ids:representation",  [{}]) or [{}])[0]
        instance = (repres.get("ids:instance",          [{}]) or [{}])[0]

        contract_id       = contract.get("@id", "")
        permission        = (contract.get("ids:permission", [{}]) or [{}])[0]
        provider_id       = contract.get("ids:provider", {}).get("@id", "")
        contract_artifact = instance.get(
            "@id", "http://w3id.org/engrd/connector/artifact/algorithm"
        )
        log.info(f"[coordinator] 1/4 Description OK")

        agreement = _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ContractRequestMessage",
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
        log.info(f"[coordinator] 2/4 ContractAgreement OK")

        agreement_id = agreement.get("@id", "")
        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract or agreement_id,
            payload=agreement,
        )
        log.info(f"[coordinator] 3/4 Acuerdo confirmado")

        algo_b64   = base64.b64encode(artifact_bytes).decode("utf-8")
        config_b64 = base64.b64encode(config_bytes).decode("utf-8")
        combined   = f"{algo_b64}||fl_config::{config_b64}||from_coordinator::1"

        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract or agreement_id,
            extra_header={"ids:contentVersion": combined},
            payload={
                "type"            : "fl_algorithm",
                "filename"        : "algorithm.py",
                "content"         : algo_b64,
                "config"          : config_b64,
                "sender"          : f"coordinator-{INSTANCE_ID}",
                "from_coordinator": True,
                "selected_csv"    : selected_csv,
            },
        )
        log.info(f"[coordinator] 4/4 algorithm.py + fl_config.json → {peer_ecc_url} ✅"
                 + (f"  (CSV: {selected_csv})" if selected_csv else ""))
        return True

    except Exception as exc:
        log.error(f"[coordinator] Error con {peer_ecc_url}: {exc}", exc_info=True)
        return False


def _activate_coordinator_from_local() -> bool:
    """
    Activa el rol coordinator cargando el algorithm.py que ya existe en
    este conector (baked en la imagen o previamente recibido via IDS).

    Este es el mecanismo correcto para el self-fetch del coordinator:
    el conector TIENE el artefacto (en el contexto IDS, está disponible
    como recurso en su propio catálogo). No necesita pedirse a sí mismo
    a través del ECC (lo que causaría un self-loop rechazado por DAPS).

    El handshake IDS completo (Description → Contract → Artifact) tiene
    sentido cuando el consumer ES DIFERENTE del provider. Para la
    activación del coordinator (mismo conector), la carga directa es
    semantícamente equivalente y arquitectónicamente correcta.
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

        # Si ya está en ALGO_IDS_PATH no hace falta copiar;
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
            f"★ algorithm.py cargado desde propio conector "
            f"({len(algo_bytes)} bytes) — worker-{INSTANCE_ID} = COORDINATOR\n"
            f"  Fuente: {algo_src}"
        )
        return True

    except Exception as exc:
        log.error(f"[activate-coordinator] Error: {exc}", exc_info=True)
        return False


# =============================================================================
# Obtención del algoritmo via IDS — coordinator como CONSUMER (de otro conector)
# =============================================================================

def _fetch_algorithm_from_ecc(source_ecc_url: str, source_connector_uri: str) -> bool:
    """
    El worker que quiere ser coordinator actúa como consumer IDS:
    ejecuta el handshake completo (Description → ContractRequest → Agreement →
    ArtifactRequest) contra el ECC fuente para obtener algorithm.py +
    fl_config.json. Al terminar, activa is_coordinator = True.

    El ECC fuente debe tener un worker DataApp que responda al
    ArtifactRequestMessage con el algoritmo (modo 'source').
    """
    global is_coordinator
    log.info(f"[fetch-algorithm] Iniciando fetch desde {source_ecc_url} ({source_connector_uri})")
    try:
        # ── Paso 1: DescriptionRequestMessage → catálogo del fuente ──────────
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
        log.info(f"[fetch-algorithm] 1/4 Description OK — artifact={contract_artifact}")

        # ── Paso 2: ContractRequestMessage ───────────────────────────────────
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
        log.info(f"[fetch-algorithm] 2/4 ContractAgreement OK — transfer={transfer_contract}")

        # ── Paso 3: ContractAgreementMessage ─────────────────────────────────
        _ids_send(
            source_ecc_url, source_connector_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
            payload=agreement,
        )
        log.info("[fetch-algorithm] 3/4 Acuerdo confirmado")

        # ── Paso 4: ArtifactRequestMessage → recibir algorithm.py ────────────
        # IMPORTANTE: No ponemos payload ni ids:contentVersion extra.
        # El DataApp fuente (modo source) detecta el ArtifactRequest genérico
        # y responde directamente con {type:fl_algorithm, content:<b64>, ...}.
        resp = _ids_send(
            source_ecc_url, source_connector_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
        )
        log.info(f"[fetch-algorithm] 4/4 ArtifactResponse recibida — type={resp.get('type','?')!r}")

        # ── Extraer y guardar algoritmo ───────────────────────────────────────
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
                "[fetch-algorithm] fl_config.json no incluido en la respuesta — "
                "guardando valores por defecto en disco"
            )
            _save_config(json.dumps(_load_fl_config()).encode())


        is_coordinator = True
        log.info(
            f"★ algorithm.py + config obtenidos via IDS desde {source_ecc_url} "
            f"— worker-{INSTANCE_ID} = COORDINATOR"
        )
        return True

    except Exception as exc:
        log.error(f"[fetch-algorithm] Error: {exc}", exc_info=True)
        return False


# =============================================================================
# Lógica FL
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
        log.error(f"Error guardando métricas locales: {e}")


def _train_local(global_weights_b64: str, round_num: int, csv_path: str | None = None) -> dict:
    _csv = csv_path or _my_selected_csv or _csv_path()
    log.info(f"[train] Ronda {round_num} — usando CSV: {os.path.basename(_csv)}")
    result = _load_algorithm().run(
        _csv,
        global_weights_b64=global_weights_b64,
        config_path=CONFIG_PATH
    )
    log.info(
        f"Ronda {round_num} — local OK  "
        f"acc={result['metrics']['accuracy']:.4f}  "
        f"auc={result['metrics']['auc']:.4f}"
    )
    _save_local_metrics(result, round_num)
    return result


def _send_global_weights(peer_ecc_url: str, peer_conn_uri: str,
                          weights_b64: str, round_num: int):
    try:
        # Forzar renovación del token DAT antes de enviar
        _dat_cache["exp"] = 0
        fl_payload = {
            "type"              : "fl_global_weights",
            "round"             : round_num,
            "global_weights_b64": weights_b64,
            "from_coordinator"  : INSTANCE_ID,
            "coordinator_ecc"   : f"https://{ECC_HOSTNAME}:8889/data",
            "coordinator_uri"   : CONNECTOR_URI,
        }
        # Serializar payload completo en base64 dentro de ids:contentVersion
        # como canal de respaldo por si el ECC descarta el payload multipart
        payload_b64 = base64.b64encode(
            json.dumps(fl_payload).encode()
        ).decode()
        content_version = (
            f"fl_global_weights::round{round_num}"
            f"::payload::{payload_b64}"
        )
        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ArtifactRequestMessage",
            requested_artifact=(
                f"http://w3id.org/engrd/connector/artifact/fl_global_round{round_num}"
            ),
            extra_header={"ids:contentVersion": content_version},
            payload=fl_payload,
        )
        log.info(f"Pesos globales ronda {round_num} → {peer_ecc_url} ✅")
    except Exception as exc:
        log.error(f"Error enviando pesos globales a {peer_ecc_url}: {exc}")


def _send_local_weights(weights_b64: str, n_samples: int,
                         metrics: dict, round_num: int):
    if not coordinator_ecc_url:
        log.error("coordinator_ecc_url no definido")
        return
    try:
        # Forzar renovación del token DAT antes de enviar
        _dat_cache["exp"] = 0
        fl_payload = {
            "type"       : "fl_weights",
            "instance_id": INSTANCE_ID,
            "round"      : round_num,
            "weights_b64": weights_b64,
            "n_samples"  : n_samples,
            "metrics"    : metrics,
        }
        # Serializar payload completo en base64 dentro de ids:contentVersion
        # como canal de respaldo por si el ECC descarta el payload multipart
        payload_b64 = base64.b64encode(
            json.dumps(fl_payload).encode()
        ).decode()
        content_version = (
            f"fl_weights::worker{INSTANCE_ID}::round{round_num}"
            f"::payload::{payload_b64}"
        )
        _ids_send(
            coordinator_ecc_url,
            coordinator_conn_uri or CONNECTOR_URI,
            "ids:ArtifactRequestMessage",
            requested_artifact=(
                f"http://w3id.org/engrd/connector/artifact/fl_weights_worker{INSTANCE_ID}"
            ),
            extra_header={"ids:contentVersion": content_version},
            payload=fl_payload,
        )
        log.info(f"Pesos ronda {round_num} enviados al coordinator ✅")
    except Exception as exc:
        log.error(f"Error enviando pesos locales: {exc}")


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
        sd       = requests.get(f"{ecc_base}/api/selfDescription/", verify=False, auth=basic_api, timeout=10).json()
        catalogs = sd.get("ids:resourceCatalog", [])
        if not catalogs:
            log.error("[publish] No se encontró ningún catalog")
            return
        catalog_id = catalogs[0].get("@id", "")

        log.info("[publish] Creando recurso IDS fl_model_final...")
        resource_body = {
            "@id"             : resource_id,
            "@type"           : "ids:TextResource",
            "ids:title"       : [{"@value": f"FL Global Model — Coordinator {INSTANCE_ID} — {ts_readable}",
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
            json=resource_body, verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando recurso: {resp.status_code}")
            return

        log.info("[publish] Añadiendo contrato restringido a peers...")
        # FIX 1: Usar snapshot inmutable de URIs aceptados en el momento del FL,
        # no el global PEER_CONNECTOR_URIS que puede haber cambiado (race condition).
        _authorized = peer_connector_uris if peer_connector_uris is not None else PEER_CONNECTOR_URIS
        if not _authorized:
            log.warning("[publish] peer_connector_uris vacío — el contrato FL no tendrá restricción de peers")
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
            json=contract_body, verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando contrato: {resp.status_code}")
            return

        global _published_fl_contract
        _published_fl_contract = contract_body

        log.info("[publish] Añadiendo representación con pesos finales...")
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
            json=repr_body, verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando representación: {resp.status_code}")
            return

        log.info(
            f"🎉 Modelo FL publicado como recurso IDS en coordinator-{INSTANCE_ID}\n"
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
    Devuelve [{filename, path, columns}] para todos los CSV disponibles en INPUT_DIR.
    Se usa tanto en el endpoint /dataset/all-columns como en el discovery del coordinator.
    """
    try:
        import pandas as pd
        files = sorted(f for f in os.listdir(INPUT_DIR) if f.endswith(".csv"))
        result = []
        for fname in files:
            fpath = os.path.join(INPUT_DIR, fname)
            try:
                df   = pd.read_csv(fpath, nrows=0, low_memory=False)
                cols = [c.lower().strip() for c in df.columns]
                result.append({"filename": fname, "path": fpath, "columns": cols})
                log.info(f"[dataset] {fname}: {len(cols)} columnas")
            except Exception as e:
                log.warning(f"[dataset] No se pudo leer {fname}: {e}")
        return result
    except Exception as e:
        log.error(f"[dataset] Error listando CSVs en {INPUT_DIR}: {e}")
        return []


def _get_my_columns() -> list:
    """
    Devuelve las columnas del CSV local con más columnas (referencia del coordinator).
    Si hay un único CSV, lo usa directamente.
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
                connectors.append({"connector_uri": uri, "endpoint": endpoint})
        log.info(f"[broker-discover] {len(connectors)} conectores encontrados en el broker")
        return connectors
    except Exception as e:
        log.error(f"[broker-discover] Error consultando Fuseki: {e}")
        return []


def _get_peer_best_csv(ecc_url: str, connector_uri: str, my_set: set) -> tuple:
    """
    Escanea TODOS los CSVs del peer via /dataset/all-columns y elige el
    que mayor coincidencia de columnas tenga con my_set.

    Devuelve (best_cols, real_uri, best_filename, best_ratio).
    """
    real_uri = connector_uri
    try:
        # ── Obtener real_uri via IDS DescriptionRequestMessage ────────────────
        try:
            desc     = _ids_send(ecc_url, connector_uri, "ids:DescriptionRequestMessage")
            real_uri = desc.get("@id", "") or connector_uri
        except Exception:
            pass

        # ── Obtener lista completa de CSVs del peer ───────────────────────────
        import re as _re
        all_csvs = []
        m = _re.search(r"ecc-worker(\d+)", ecc_url)
        if m:
            wid = m.group(1)
            try:
                r = requests.get(
                    f"https://be-dataapp-worker{wid}:8500/dataset/all-columns",
                    verify=False, timeout=8,
                )
                if r.ok:
                    all_csvs = r.json()  # [{filename, columns, count}]
                    log.info(
                        f"[broker-discover] {real_uri} — "
                        f"{len(all_csvs)} CSV(s) disponibles para evaluar"
                    )
            except Exception as e:
                log.warning(f"[broker-discover] /dataset/all-columns falló para {ecc_url}: {e}")

            # Fallback: endpoint antiguo /dataset/columns (un solo CSV)
            if not all_csvs:
                try:
                    r = requests.get(
                        f"https://be-dataapp-worker{wid}:8500/dataset/columns",
                        verify=False, timeout=5,
                    )
                    if r.ok:
                        data  = r.json()
                        cols  = data.get("columns", [])
                        fname = data.get("filename", "dataset.csv")
                        all_csvs = [{"filename": fname, "columns": cols}]
                except Exception:
                    pass

        if not all_csvs:
            log.warning(f"[broker-discover] No se pudo obtener ningún CSV de {real_uri}")
            return [], real_uri, None, 0.0

        # ── Evaluar cada CSV y elegir el de mayor match_ratio ─────────────────
        best_cols, best_filename, best_ratio = [], None, 0.0
        for csv_info in all_csvs:
            fname  = csv_info.get("filename", "?")
            cols   = [c.lower().strip() for c in csv_info.get("columns", [])]
            p_set  = set(cols)
            common = my_set & p_set
            ratio  = len(common) / len(my_set) if my_set else 0.0
            is_best = ratio > best_ratio
            log.info(
                f"[broker-discover]   {fname}: {len(p_set)} cols, "
                f"{len(common)} comunes, ratio={ratio:.0%}"
                + (" ← MEJOR" if is_best else "")
            )
            if is_best:
                best_ratio    = ratio
                best_cols     = cols
                best_filename = fname

        return best_cols, real_uri, best_filename, best_ratio

    except Exception as e:
        log.warning(f"[broker-discover] Error escaneando CSVs de {connector_uri}: {e}")
        return [], real_uri, None, 0.0


def _ecc_url_from_connector_uri(connector_uri: str, endpoint: str) -> str:
    from urllib.parse import urlparse
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname:
            return f"https://{parsed.hostname}:8889/data"
    
    # El regex rígido fue eliminado para favorecer la parametrización pura del DAPS/Broker.
    return ""


MATCH_THRESHOLD = 0.95  # 95% de coincidencia mínima de columnas


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

        # Saltar propio coordinator (por URI o por ECC URL) — dinámico vía ECC_HOSTNAME
        if uri == CONNECTOR_URI or ecc_url == my_ecc_url:
            log.info(f"[broker-discover] Saltando propio connector: {uri}")
            continue

        log.info(f"[broker-discover] Evaluando {uri} — escaneando todos sus CSVs...")
        best_cols, real_uri, best_filename, best_ratio = _get_peer_best_csv(
            ecc_url, uri, my_set
        )
        if real_uri != uri:
            log.info(f"[broker-discover] URI broker {uri!r} → URI IDS real {real_uri!r}")

        common = my_set & set(c.lower() for c in best_cols)
        log.info(
            f"[broker-discover] {real_uri}\n"
            f"  mejor CSV: {best_filename!r}  comunes: {len(common)}/{len(my_set)}  "
            f"ratio: {best_ratio:.0%}  (umbral: {MATCH_THRESHOLD:.0%})  "
            + ("✅ COMPATIBLE" if best_ratio >= MATCH_THRESHOLD else "❌ DESCARTADO")
        )

        if best_ratio >= MATCH_THRESHOLD:
            compatible.append({
                "connector_uri": real_uri,
                "ecc_url"      : ecc_url,
                "common_cols"  : sorted(common),
                "match_ratio"  : round(best_ratio, 3),
                "selected_csv" : best_filename,
            })

    log.info(
        f"[broker-discover] {len(compatible)} workers compatibles "
        f"(umbral {MATCH_THRESHOLD:.0%})"
    )
    return compatible


def _run_fl(n_rounds: int, round_timeout: int, min_workers: int,
             algo_bytes: bytes = None, config_bytes: bytes = None):
    global fl_state
    # FIX 1: Snapshot inmutable de los peers aceptados al inicio del FL.
    # Evita race condition si PEER_CONNECTOR_URIS cambia durante el entrenamiento.
    _peers_snapshot = list(PEER_CONNECTOR_URIS)

    with _fl_lock:
        fl_state.update({"status": "running", "current_round": 0,
                          "total_rounds": n_rounds, "history": []})

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
        log.info(f"{'═'*56}")
        log.info(f"  RONDA {round_num}/{n_rounds}  [coordinator-{INSTANCE_ID}]")
        log.info(f"{'═'*56}")

        with _fl_lock:
            fl_state["current_round"] = round_num
            fl_state["status"]        = f"round_{round_num}"

        _round_weights.clear()
        t0 = time.time()

        if algo_bytes:
            log.info(f"[ronda {round_num}] Distribuyendo algorithm.py + fl_config.json a peers…")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(PEER_ECC_URLS), 1)) as ex:
                _peer_csvs = PEER_SELECTED_CSVS if PEER_SELECTED_CSVS else [None] * len(PEER_ECC_URLS)
                futures = {
                    ex.submit(_negotiate_and_send_algorithm, p, u, algo_bytes,
                              config_bytes or b"{}", csv): p
                    for p, u, csv in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS, _peer_csvs)
                }
                for fut in concurrent.futures.as_completed(futures):
                    peer = futures[fut]
                    try:
                        ok = fut.result()
                        log.info(f"  [ronda {round_num}] → {peer}: {'✅' if ok else '❌'}")
                    except Exception as exc:
                        log.error(f"  [ronda {round_num}] → {peer}: ❌ {exc}")

        if algo_bytes:
            time.sleep(3)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(PEER_ECC_URLS)) as ex:
            for peer_url, peer_uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
                ex.submit(_send_global_weights, peer_url, peer_uri,
                          global_weights_b64, round_num)

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
            log.error(f"Ronda {round_num}: solo {len(results)}/{min_workers} workers respondieron — abortando")
            with _fl_lock:
                fl_state["status"] = "failed"
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

        acc = global_metrics.get("accuracy", 0)
        if acc > best_accuracy:
            best_accuracy = acc
            best_weights_b64 = global_weights_b64
            best_metrics = global_metrics
            best_round = round_num

            with open(model_path, "w") as f:
                json.dump({"round": best_round, "weights_b64": best_weights_b64, "metrics": best_metrics}, f)
            log.info(f"✨ Nueva mejor ronda encontrada ({best_round}) con acc={best_accuracy} — guardada en disco")

        log.info(
            f"Ronda {round_num} OK en {elapsed}s  "
            f"acc={global_metrics.get('accuracy','?')}  "
            f"auc={global_metrics.get('auc','?')}"
        )

    with _fl_lock:
        fl_state["status"] = "completed"

    with open(os.path.join(OUTPUT_DIR, "fl_results.json"), "w") as f:
        json.dump(fl_state["history"], f, indent=2)

    log.info(f"✅ FL completado — {n_rounds} rondas. Mejor ronda: {best_round}")

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
# POST /data — mensajes IDS entrantes del ECC
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
    log.info(f"◀ Mensaje IDS: {tipo}")

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

    # ── DescriptionRequestMessage ─────────────────────────────────────────────
    if tipo == "ids:DescriptionRequestMessage":
        if "ids:requestedElement" not in mensaje:
            body_resp = self_desc
        else:
            url  = f"https://{ECC_HOSTNAME}:8449/api/offeredResource/"
            hdrs = {"resource": mensaje["ids:requestedElement"]["@id"]}
            body_resp = requests.get(url, headers=hdrs, verify=False, auth=basic_api, timeout=10).json()

        return _multipart_response(
            _resp("ids:DescriptionResponseMessage", "descriptionResponseMessage"),
            json.dumps(body_resp)
        )

    # ── ContractRequestMessage ────────────────────────────────────────────────
    elif tipo == "ids:ContractRequestMessage":
        payload_dict      = json.loads(payload_val) if payload_val else {}
        contract_offer_id = payload_dict.get("@id", "")

        consumer_uri = mensaje.get("ids:issuerConnector", {}).get("@id", "")

        if FL_OPT_OUT:
            log.warning(
                f"[ContractRequest] PARTICIPACIÓN DENEGADA — "
                f"worker-{INSTANCE_ID} ha optado por no compartir datos (Soberanía)\n"
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
                    f"Worker {INSTANCE_ID} has opted out of federated learning participation. "
                    "This connector is registered in the broker but does not share its data (Data Sovereignty rules)."
                )
            }))

        # ── Verificar si el consumer está autorizado en el contrato FL restringido ──
        # El modelo FL publicado usa connector-restricted-policy con ids:constraint IN [peers].
        # Si el solicitante no está en esa lista, rechazamos con unauthorized_consumer.
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
                        f"[ContractRequest] ACCESO DENEGADO — {consumer_uri!r} "
                        f"no está en la lista de peers autorizados del modelo FL.\n"
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
        contrato = requests.get(url, headers=hdrs, verify=False, auth=basic_api, timeout=10).json()

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

    # ── ContractAgreementMessage ──────────────────────────────────────────────
    elif tipo == "ids:ContractAgreementMessage":
        return _multipart_response(
            _resp("ids:MessageProcessedNotificationMessage", "messageProcessedNotificationMessage")
        )

    # ── ArtifactRequestMessage ────────────────────────────────────────────────
    elif tipo == "ids:ArtifactRequestMessage":
        try:
            payload_dict = json.loads(payload_val) if payload_val else {}
        except Exception:
            payload_dict = {}

        # ── FIX BUG 1: Solo parsear ids:contentVersion como fl_algorithm
        #    si NO es fl_global_weights:: ni fl_weights::
        #    Antes este bloque asumía que CUALQUIER contentVersion era fl_algorithm,
        #    lo que causaba que los pesos globales sobreescribieran algorithm.py
        #    y convirtieran al worker en coordinator erróneamente.
        if not payload_dict.get("type"):
            content_version = mensaje.get("ids:contentVersion", "")
            if content_version and isinstance(content_version, str):
                if (content_version.startswith("fl_global_weights::") or
                        content_version.startswith("fl_weights::")):
                    # El tipo y datos vienen del payload JSON — parsear explícitamente
                    log.info(f"[ArtifactRequest] ids:contentVersion={content_version[:40]}... — parseando payload JSON")
                    if payload_val:
                        try:
                            payload_dict = json.loads(payload_val)
                            log.info(f"[ArtifactRequest] payload_dict parseado desde payload_val: type={payload_dict.get('type','?')!r}")
                        except Exception as _pe:
                            log.error(f"[ArtifactRequest] Error parseando payload_val para {content_version[:30]}: {_pe}")
                    # Si payload_val está vacío o falló el parse, intentar extraer
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
                    # Último recurso: inferir solo el tipo desde el prefijo
                    if not payload_dict.get("type"):
                        if content_version.startswith("fl_global_weights::"):
                            payload_dict["type"] = "fl_global_weights"
                            log.warning("[ArtifactRequest] type inferido desde contentVersion: fl_global_weights (payload vacío)")
                        elif content_version.startswith("fl_weights::"):
                            payload_dict["type"] = "fl_weights"
                            log.warning("[ArtifactRequest] type inferido desde contentVersion: fl_weights (payload vacío — pesos perdidos)")
                else:
                    # Es fl_algorithm SOLO si parece payload IDS-FL válido:
                    # el codec IDS-FL incluye siempre al menos "||from_coordinator"
                    # o "||fl_config::" o un base64 largo (> 50 chars) sin "::" adicionales.
                    # Si el ECC añade su propia value (p.ej. una URI o token corto),
                    # lo ignoramos y dejamos artifact_type vacío → modo fuente.
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

        # fl_weights — pesos locales de un worker → coordinator acumula
        if artifact_type == "fl_weights":
            sender      = payload_dict.get("instance_id", "?")
            round_num   = payload_dict.get("round", 0)
            weights_b64 = payload_dict.get("weights_b64")
            n_samples   = payload_dict.get("n_samples")
            metrics     = payload_dict.get("metrics")
            log.info(f"Pesos de worker-{sender} (ronda {round_num})")
            if not weights_b64 or n_samples is None or metrics is None:
                log.error(
                    f"[fl_weights] Payload incompleto desde worker-{sender} ronda {round_num} — "
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
            log.info(f"[fl_weights] ✅ Pesos de worker-{sender} ronda {round_num} acumulados ({len(_round_weights)} total)")
            return _multipart_response(resp_h, json.dumps({"status": "weights_received", "from": sender}))

        # fl_global_weights — worker entrena localmente
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

            def _train_and_reply():
                try:
                    deadline_algo = time.time() + 15
                    while time.time() < deadline_algo:
                        if os.path.exists(ALGO_IDS_PATH) or os.path.exists(ALGO_BAKED_PATH):
                            break
                        log.info(f"[fl_global_weights] Esperando algorithm.py... (ronda {round_num})")
                        time.sleep(1)
                    else:
                        log.error(f"[fl_global_weights] algorithm.py no disponible tras 15s — ronda {round_num} abortada")
                        return
                    result = _train_local(global_weights_b64, round_num, _my_selected_csv)
                    _send_local_weights(result["weights_b64"], result["n_samples"],
                                        result["metrics"], round_num)
                except Exception as exc:
                    log.error(f"Error ronda {round_num}: {exc}")

            threading.Thread(target=_train_and_reply, daemon=True).start()
            return _multipart_response(resp_h, json.dumps({"status": "training_started", "round": round_num}))

        # fl_algorithm — guardar algorithm.py + fl_config.json
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
                log.warning("fl_config.json no recibido — usando valores por defecto")

            if payload_dict.get("from_coordinator"):
                global _my_selected_csv
                sel_csv = payload_dict.get("selected_csv")
                if sel_csv:
                    full_path = os.path.join(INPUT_DIR, sel_csv)
                    if os.path.exists(full_path):
                        _my_selected_csv = full_path
                        log.info(
                            f"[fl_algorithm] CSV seleccionado por coordinator: "
                            f"{sel_csv} → {full_path}"
                        )
                    else:
                        log.warning(
                            f"[fl_algorithm] CSV '{sel_csv}' no encontrado en {INPUT_DIR}"
                            f" — se usará selección automática"
                        )
                log.info(f"✔ algorithm.py + config recibidos del coordinator — worker-{INSTANCE_ID} = WORKER")
            else:
                is_coordinator = True
                log.info(f"★ algorithm.py + config recibidos desde Postman — worker-{INSTANCE_ID} = COORDINATOR")

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

        # ── Modo fuente: servir algorithm.py a otro coordinator que lo solicita ──
        # Cuando el artifact_type es desconocido/vacío y el artefacto solicitado
        # no es de tipo fl_weights/fl_global_weights, este DataApp actúa como
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
                        f"({len(algo_bytes_src)} bytes) → {requester}"
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
# Endpoints de control y monitorización
# =============================================================================

# =============================================================================
# POST /fl/fetch-algorithm — coordinator solicita el algoritmo via IDS
# =============================================================================

@app.post("/fl/fetch-algorithm")
async def fl_fetch_algorithm(request: Request):
    """
    El worker que quiere ser coordinator llama a este endpoint.
    Ejecuta el handshake IDS completo contra el ECC fuente para obtener
    algorithm.py + fl_config.json y activar el rol coordinator.

    Por defecto (body vacío) hace un **IDS self-fetch**:
      el coordinator actúa como CONSUMER Y PROVIDER de su propio ECC.
      DescriptionRequestMessage → ContractRequestMessage
      → ContractAgreementMessage → ArtifactRequestMessage
      El ECC reenvía al /data local que sirve el algorithm.py baked.

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

    # ── MODO DEFAULT: IDS self-fetch (sin intermediario externo) ─────────────
    # Si no se especifica source_ecc_url, el coordinator construye la URL de
    # su propio ECC y ejecuta el handshake IDS completo contra él:
    #   DescriptionRequestMessage → ContractRequestMessage
    #   → ContractAgreementMessage → ArtifactRequestMessage
    # El ECC reenvía cada mensaje al /data del propio DataApp, que actúa en
    # "modo fuente" y sirve el algorithm.py + fl_config.json baked.
    # run_in_executor libera el event loop para que /data pueda responder
    # concurrentemente → no hay deadlock.
    if not source_ecc_url:
        source_ecc_url       = f"https://{ECC_HOSTNAME}:8889/data"
        source_connector_uri = CONNECTOR_URI
        log.info(
            f"[/fl/fetch-algorithm] IDS self-fetch — coordinator actúa como consumer Y provider\n"
            f"  source_ecc_url : {source_ecc_url}\n"
            f"  connector_uri  : {source_connector_uri}"
        )

    # ── Handshake IDS (self-fetch o externo) ─────────────────────────────────
    # Ejecutar en thread pool para liberar el event loop:
    #   el ECC necesita llamar de vuelta a /data (o al ECC externo),
    #   y ese handler debe poder ejecutarse concurrentemente.
    log.info(
        f"[/fl/fetch-algorithm] Iniciando fetch —\n"
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
                "next_step": "POST /broker/discover → POST /fl/negotiate → POST /fl/start",
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
                    "y que algorithm.py está disponible en el DataApp fuente."
                ),
            }
        )


@app.post("/fl/start")
async def fl_start(request: Request):
    global is_coordinator

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Este worker no es coordinator. Envía el algoritmo primero (pasos 1-4)."}
        )

    algo_path = ALGO_IDS_PATH if os.path.exists(ALGO_IDS_PATH) else ALGO_BAKED_PATH
    if not os.path.exists(algo_path):
        return JSONResponse(
            status_code=400,
            content={"error": "algorithm.py no encontrado. Envía el algoritmo primero (pasos 1-4)."}
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
            f"[/fl/start] /fl/negotiate no fue ejecutado — usando PEER_ECC_URLS del .env: {peer_urls}"
        )

    if not peer_urls:
        return JSONResponse(
            status_code=400,
            content={
                "error": "No hay workers disponibles. Ejecuta /fl/negotiate primero.",
                "hint" : "POST /broker/discover → POST /fl/negotiate → POST /fl/start"
            }
        )

    log.info(
        f"[/fl/start] Arrancando FL — coordinator-{INSTANCE_ID}\n"
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


@app.get("/dataset/columns")
def dataset_columns():
    try:
        import pandas as pd
        csv = _csv_path()
        df  = pd.read_csv(csv, nrows=0, low_memory=False)
        cols = [c.lower().strip() for c in df.columns]
        return {
            "instance" : INSTANCE_ID,
            "filename" : os.path.basename(csv),
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
    Devuelve la lista de TODOS los CSVs disponibles en INPUT_DIR con sus columnas.
    El coordinator usa este endpoint durante el descubrimiento (FASE 2) para
    evaluar qué CSV del peer tiene mayor coincidencia de columnas y elegir el
    más adecuado para federated learning (umbral 95%).
    """
    csvs = _get_all_local_csvs()
    if not csvs:
        return JSONResponse(
            status_code=404,
            content={"error": f"No hay CSVs en {INPUT_DIR}"}
        )
    return [
        {"filename": c["filename"], "columns": c["columns"], "count": len(c["columns"])}
        for c in csvs
    ]


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


@app.get("/broker/connectors")
def broker_connectors():
    connectors = _get_registered_connectors()
    return {
        "coordinator" : INSTANCE_ID,
        "count"       : len(connectors),
        "connectors"  : connectors,
    }


@app.post("/broker/discover")
async def broker_discover_post():
    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Solo el coordinator puede hacer descubrimiento. Envía el algoritmo primero (pasos 1-4)."}
        )

    my_cols    = _get_my_columns()
    compatible = _discover_compatible_workers(my_cols)

    return {
        "coordinator"        : INSTANCE_ID,
        "my_columns_count"   : len(my_cols),
        "compatible_workers" : compatible,
        "count"              : len(compatible),
        "next_step"          : "POST /fl/negotiate para negociar contratos con los compatibles",
    }


@app.post("/fl/negotiate")
async def fl_negotiate():
    global _accepted_workers, PEER_ECC_URLS, PEER_CONNECTOR_URIS, PEER_SELECTED_CSVS

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Solo el coordinator puede negociar. Envía el algoritmo primero (pasos 1-4)."}
        )

    my_cols    = _get_my_columns()
    compatible = _discover_compatible_workers(my_cols)

    if not compatible:
        return JSONResponse(
            status_code=404,
            content={"error": "No hay workers compatibles en el broker."}
        )

    accepted = []
    rejected = []

    for worker in compatible:
        uri     = worker["connector_uri"]
        ecc_url = worker["ecc_url"]
        log.info(f"[/fl/negotiate] Negociando contrato con {uri}")
        try:
            desc     = _ids_send(ecc_url, uri, "ids:DescriptionRequestMessage")

            # FIX: Usar el @id real de la self-description como connector_uri,
            # no la URI del broker (que puede ser https://broker-reverseproxy/connectors/XXXXX).
            # La self-description siempre contiene el @id IDS nativo del connector.
            real_uri = desc.get("@id", "") or uri
            if real_uri != uri:
                log.info(f"[/fl/negotiate] URI broker {uri!r} → URI IDS real {real_uri!r}")
                uri = real_uri

            catalogs = desc.get("ids:resourceCatalog", [{}])
            resource = (catalogs[0].get("ids:offeredResource", [{}]) or [{}])[0]
            contract = (resource.get("ids:contractOffer",  [{}]) or [{}])[0]
            repres   = (resource.get("ids:representation", [{}]) or [{}])[0]
            instance = (repres.get("ids:instance",         [{}]) or [{}])[0]

            contract_id       = contract.get("@id", "")
            permission        = (contract.get("ids:permission", [{}]) or [{}])[0]
            provider_id       = contract.get("ids:provider", {}).get("@id", "")
            contract_artifact = instance.get("@id", "http://w3id.org/engrd/connector/artifact/1")

            response = _ids_send(
                ecc_url, uri, "ids:ContractRequestMessage",
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

            resp_type = response.get("@type", "")
            if "Rejection" in resp_type or response.get("status") == "rejected":
                reason = response.get("reason", "unknown")
                log.warning(f"[/fl/negotiate] {uri} RECHAZÓ el contrato — razón: {reason}")
                rejected.append({
                    "connector_uri": uri,
                    "ecc_url"      : ecc_url,
                    "reason"       : reason,
                    "message"      : response.get("message", ""),
                })
            else:
                agreement_id = response.get("@id", "")
                # FIX BUG 2: ContractAgreementMessage en /fl/negotiate necesita
                # correlation_message para que el ECC no lo rechace como MALFORMED_MESSAGE
                _ids_send(
                    ecc_url, uri, "ids:ContractAgreementMessage",
                    requested_artifact=contract_artifact,
                    correlation_message=agreement_id,
                    payload=response,
                )
                log.info(f"[/fl/negotiate] {uri} ACEPTÓ el contrato ✅")
                accepted.append({
                    "connector_uri"    : uri,
                    "ecc_url"          : ecc_url,
                    "match_ratio"      : worker["match_ratio"],
                    "transfer_contract": agreement_id,
                })

        except Exception as exc:
            log.error(f"[/fl/negotiate] Error negociando con {uri}: {exc}")
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
    return JSONResponse(status_code=404, content={"error": "Sin resultados todavía"})


@app.get("/fl/model")
def fl_model():
    model_path = os.path.join(OUTPUT_DIR, "global_model.json")
    if not os.path.exists(model_path):
        return JSONResponse(status_code=404, content={"error": "Sin modelo todavía"})
    with open(model_path) as f:
        data = json.load(f)
    return {
        "coordinator_id"   : INSTANCE_ID,
        "round"            : data.get("round"),
        "metrics"          : data.get("metrics"),
        "weights_available": data.get("weights_b64") is not None,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500, access_log=False)