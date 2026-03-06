"""
app.py  —  IA DataApp Worker/Coordinator
=========================================

Sustituye completamente al Java DataApp del TRUE Connector.
Los 3 workers ejecutan este mismo fichero — son idénticos en código.

Arquitectura (según indicaciones del profesor):
  - TÚ (desde Postman) decides qué worker es el coordinator.
  - Llamas a  POST http://localhost:500N/proxy  igual que antes llamabas
    a connectorA:8184/proxy con el Java DataApp.
  - /proxy recibe el JSON de Postman, construye el mensaje IDS multipart
    y lo envía directo al ECC destino (Forward-To).
  - No hay consumer Python — Postman ES el consumer.
  - No hay broadcast automático — tú eliges el coordinator.

Flujo desde Postman (tú eres el coordinator en worker-1):
  1. POST /proxy  DescriptionRequestMessage → ecc-worker2:8889/data
  2. POST /proxy  ContractRequestMessage    → ecc-worker2:8889/data
  3. POST /proxy  ContractAgreementMessage  → ecc-worker2:8889/data
  4. POST /proxy  ArtifactRequestMessage    → ecc-worker2:8889/data
     payload: { "type": "fl_algorithm", "content": "<base64 de algorithm.py>" }
     → worker-2 recibe el algorithm.py, se convierte en COORDINATOR,
       distribuye a worker-1 y worker-3, y arranca el FL autónomamente.

  (Repetir pasos 1-4 para worker-3 si quieres que sea el coordinator)

Flujo IDS interno coordinator → workers (automático):
  coordinator:8500 → ecc-coordinatorN:8889 → ecc-workerM:8889 → workerM:8500/data

ECC reenvía mensajes entrantes aquí via:
  DATA_APP_ENDPOINT = http://be-dataapp-workerN:8500/data
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

# ECCs de los otros 2 peers — usados por el coordinator para distribuir
# algorithm.py y enviar pesos globales en cada ronda FL
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

# Parámetros FL
FL_ROUNDS     = int(os.getenv("FL_ROUNDS",     "5"))
ROUND_TIMEOUT = int(os.getenv("ROUND_TIMEOUT", "180"))

# Credenciales para la API interna del ECC
API_USER = "apiUser"
API_PASS = "passwordApiUser"

# Directorios — cada worker monta su propia carpeta aislada via docker volume
DATA_DIR   = "/home/nobody/data"
INPUT_DIR  = os.path.join(DATA_DIR, "input")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")

# algorithm.py: prioridad al recibido via IDS sobre el baked en imagen
ALGO_IDS_PATH   = os.path.join(DATA_DIR, "algorithm.py")
ALGO_BAKED_PATH = "/app/algorithm.py"

os.makedirs(INPUT_DIR,  exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


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
coordinator_ecc_url  = None   # aprendido al recibir fl_global_weights
coordinator_conn_uri = None

fl_state = {
    "status"       : "idle",
    "current_round": 0,
    "total_rounds" : FL_ROUNDS,
    "history"      : [],
}
_fl_lock = threading.Lock()

_round_weights: dict = {}
_round_lock = threading.Lock()


# =============================================================================
# FastAPI
# =============================================================================

app = FastAPI(
    title=f"IA DataApp — Worker {INSTANCE_ID}",
    description=(
        "Sustituye al Java DataApp del TRUE Connector. "
        "POST /proxy para Postman. POST /data para el ECC."
    ),
    version="6.0.0",
)


# =============================================================================
# Utilidades IDS — construcción de mensajes
# =============================================================================

def _now_iso() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _ids_context() -> dict:
    return {
        "ids" : "https://w3id.org/idsa/core/",
        "idsc": "https://w3id.org/idsa/code/",
    }


def _security_token() -> dict:
    return {
        "@type"          : "ids:DynamicAttributeToken",
        "@id"            : "https://w3id.org/idsa/autogen/dynamicAttributeToken/d599a43f",
        "ids:tokenValue" : "DummyTokenValue",
        "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
    }


def _get_self_description() -> dict:
    resp = requests.get(
        f"https://{ECC_HOSTNAME}:8449/", verify=False, timeout=10
    )
    resp.raise_for_status()
    return resp.json()


def _multipart_response(header_dict: dict, payload_str: str = None) -> Response:
    """
    Construye respuesta multipart/form-data compatible con TRUE Connector.
    Formato exacto según documentación oficial TRUE Connector:
    - Content-Type: application/json; charset=UTF-8 en parte header
    - Content-Length en cada parte (requerido por el parser)
    """
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
    """Campos comunes a todas las respuestas IDS enviadas desde /data."""
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
#
# Replica exactamente el endpoint /proxy del Java DataApp (puerto 8184).
# Postman envía aquí el mismo JSON que enviaba al Java DataApp:
#   {
#     "multipart"  : "form",
#     "Forward-To" : "https://ecc-worker2:8889/data",
#     "messageType": "DescriptionRequestMessage",
#     "payload"    : { ... }            (opcional)
#     "requestedArtifact": "...",       (opcional)
#     "requestedElement" : "...",       (opcional)
#     "transferContract" : "..."        (opcional)
#   }
#
# Python construye el mensaje IDS multipart y lo posta directo al ECC destino.
# Devuelve la respuesta parseada a Postman como JSON.
# =============================================================================

@app.post("/proxy")
async def proxy(request: Request):
    """
    Punto de entrada para Postman — replica connectorA:8184/proxy del Java DataApp.
    """
    body = await request.json()

    forward_to        = body.get("Forward-To", "")
    message_type_raw  = body.get("messageType", "")
    payload_in        = body.get("payload", None)
    req_artifact      = body.get("requestedArtifact")
    req_element       = body.get("requestedElement")
    transfer_contract = body.get("transferContract")

    # ContractRequestMessage — construir payload si llegan IDs planos desde Postman
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

    # Normalizar messageType con prefijo ids:
    message_type = message_type_raw if message_type_raw.startswith("ids:") \
                   else f"ids:{message_type_raw}"

    dest_conn_uri = _infer_connector_uri(forward_to)

    log.info(f"[/proxy] {message_type} → {forward_to}")

    try:
        # ContractAgreementMessage requiere ids:correlationMessage obligatorio
        # Lo tomamos del transfer_contract (es el @id del acuerdo) si no viene explícito
        corr_msg = body.get("correlationMessage") or transfer_contract or None

        # Si es fl_algorithm, el contenido b64 viaja en el header IDS (ids:contentVersion)
        # para que el ECC receptor no lo descarte al reenviar al DataApp
        header_content_out = None
        if isinstance(payload_in, dict) and payload_in.get("type") == "fl_algorithm":
            header_content_out = payload_in.pop("content", None)
            log.info(f"[/proxy] fl_algorithm detectado — content ({len(header_content_out or '')} chars) → ids:tokenValue")

        result = _ids_send(
            forward_to_url       = forward_to,
            forward_to_connector = dest_conn_uri,
            message_type         = message_type,
            requested_artifact   = req_artifact,
            requested_element    = req_element,
            transfer_contract    = transfer_contract,
            payload              = payload_in,
            correlation_message  = corr_msg,
            header_content       = header_content_out,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        log.error(f"[/proxy] Error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=502,
            content={"error": str(exc), "forward_to": forward_to}
        )


def _infer_connector_uri(ecc_url: str) -> str:
    """Infiere la URI del conector a partir de la URL del ECC destino."""
    for url, uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
        if url in ecc_url or ecc_url in url:
            return uri
    import re
    m = re.search(r"ecc-worker(\d+)", ecc_url)
    if m:
        return f"http://w3id.org/engrd/connector/worker{m.group(1)}"
    return ecc_url


# =============================================================================
# Utilidades IDS — envío de mensajes salientes
#
# Python construye el mensaje IDS multipart completo y lo posta DIRECTAMENTE
# al ECC remoto en :8889/data (no hay proxy intermediario).
# =============================================================================

def _build_outgoing_header(message_type: str, dest_connector_uri: str,
                            extra: dict = None) -> dict:
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
    requested_artifact  : str  = None,
    requested_element   : str  = None,
    transfer_contract   : str  = None,
    payload             : dict = None,
    correlation_message : str  = None,
    header_content      : str  = None,
    header_content_type : str  = "fl_algorithm",
    peer_algorithm      : bool = False,
) -> dict:
    """
    Envía un mensaje IDS directamente al ECC remoto (:8889/data).
    Construye el multipart (header IDS + payload) y lo posta directo.
    La respuesta llega como multipart — se extrae la parte payload.

    header_content: base64 del algoritmo transportado en ids:contentVersion.
    El ECC nunca modifica este campo, por lo que llega intacto al DataApp receptor.
    """
    extra = {}
    if requested_artifact:  extra["ids:requestedArtifact"]  = {"@id": requested_artifact}
    if requested_element:   extra["ids:requestedElement"]   = {"@id": requested_element}
    if transfer_contract:   extra["ids:transferContract"]   = {"@id": transfer_contract}
    if correlation_message: extra["ids:correlationMessage"] = {"@id": correlation_message}
    if header_content:
        # El algoritmo viaja en ids:tokenValue del securityToken — campo string libre
        # que el ECC no valida ni modifica al reenviar
        extra["ids:securityToken"] = {
            "@type"          : "ids:DynamicAttributeToken",
            "@id"            : "https://w3id.org/idsa/autogen/dynamicAttributeToken/fl",
            "ids:tokenValue" : (f"{header_content_type}::from_coordinator::{header_content}" if peer_algorithm else f"{header_content_type}::{header_content}"),
            "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
        }

    header_dict = _build_outgoing_header(message_type, forward_to_connector, extra)
    str_header  = json.dumps(header_dict)
    # Tuple (filename, data, content_type) — MultipartEncoder sets Content-Type
    # as a part header, not injected into the body. TRUE Connector requires this.
    fields = {
        "header": ("header", str_header, "application/json")
    }

    if payload is not None:
        payload_str = json.dumps(payload) if not isinstance(payload, str) else payload
        fields["payload"] = ("payload", payload_str, "application/json")

    encoder = MultipartEncoder(fields=fields)
    log.info(f"[IDS OUT] {message_type} → {forward_to_url}")

    resp = requests.post(
        forward_to_url,
        data=encoder,
        headers={"Content-Type": encoder.content_type},
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()

    # Parsear respuesta multipart — extraer parte payload (no el header IDS)
    content_type = resp.headers.get("Content-Type", "")
    if "multipart" in content_type:
        try:
            decoder = MultipartDecoder(resp.content, content_type)
            parts_by_name = {}
            for part in decoder.parts:
                disp = part.headers.get(b"Content-Disposition", b"").decode("utf-8", errors="ignore")
                name = ""
                for seg in disp.split(";"):
                    seg = seg.strip()
                    if seg.startswith("name="):
                        name = seg.split("=", 1)[1].strip().strip('"')
                text = part.content.decode("utf-8", errors="ignore").strip()
                parts_by_name[name] = text
            # Preferir parte "payload" si existe, si no usar "header"
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
# Negociación IDS completa — coordinator → peer (enviar algorithm.py)
# =============================================================================

def _negotiate_and_send_algorithm(peer_ecc_url: str, peer_conn_uri: str,
                                   artifact_bytes: bytes) -> bool:
    """
    4 pasos IDS para enviar algorithm.py a un peer worker.
    Ejecutado por el coordinator al recibir fl_algorithm de Postman.
    """
    log.info(f"[coordinator] Negociación con {peer_ecc_url}")
    try:
        # 1. DescriptionRequestMessage
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

        # 2. ContractRequestMessage
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

        # 3. ContractAgreementMessage
        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            payload=agreement,
        )
        log.info(f"[coordinator] 3/4 Acuerdo confirmado")

        # 4. ArtifactRequestMessage — algorithm.py en base64
        algo_b64 = base64.b64encode(artifact_bytes).decode("utf-8")
        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            header_content=algo_b64,
            header_content_type="fl_algorithm",
            peer_algorithm=True,
            payload={
                "type"            : "fl_algorithm",
                "filename"        : "algorithm.py",
                "content"         : algo_b64,
                "sender"          : f"coordinator-{INSTANCE_ID}",
                "from_coordinator": True,
            },
        )
        log.info(f"[coordinator] 4/4 algorithm.py → {peer_ecc_url} ✅")
        return True

    except Exception as exc:
        log.error(f"[coordinator] Error con {peer_ecc_url}: {exc}", exc_info=True)
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
    """FedAvg — McMahan et al. (2017). Promedio ponderado por n_samples."""
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
    """
    Guarda las métricas locales de este worker tras cada ronda en:
      /home/nobody/data/output/local_metrics.json
    Acumula todas las rondas en el mismo fichero.
    """
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

        log.info(f"Métricas ronda {round_num} guardadas en {metrics_path}")
    except Exception as e:
        log.error(f"Error guardando métricas locales: {e}")


def _train_local(global_weights_b64: str, round_num: int) -> dict:
    result = _load_algorithm().run(_csv_path(), global_weights_b64=global_weights_b64)
    log.info(
        f"Ronda {round_num} — local OK  "
        f"acc={result['metrics']['accuracy']:.4f}  "
        f"auc={result['metrics']['auc']:.4f}"
    )
    _save_local_metrics(result, round_num)
    return result


def _send_global_weights(peer_ecc_url: str, peer_conn_uri: str,
                          weights_b64: str, round_num: int):
    """Coordinator → Worker: envía pesos globales de la ronda."""
    try:
        import base64 as _b64
        fl_payload = {
            "type"              : "fl_global_weights",
            "round"             : round_num,
            "global_weights_b64": weights_b64,
            "from_coordinator"  : INSTANCE_ID,
            "coordinator_ecc"   : f"https://{ECC_HOSTNAME}:8889/data",
            "coordinator_uri"   : CONNECTOR_URI,
        }
        payload_b64 = _b64.b64encode(json.dumps(fl_payload).encode()).decode()
        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ArtifactRequestMessage",
            requested_artifact=(
                f"http://w3id.org/engrd/connector/artifact/fl_global_round{round_num}"
            ),
            header_content=payload_b64,
            header_content_type="fl_global_weights",
            payload=fl_payload,
        )
        log.info(f"Pesos globales ronda {round_num} → {peer_ecc_url} ✅")
    except Exception as exc:
        log.error(f"Error enviando pesos globales a {peer_ecc_url}: {exc}")


def _send_local_weights(weights_b64: str, n_samples: int,
                         metrics: dict, round_num: int):
    """Worker → Coordinator: devuelve pesos locales tras entrenar."""
    if not coordinator_ecc_url:
        log.error("coordinator_ecc_url no definido")
        return
    try:
        import base64 as _b64
        fl_payload = {
            "type"       : "fl_weights",
            "instance_id": INSTANCE_ID,
            "round"      : round_num,
            "weights_b64": weights_b64,
            "n_samples"  : n_samples,
            "metrics"    : metrics,
        }
        payload_b64 = _b64.b64encode(json.dumps(fl_payload).encode()).decode()
        _ids_send(
            coordinator_ecc_url,
            coordinator_conn_uri or CONNECTOR_URI,
            "ids:ArtifactRequestMessage",
            requested_artifact=(
                f"http://w3id.org/engrd/connector/artifact/fl_weights_worker{INSTANCE_ID}"
            ),
            header_content=payload_b64,
            header_content_type="fl_weights",
            payload=fl_payload,
        )
        log.info(f"Pesos ronda {round_num} enviados al coordinator ✅")
    except Exception as exc:
        log.error(f"Error enviando pesos locales: {exc}")


def _publish_fl_model_as_ids_resource(global_weights_b64: str, global_metrics: dict, n_rounds: int):
    """
    Al terminar el FL, el coordinator publica el modelo global como un nuevo
    recurso IDS en su propio ECC con acceso restringido a los peers participantes.

    Flujo:
      1. GET  /api/selfDescription/         → obtener catalog @id
      2. POST /api/offeredResource/         → crear recurso fl_model_final
      3. POST /api/contractOffer/           → contrato restringido a los peers
      4. POST /api/representation/          → representación con los pesos

    Todo apunta al ECC del coordinator (ECC_HOSTNAME e INSTANCE_ID dinámicos).
    """
    from requests.auth import HTTPBasicAuth
    basic_api = HTTPBasicAuth(API_USER, API_PASS)
    ecc_base  = f"https://{ECC_HOSTNAME}:8449"

    resource_id = (
        f"https://w3id.org/idsa/autogen/textResource/fl_model_"
        f"coordinator{INSTANCE_ID}_{uuid.uuid4().hex[:8]}"
    )
    artifact_id = (
        f"http://w3id.org/engrd/connector/artifact/fl_model_final_{INSTANCE_ID}"
    )
    contract_id = (
        f"https://w3id.org/idsa/autogen/contractOffer/fl_model_"
        f"coordinator{INSTANCE_ID}_{uuid.uuid4().hex[:8]}"
    )
    repr_id = (
        f"https://w3id.org/idsa/autogen/representation/fl_model_"
        f"coordinator{INSTANCE_ID}_{uuid.uuid4().hex[:8]}"
    )

    try:
        # ── 1. Obtener catalog @id desde la self-description ──────────────────
        log.info("[publish] Obteniendo catalog ID del ECC...")
        sd       = requests.get(f"{ecc_base}/api/selfDescription/",
                                verify=False, auth=basic_api, timeout=10).json()
        catalogs = sd.get("ids:resourceCatalog", [])
        if not catalogs:
            log.error("[publish] No se encontró ningún catalog en la self-description")
            return
        catalog_id = catalogs[0].get("@id", "")
        if not catalog_id:
            log.error("[publish] catalog @id vacío")
            return
        log.info(f"[publish] Catalog ID: {catalog_id}")

        # ── 2. Crear recurso fl_model_final ───────────────────────────────────
        log.info("[publish] Creando recurso IDS fl_model_final...")
        resource_body = {
            "@id"             : resource_id,
            "@type"           : "ids:Resource",
            "ids:title"       : [{"@value": f"FL Global Model — Coordinator {INSTANCE_ID}", "@language": "en"}],
            "ids:description" : [{"@value":
                f"Modelo federado final tras {n_rounds} rondas. "
                f"acc={global_metrics.get('accuracy','?')}  "
                f"auc={global_metrics.get('auc','?')}",
                "@language": "en"
            }],
            "ids:keyword"     : [{"@value": "federated-learning", "@language": "en"},
                                 {"@value": "fl-model",           "@language": "en"}],
            "ids:version"     : f"round_{n_rounds}",
        }
        resp = requests.post(
            f"{ecc_base}/api/offeredResource/",
            headers={"catalog": catalog_id, "Content-Type": "application/json"},
            json=resource_body,
            verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando recurso: {resp.status_code} {resp.text[:200]}")
            return
        log.info(f"[publish] ✅ Recurso creado: {resource_id}")

        # ── 3. Añadir contrato restringido a los peers participantes ──────────
        log.info("[publish] Añadiendo contrato IDS restringido a peers...")
        permissions = []
        for peer_uri in PEER_CONNECTOR_URIS:
            permissions.append({
                "@type"       : "ids:Permission",
                "@id"         : f"https://w3id.org/idsa/autogen/permission/{uuid.uuid4()}",
                "ids:action"  : [{"@id": "https://w3id.org/idsa/code/USE"}],
                "ids:assignee": [{"@id": peer_uri}],
                "ids:assigner": [{"@id": CONNECTOR_URI}],
                "ids:target"  : {"@id": artifact_id},
            })

        contract_body = {
            "@id"           : contract_id,
            "@type"         : "ids:ContractOffer",
            "ids:provider"  : {"@id": CONNECTOR_URI},
            "ids:permission": permissions,
            "ids:obligation": [],
            "ids:prohibition": [],
        }
        resp = requests.post(
            f"{ecc_base}/api/contractOffer/",
            headers={"resource": resource_id, "Content-Type": "application/json"},
            json=contract_body,
            verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando contrato: {resp.status_code} {resp.text[:200]}")
            return
        log.info(f"[publish] ✅ Contrato creado: {contract_id}")

        # ── 4. Añadir representación con el artifact (pesos finales) ──────────
        log.info("[publish] Añadiendo representación con pesos finales...")
        repr_body = {
            "@id"          : repr_id,
            "@type"        : "ids:Representation",
            "ids:mediaType": {
                "@type"                : "ids:IANAMediaType",
                "@id"                  : f"https://w3id.org/idsa/autogen/mediaType/{uuid.uuid4().hex[:8]}",
                "ids:filenameExtension": "json",
            },
            "ids:instance" : [{
                "@type"           : "ids:Artifact",
                "@id"             : artifact_id,
                "ids:fileName"    : f"fl_global_model_coordinator{INSTANCE_ID}.json",
                "ids:byteSize"    : len(global_weights_b64),
                "ids:creationDate": {
                    "@value": _now_iso(),
                    "@type" : "http://www.w3.org/2001/XMLSchema#dateTimeStamp",
                },
                "ids:checkSum"    : str(hash(global_weights_b64))[:16],
            }],
        }
        resp = requests.post(
            f"{ecc_base}/api/representation/",
            headers={"resource": resource_id, "Content-Type": "application/json"},
            json=repr_body,
            verify=False, auth=basic_api, timeout=10
        )
        if not resp.ok:
            log.error(f"[publish] Error creando representación: {resp.status_code} {resp.text[:200]}")
            return
        log.info(f"[publish] ✅ Representación creada: {repr_id}")

        log.info(
            f"🎉 Modelo FL publicado como recurso IDS en coordinator-{INSTANCE_ID}\n"
            f"   Resource  : {resource_id}\n"
            f"   Artifact  : {artifact_id}\n"
            f"   Contrato  : {contract_id} (restringido a {len(PEER_CONNECTOR_URIS)} peers)\n"
            f"   Peers     : {PEER_CONNECTOR_URIS}"
        )

    except Exception as exc:
        log.error(f"[publish] Error publicando modelo IDS: {exc}", exc_info=True)


def _run_fl(n_rounds: int):
    """
    Bucle FL — ejecutado en hilo separado por el coordinator.
    Por cada ronda:
      1. Envía pesos globales a los 2 peers en paralelo
      2. Entrena localmente (coordinator también es worker)
      3. Espera pesos de ambos peers (timeout: ROUND_TIMEOUT)
      4. FedAvg + checkpoint
    """
    global fl_state

    with _fl_lock:
        fl_state.update({"status": "running", "current_round": 0, "history": []})

    global_weights_b64 = None
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

        # Enviar pesos globales a peers en paralelo
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(PEER_ECC_URLS)) as ex:
            for peer_url, peer_uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
                ex.submit(_send_global_weights, peer_url, peer_uri,
                          global_weights_b64, round_num)

        # Entrenamiento local del coordinator
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

        # Esperar pesos de todos (peers + coordinator)
        expected = len(PEER_ECC_URLS) + 1
        deadline = time.time() + ROUND_TIMEOUT
        while time.time() < deadline:
            with _round_lock:
                if len(_round_weights) >= expected:
                    break
            log.info(f"Esperando pesos... {len(_round_weights)}/{expected}")
            time.sleep(2)

        with _round_lock:
            results = list(_round_weights.values())

        if not results:
            log.error(f"Ronda {round_num}: ningún worker respondió — abortando")
            with _fl_lock:
                fl_state["status"] = "failed"
            return

        # FedAvg + métricas ponderadas
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

        with open(model_path, "w") as f:
            json.dump({
                "round"      : round_num,
                "weights_b64": global_weights_b64,
                "metrics"    : global_metrics,
            }, f)

        log.info(
            f"Ronda {round_num} OK en {elapsed}s  "
            f"acc={global_metrics.get('accuracy','?')}  "
            f"auc={global_metrics.get('auc','?')}"
        )

    with _fl_lock:
        fl_state["status"] = "completed"

    with open(os.path.join(OUTPUT_DIR, "fl_results.json"), "w") as f:
        json.dump(fl_state["history"], f, indent=2)

    log.info(f"✅ FL completado — {n_rounds} rondas")

    # Publicar modelo final como recurso IDS restringido a los peers participantes
    try:
        last_metrics = fl_state["history"][-1]["global_metrics"] if fl_state["history"] else {}
        _publish_fl_model_as_ids_resource(global_weights_b64, last_metrics, n_rounds)
    except Exception as exc:
        log.error(f"Error publicando modelo IDS (no crítico): {exc}")


# =============================================================================
# POST /data — mensajes IDS entrantes del ECC
#
# DATA_APP_ENDPOINT = http://be-dataapp-workerN:8500/data
# El ECC recibe mensajes de otros ECCs y los reenvía aquí.
#
# Tipos de artefacto FL (campo "type" en payload):
#   fl_algorithm      → coordinator recibe algorithm.py desde Postman vía IDS,
#                        distribuye a peers y arranca FL
#   fl_global_weights → worker recibe pesos globales, entrena, devuelve pesos
#   fl_weights        → coordinator acumula pesos locales para FedAvg
# =============================================================================

@app.post("/data")
async def ids_data(request: Request):
    """
    Recibe mensajes IDS del ECC. El ECC v1.14.8 puede enviar multipart/mixed
    o multipart/form-data — se parsea manualmente para cubrir ambos casos.
    """
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
                # El ECC puede enviar las cabeceras MIME incrustadas en el texto
                if "\n\n" in text:
                    text = text.split("\n\n", 1)[-1].strip()
                if 'name="header"' in disp:
                    header_val = text
                elif 'name="payload"' in disp:
                    payload_val = text
                elif not header_val and (text.startswith("{") or text.startswith("[")):
                    # Primera parte JSON sin nombre explícito → es el header IDS
                    header_val = text
        except Exception as e:
            log.error(f"[/data] Error parseando multipart: {e} | CT={content_type}")
            return JSONResponse(status_code=400, content={"error": f"multipart parse error: {e}"})
    else:
        # Fallback form urlencoded
        try:
            form        = await request.form()
            header_val  = form.get("header")
            payload_val = form.get("payload")
        except Exception as e:
            log.error(f"[/data] Error leyendo form: {e}")

    if not header_val:
        log.error(f"[/data] Campo 'header' no encontrado. CT={content_type} | body[:300]={raw_body[:300]}")
        return JSONResponse(status_code=400, content={"error": "missing IDS header field"})

    header  = header_val
    payload = payload_val

    mensaje = json.loads(header)
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
            body_resp = requests.get(
                url, headers=hdrs, verify=False, auth=basic_api, timeout=10
            ).json()

        return _multipart_response(
            _resp("ids:DescriptionResponseMessage", "descriptionResponseMessage"),
            json.dumps(body_resp)
        )

    # ── ContractRequestMessage ────────────────────────────────────────────────
    elif tipo == "ids:ContractRequestMessage":
        payload_dict      = json.loads(payload) if payload else {}
        contract_offer_id = payload_dict.get("@id", "")

        # ── FALLBACK: si el ID llega vacío, inferirlo desde la self-description
        if not contract_offer_id:
            log.warning("[ContractRequest] contract_id vacío — infiriendo desde self-description")
            try:
                sd        = _get_self_description()
                catalogs  = sd.get("ids:resourceCatalog", [{}])
                resource  = (catalogs[0].get("ids:offeredResource", [{}]) or [{}])[0]
                contract  = (resource.get("ids:contractOffer", [{}]) or [{}])[0]
                contract_offer_id = contract.get("@id", "")
                log.info(f"[ContractRequest] contract_id inferido: {contract_offer_id}")
            except Exception as e:
                log.error(f"[ContractRequest] No se pudo inferir contract_id: {e}")

        url      = f"https://{ECC_HOSTNAME}:8449/api/contractOffer/"
        hdrs     = {"contractOffer": contract_offer_id}
        contrato = requests.get(
            url, headers=hdrs, verify=False, auth=basic_api, timeout=10
        ).json()

        # ── Convertir ContractOffer → ContractAgreement ───────────────────────
        # TRUE Connector devuelve la oferta original; hay que promoverla a acuerdo
        # para que el consumer (Postman) pueda extraer el @id como transfer_contract
        contrato["@type"]            = "ids:ContractAgreement"
        contrato["ids:consumer"]     = mensaje["ids:issuerConnector"]
        # Asignar nuevo @id de acuerdo si el que viene es de tipo contractOffer
        orig_id = contrato.get("@id", "")
        if "contractOffer" in orig_id or not orig_id:
            import uuid as _uuid
            contrato["@id"] = (
                f"https://w3id.org/idsa/autogen/contractAgreement/{_uuid.uuid4()}"
            )
        log.info(f"[ContractRequest] ContractAgreement generado: {contrato['@id']}")

        return _multipart_response(
            _resp("ids:ContractAgreementMessage", "contractAgreementMessage"),
            json.dumps(contrato)
        )

    # ── ContractAgreementMessage ──────────────────────────────────────────────
    elif tipo == "ids:ContractAgreementMessage":
        return _multipart_response(
            _resp("ids:MessageProcessedNotificationMessage",
                  "messageProcessedNotificationMessage")
        )

    # ── ArtifactRequestMessage ────────────────────────────────────────────────
    elif tipo == "ids:ArtifactRequestMessage":
        try:
            payload_dict = json.loads(payload) if payload else {}
        except Exception:
            payload_dict = {}

        # Recuperar algoritmo desde ids:contentVersion del header IDS si payload llegó vacío
        # (el ECC descarta el payload multipart pero preserva todos los campos del header)
        # ids:securityToken.ids:tokenValue transporta el algoritmo b64
        # cuando el ECC descarta el payload multipart
        if not payload_dict.get("type"):
            token = mensaje.get("ids:securityToken", {})
            token_val = token.get("ids:tokenValue", "") if isinstance(token, dict) else ""
            import base64 as _b64
            for prefix in ("fl_algorithm", "fl_global_weights", "fl_weights"):
                if token_val.startswith(f"{prefix}::"):
                    rest = token_val[len(f"{prefix}::"):]
                    from_coord = rest.startswith("from_coordinator::")
                    payload_b64 = rest[len("from_coordinator::"):] if from_coord else rest
                    if prefix == "fl_algorithm":
                        payload_dict = {"type": "fl_algorithm", "content": payload_b64, "from_coordinator": from_coord}
                        log.info(f"[ArtifactRequest] fl_algorithm recuperado desde tokenValue ({len(payload_b64)} chars) | from_coordinator={from_coord}")
                    else:
                        try:
                            payload_dict = json.loads(_b64.b64decode(payload_b64).decode())
                            log.info(f"[ArtifactRequest] {prefix} recuperado desde tokenValue | keys={list(payload_dict.keys())}")
                        except Exception as e:
                            log.error(f"[ArtifactRequest] Error decodificando tokenValue {prefix}: {e}")
                    break

        artifact_type = payload_dict.get("type", "")
        log.info(f"[ArtifactRequest] artifact_type={artifact_type!r} | payload keys={list(payload_dict.keys())}")
        log.info(f"[ArtifactRequest] header keys IDS: {[k for k in mensaje.keys() if 'ids:' in k]}")
        resp_h = _resp(
            "ids:ArtifactResponseMessage", "artifactResponseMessage",
            {"ids:transferContract": mensaje.get("ids:transferContract", {})}
        )

        # fl_weights — pesos locales de un worker → coordinator acumula
        if artifact_type == "fl_weights":
            sender    = payload_dict.get("instance_id", "?")
            round_num = payload_dict.get("round", 0)
            log.info(f"Pesos de worker-{sender} (ronda {round_num})")
            with _round_lock:
                _round_weights[sender] = {
                    "weights_b64": payload_dict["weights_b64"],
                    "n_samples"  : payload_dict["n_samples"],
                    "metrics"    : payload_dict["metrics"],
                }
            return _multipart_response(
                resp_h,
                json.dumps({"status": "weights_received", "from": sender})
            )

        # fl_global_weights — pesos globales → este worker entrena
        if artifact_type == "fl_global_weights":
            round_num          = payload_dict.get("round", 1)
            global_weights_b64 = payload_dict.get("global_weights_b64")

            if not coordinator_ecc_url:
                coordinator_ecc_url  = payload_dict.get("coordinator_ecc")
                coordinator_conn_uri = payload_dict.get("coordinator_uri")
                log.info(f"Coordinator ECC: {coordinator_ecc_url}")

            log.info(f"Pesos globales ronda {round_num} — iniciando entrenamiento")

            def _train_and_reply():
                try:
                    result = _train_local(global_weights_b64, round_num)
                    _send_local_weights(
                        result["weights_b64"], result["n_samples"],
                        result["metrics"], round_num
                    )
                except Exception as exc:
                    log.error(f"Error ronda {round_num}: {exc}")

            threading.Thread(target=_train_and_reply, daemon=True).start()
            return _multipart_response(
                resp_h,
                json.dumps({"status": "training_started", "round": round_num})
            )

        # fl_algorithm — coordinator recibe algorithm.py → distribuye y arranca FL
        if artifact_type == "fl_algorithm":
            content_b64 = payload_dict.get("content", "")
            try:
                algo_bytes = base64.b64decode(content_b64)
            except Exception:
                algo_bytes = content_b64.encode() if isinstance(content_b64, str) else b""

            _save_algorithm(algo_bytes)
            if payload_dict.get("from_coordinator"):
                log.info(f"✔ algorithm.py recibido del coordinator — worker-{INSTANCE_ID} mantiene rol WORKER")
            else:
                is_coordinator = True
                log.info(f"★ algorithm.py recibido desde Postman — worker-{INSTANCE_ID} = COORDINATOR")
            log.info(f"  FL listo para arrancar — llama a POST /fl/start")
            return _multipart_response(
                resp_h,
                json.dumps({
                    "status"     : "algorithm_received",
                    "coordinator": INSTANCE_ID,
                    "fl_rounds"  : FL_ROUNDS,
                    "next_step"  : "POST /fl/start to begin training"
                }),
            )

        log.warning(f"Tipo de artefacto desconocido: {artifact_type!r}")
        return _multipart_response(
            resp_h,
            json.dumps({"status": "unknown_artifact_type", "received": artifact_type})
        )

    log.warning(f"Mensaje no manejado: {tipo}")
    return JSONResponse(status_code=200, content={"status": "ignored", "type": tipo})


@app.get("/data")
async def ids_data_get():
    return {"instance": INSTANCE_ID, "role": "coordinator" if is_coordinator else "worker"}


# =============================================================================
# Monitorización
# =============================================================================


@app.post("/fl/start")
async def fl_start(request: Request):
    """
    Arranca el ciclo FL completo desde el coordinator.
    Distribuye algorithm.py a los peers vía IDS y lanza FedAvg.

    Body opcional:
        { "rounds": 5 }   ← si no se indica, usa FL_ROUNDS del entorno
    """
    global is_coordinator

    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Este worker no es coordinator. Envía el algoritmo primero (paso 5)."}
        )

    algo_path = ALGO_IDS_PATH if os.path.exists(ALGO_IDS_PATH) else ALGO_BAKED_PATH
    if not os.path.exists(algo_path):
        return JSONResponse(
            status_code=400,
            content={"error": "algorithm.py no encontrado. Envía el algoritmo primero (paso 5)."}
        )

    with open(algo_path, "rb") as f:
        algo_bytes = f.read()

    try:
        body = await request.json()
        rounds = int(body.get("rounds", FL_ROUNDS))
    except Exception:
        rounds = FL_ROUNDS

    rounds = max(1, rounds)
    log.info(f"[/fl/start] Arrancando FL — {rounds} rondas — coordinator-{INSTANCE_ID}")

    def _launch():
        log.info(f"Distribuyendo algorithm.py a {len(PEER_ECC_URLS)} peers…")
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(len(PEER_ECC_URLS), 1)) as ex:
            futures = {
                ex.submit(_negotiate_and_send_algorithm, p, u, algo_bytes): p
                for p, u in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS)
            }
            for fut in concurrent.futures.as_completed(futures):
                peer = futures[fut]
                try:
                    ok = fut.result()
                    log.info(f"  → {peer}: {'✅' if ok else '❌'}")
                except Exception as exc:
                    log.error(f"  → {peer}: ❌ {exc}")
        _run_fl(rounds)

    threading.Thread(target=_launch, daemon=True).start()

    return JSONResponse(
        status_code=202,
        content={
            "status"     : "started",
            "coordinator": INSTANCE_ID,
            "fl_rounds"  : rounds,
        }
    )


@app.get("/health")
def health():
    return {
        "status"  : "ok",
        "instance": INSTANCE_ID,
        "role"    : "coordinator" if is_coordinator else "worker",
    }


@app.get("/status")
def status():
    csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    try:
        csv_sel = _csv_path()
    except FileNotFoundError:
        csv_sel = None
    return {
        "instance"        : INSTANCE_ID,
        "role"            : "coordinator" if is_coordinator else "worker",
        "algorithm_loaded": os.path.exists(ALGO_IDS_PATH),
        "csv_available"   : csv_files,
        "csv_selected"    : csv_sel,
        "coordinator_ecc" : coordinator_ecc_url,
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