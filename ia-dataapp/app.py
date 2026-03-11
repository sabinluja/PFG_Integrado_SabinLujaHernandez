"""
app.py  —  IA DataApp Worker/Coordinator
=========================================

Flujo desde Postman (tú eres el coordinator en worker-1):
  1. POST /proxy  DescriptionRequestMessage → ecc-worker2:8889/data
  2. POST /proxy  ContractRequestMessage    → ecc-worker2:8889/data
  3. POST /proxy  ContractAgreementMessage  → ecc-worker2:8889/data
  4. POST /proxy  ArtifactRequestMessage    → ecc-worker2:8889/data
     payload: {
       "type": "fl_algorithm",
       "content": "<base64 de algorithm.py>",
       "config": "<base64 de fl_config.json>"   ← NUEVO
     }
     → worker-2 recibe algorithm.py + fl_config.json, se convierte en COORDINATOR,
       distribuye ambos a los workers y arranca el FL con los parámetros del JSON.

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
    """
    Lee fl_config.json guardado en DATA_DIR.
    Si no existe, devuelve valores por defecto.
    Estos valores también los lee algorithm.py directamente en cada ronda.
    """
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

fl_state = {
    "status"       : "idle",
    "current_round": 0,
    "total_rounds" : 0,   # se rellena al arrancar desde fl_config.json
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
    version="7.0.0",
)


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


def _security_token() -> dict:
    return {
        "@type"          : "ids:DynamicAttributeToken",
        "@id"            : "https://w3id.org/idsa/autogen/dynamicAttributeToken/d599a43f",
        "ids:tokenValue" : "DummyTokenValue",
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


def _multipart_response(header_dict: dict, payload_str: str = None) -> Response:
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

        header_content_out = None
        if isinstance(payload_in, dict) and payload_in.get("type") == "fl_algorithm":
            algo_b64   = payload_in.pop("content", None) or ""
            config_b64 = payload_in.pop("config",  None) or ""
            # Empaquetar ambos en tokenValue: "<algo_b64>||fl_config::<config_b64>"
            header_content_out = f"{algo_b64}||fl_config::{config_b64}" if config_b64 else algo_b64
            log.info(f"[/proxy] fl_algorithm detectado — content+config → ids:tokenValue (config={'present' if config_b64 else 'absent'})")

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
    for url, uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
        if url in ecc_url or ecc_url in url:
            return uri
    import re
    m = re.search(r"ecc-worker(\d+)", ecc_url)
    if m:
        return f"http://w3id.org/engrd/connector/worker{m.group(1)}"
    return ecc_url


# =============================================================================
# Utilidades IDS — envío saliente
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
    str_header  = json.dumps(header_dict)
    fields = {"header": ("header", str_header, "application/json")}

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
# Negociación IDS completa — coordinator → peer (enviar algorithm.py + config)
# =============================================================================

def _negotiate_and_send_algorithm(peer_ecc_url: str, peer_conn_uri: str,
                                   artifact_bytes: bytes,
                                   config_bytes: bytes) -> bool:
    """
    4 pasos IDS para enviar algorithm.py + fl_config.json a un peer worker.
    """
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

        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            payload=agreement,
        )
        log.info(f"[coordinator] 3/4 Acuerdo confirmado")

        # Empaquetar algorithm.py + fl_config.json juntos en el tokenValue
        algo_b64   = base64.b64encode(artifact_bytes).decode("utf-8")
        config_b64 = base64.b64encode(config_bytes).decode("utf-8")
        combined   = f"{algo_b64}||fl_config::{config_b64}"

        _ids_send(
            peer_ecc_url, peer_conn_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            header_content=combined,
            header_content_type="fl_algorithm",
            peer_algorithm=True,
            payload={
                "type"            : "fl_algorithm",
                "filename"        : "algorithm.py",
                "content"         : algo_b64,
                "config"          : config_b64,
                "sender"          : f"coordinator-{INSTANCE_ID}",
                "from_coordinator": True,
            },
        )
        log.info(f"[coordinator] 4/4 algorithm.py + fl_config.json → {peer_ecc_url} ✅")
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


def _save_config(data: bytes):
    """Guarda fl_config.json en DATA_DIR."""
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


def _train_local(global_weights_b64: str, round_num: int) -> dict:
    # Pasa CONFIG_PATH a algorithm.run() para que lea los hiperparámetros
    result = _load_algorithm().run(
        _csv_path(),
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

        log.info("[publish] Añadiendo contrato restringido a peers (connector-restricted-policy)...")
        allowed_uris = [{"@value": u, "@type": "http://www.w3.org/2001/XMLSchema#anyURI"}
                        for u in PEER_CONNECTOR_URIS]
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
            f"   Contrato  : {contract_id} (restringido a {len(PEER_CONNECTOR_URIS)} peers)"
        )

    except Exception as exc:
        log.error(f"[publish] Error: {exc}", exc_info=True)


def _run_fl(n_rounds: int, round_timeout: int, min_workers: int,
             algo_bytes: bytes = None, config_bytes: bytes = None):
    """
    Bucle FL — parámetros leídos de fl_config.json.
    El coordinator distribuye algorithm.py + fl_config.json a los peers
    al inicio de CADA ronda, garantizando independencia entre rondas.
    """
    global fl_state

    with _fl_lock:
        fl_state.update({"status": "running", "current_round": 0,
                          "total_rounds": n_rounds, "history": []})

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

        # Distribuir algorithm.py + fl_config.json al inicio de cada ronda
        if algo_bytes:
            log.info(f"[ronda {round_num}] Distribuyendo algorithm.py + fl_config.json a peers…")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(PEER_ECC_URLS), 1)) as ex:
                futures = {
                    ex.submit(_negotiate_and_send_algorithm, p, u, algo_bytes, config_bytes or b"{}"): p
                    for p, u in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS)
                }
                for fut in concurrent.futures.as_completed(futures):
                    peer = futures[fut]
                    try:
                        ok = fut.result()
                        log.info(f"  [ronda {round_num}] → {peer}: {'✅' if ok else '❌'}")
                    except Exception as exc:
                        log.error(f"  [ronda {round_num}] → {peer}: ❌ {exc}")

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

        with open(model_path, "w") as f:
            json.dump({"round": round_num, "weights_b64": global_weights_b64, "metrics": global_metrics}, f)

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

    try:
        last_metrics = fl_state["history"][-1]["global_metrics"] if fl_state["history"] else {}
        _publish_fl_model_as_ids_resource(global_weights_b64, last_metrics, n_rounds)
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

        # ── Comprobación de acceso: solo peers autorizados pueden negociar ──
        consumer_uri = mensaje.get("ids:issuerConnector", {}).get("@id", "")
        if PEER_CONNECTOR_URIS and consumer_uri not in PEER_CONNECTOR_URIS:
            log.warning(
                f"[ContractRequest] ACCESO DENEGADO — connector no autorizado: {consumer_uri!r}\n"
                f"  Peers autorizados: {PEER_CONNECTOR_URIS}"
            )
            # ids:RejectionMessage es el tipo base que el ECC de TRUE Connector
            # reenvía correctamente. ids:ContractRejectionMessage causa un 500.
            rejection_header = _resp(
                "ids:RejectionMessage", "rejectionMessage",
                {"ids:rejectionReason": {"@id": "https://w3id.org/idsa/code/NOT_AUTHORIZED"}}
            )
            return _multipart_response(rejection_header, json.dumps({
                "status"  : "rejected",
                "reason"  : "unauthorized_consumer",
                "consumer": consumer_uri,
                "message" : (
                    f"Connector {consumer_uri!r} is not authorised to access "
                    "this federated learning resource."
                )
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

        # Recuperar desde tokenValue si payload llegó vacío
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
                        # Separar algorithm.py de fl_config.json si vienen juntos
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

        # También intentar extraer config del payload JSON si viene por esa vía
        if payload_dict.get("type") == "fl_algorithm" and not payload_dict.get("config"):
            if payload_val:
                try:
                    pv = json.loads(payload_val)
                    if pv.get("config"):
                        payload_dict["config"] = pv["config"]
                except Exception:
                    pass

        artifact_type = payload_dict.get("type", "")
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
            return _multipart_response(resp_h, json.dumps({"status": "weights_received", "from": sender}))

        # fl_global_weights — worker entrena localmente
        if artifact_type == "fl_global_weights":
            round_num          = payload_dict.get("round", 1)
            global_weights_b64 = payload_dict.get("global_weights_b64")

            if not coordinator_ecc_url:
                coordinator_ecc_url  = payload_dict.get("coordinator_ecc")
                coordinator_conn_uri = payload_dict.get("coordinator_uri")

            def _train_and_reply():
                try:
                    result = _train_local(global_weights_b64, round_num)
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

            # Guardar fl_config.json si viene en el mensaje
            if config_b64:
                try:
                    config_bytes = base64.b64decode(config_b64)
                    _save_config(config_bytes)
                except Exception as e:
                    log.warning(f"No se pudo guardar fl_config.json: {e}")
            else:
                log.warning("fl_config.json no recibido — usando valores por defecto")

            if payload_dict.get("from_coordinator"):
                log.info(f"✔ algorithm.py + config recibidos del coordinator — worker-{INSTANCE_ID} = WORKER")
            else:
                is_coordinator = True
                log.info(f"★ algorithm.py + config recibidos desde Postman — worker-{INSTANCE_ID} = COORDINATOR")

            cfg = _load_fl_config()
            return _multipart_response(
                resp_h,
                json.dumps({
                    "status"      : "algorithm_received",
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

@app.post("/fl/start")
async def fl_start(request: Request):
    """
    Arranca el ciclo FL completo desde el coordinator.
    Los parámetros (rounds, round_timeout, min_workers) se leen de fl_config.json.
    Ya NO se aceptan en el body — todo viene del JSON enviado en el paso 5.
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

    # Leer configuración desde fl_config.json (o defaults si no existe)
    cfg           = _load_fl_config()
    rounds        = int(cfg["rounds"])
    round_timeout = int(cfg["round_timeout"])
    min_workers   = int(cfg["min_workers"])

    log.info(
        f"[/fl/start] Arrancando FL — coordinator-{INSTANCE_ID}\n"
        f"  rounds={rounds}  round_timeout={round_timeout}s  min_workers={min_workers}"
    )

    with open(algo_path, "rb") as f:
        algo_bytes = f.read()

    # Leer config bytes para redistribuir a peers
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            config_bytes = f.read()
    else:
        config_bytes = json.dumps(cfg).encode()

    def _launch():
        _run_fl(rounds, round_timeout, min_workers, algo_bytes, config_bytes)

    threading.Thread(target=_launch, daemon=True).start()

    return JSONResponse(
        status_code=202,
        content={
            "status"     : "started",
            "coordinator": INSTANCE_ID,
            "fl_config"  : {
                "rounds"       : rounds,
                "round_timeout": round_timeout,
                "min_workers"  : min_workers,
            },
        }
    )


@app.get("/ids/self-description")
def ids_self_description():
    try:
        return JSONResponse(content=_get_self_description())
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.get("/ids/contract")
def ids_contract(contractOffer: str = None, request: Request = None):
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
        "fl_config"       : cfg,
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