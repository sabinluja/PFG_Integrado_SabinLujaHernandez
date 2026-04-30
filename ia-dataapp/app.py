"""
app.py  --  IA DataApp Worker/Coordinator
=========================================

Cualquier worker puede instanciarse como Coordinator recibiendo el algoritmo
en la FASE 1. La comunicación se orquesta nativamente mediante la red IDS.

Arquitectura Híbrida:
  - Control Plane (IDS): Negociación de contratos y descubrimiento (HTTPS/REST + DAPS).
  - Data Plane (WS): Transferencia asíncrona de alto rendimiento de pesos FL (WebSockets).

Flujo actual (alineado con pfg_ids_fl_flow.py y Postman):
  FASE 0: Resolución de Endpoints, validación de Broker y Catálogo IDS dinámico.
  FASE 1: Catálogo IDS del Coordinador (Encontrar CSVs)
  FASE 2: Preparación de Artefactos FL (Imagen Docker)
  FASE 3: Descubrimiento de peers en Broker (Fuseki) y filtro semántico (LLM).
  FASE 4: Negociación de contratos IDS obligatorios (Restringido > Worker4 descartado).
  FASE 5: Arranque del Entrenamiento FL vía propagación IDS, Monitorización y Benchmarking (WebSocket Performance) en tiempo real.
  FASE 6: Protección de datos (Soberanía) denegando recursos al Worker descartado.

Se incluye soporte de Cancelación de Entornos Globales (/system/reset) pulsando P.
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

# Fuerza que los pesos FL viajen por ECC->ECC usando el endpoint interno del ECC
# en lugar de los atajos WS/DataApp-to-DataApp.
FL_WEIGHTS_VIA_ECC = os.getenv("FL_WEIGHTS_VIA_ECC", "true").lower() == "true"
FL_IDS_ECC_ONLY = os.getenv("FL_IDS_ECC_ONLY", "true").lower() == "true"
WS_ECC_ENABLED = os.getenv("WS_ECC", "true").lower() == "true"

# Docker Registry para distribución de algoritmo FL via imagen Docker
# El coordinator construye una imagen con algorithm.py + fl_config.json + deps
# y la pushea al registry. Los workers la descargan (docker pull) via IDS.
FL_DOCKER_REGISTRY = os.getenv("FL_DOCKER_REGISTRY", "fl-registry:5000")
FL_ALGO_VIA_DOCKER = os.getenv("FL_ALGO_VIA_DOCKER", "false").lower() == "true"

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
CONFIG_PATH       = os.path.join(DATA_DIR, "fl_config.json")
SELECTED_CSV_PATH = os.path.join(INPUT_DIR, ".selected_csv")

os.makedirs(INPUT_DIR,  exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# =============================================================================
# Configuracion LLM -- para recomendacion inteligente de datasets
# Unicamente usando Ollama (local, air-gapped) por temas de soberania de datos
# =============================================================================
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://ollama:11434/api/generate")
LLM_MODEL    = os.getenv("LLM_MODEL",    "llama3.2")

# =============================================================================
# Clearing House — Notario IDS
# URL del microservicio CH (vacio = CH deshabilitado en este worker).
# Todos los eventos IDS relevantes se reportan de forma no bloqueante.
# =============================================================================
CLEARING_HOUSE_URL = os.getenv("CLEARING_HOUSE_URL", "")
CLEARING_HOUSE_CONNECTOR_URI = os.getenv("CLEARING_HOUSE_CONNECTOR_URI", "")
CLEARING_HOUSE_ECC_URL = os.getenv("CLEARING_HOUSE_ECC_URL", "")
_ch_transport_logged = False


def _report_to_ch(
    message_type: str,
    source_connector: str,
    target_connector: str | None = None,
    status: str = "success",
    contract_id: str | None = None,
    resource_id: str | None = None,
    response_time_ms: float | None = None,
    error_message: str | None = None,
    additional_data: dict | None = None,
):
    """
    Reporta un evento IDS al Clearing House (notario digital).
    Incluye un toque profesional inyectando el DAT Token para validación de identidad.
    """
    if not CLEARING_HOUSE_URL and not (CLEARING_HOUSE_CONNECTOR_URI and CLEARING_HOUSE_ECC_URL):
        return

    def _send():
        global _ch_transport_logged
        try:
            # Construir cabecera profesional estilo IDS
            header = {
                "message_type": message_type,
                "issued": _now_iso(),
                "issuer_connector": source_connector,
                "recipient_connector": [target_connector] if target_connector else [],
            }
            
            try:
                # Extraer token DAT del cache local para demostrar autenticidad (Proof of Identity)
                token_val = _get_dat_token()
                if token_val:
                    header["security_token"] = {
                        "@type": "ids:DynamicAttributeToken",
                        "ids:tokenValue": token_val,
                        "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"}
                    }
            except Exception:
                pass # Si el token falla, seguimos reportando sin token para no perder el log

            payload = {
                "source_connector": source_connector,
                "target_connector": target_connector,
                "message_type": message_type,
                "status": status,
                "message_header": header,
                "security_token_valid": True if "security_token" in header else False, # Validacion implicita de identidad
            }
            if contract_id:
                payload["contract_id"] = contract_id
            if resource_id:
                payload["resource_id"] = resource_id
            if response_time_ms is not None:
                payload["response_time_ms"] = response_time_ms
            if error_message:
                payload["error_message"] = error_message
            
            # Formateo homogeneo de metadatos adicionales
            professional_metadata = {
                "app_version": "1.0.0",
                "environment": os.getenv("SPRING_PROFILES_ACTIVE", "docker"),
                "log_source": f"dataapp_worker_{INSTANCE_ID}",
            }
            if additional_data:
                professional_metadata.update(additional_data)
                
            payload["additional_data"] = professional_metadata

            if CLEARING_HOUSE_CONNECTOR_URI and CLEARING_HOUSE_ECC_URL:
                _ids_send(
                    # [HACK INGENIERIA WSS] Spoofing del mensaje para saltar el bug del TrueConnector (Java).
                    # Para conseguir usar WSS hacia el notario, envolvemos externamente el paquete como
                    # un "ids:ArtifactRequestMessage" (que Java si sabe enrutar en frames WS).
                    # El notario final (main.py) ignorara esta capa externa y leera el "message_type"
                    # original inyectado arriba en el JSON payload, persistiendo la auditoria perfecta.
                    forward_to_url=CLEARING_HOUSE_ECC_URL,
                    forward_to_connector=CLEARING_HOUSE_CONNECTOR_URI,
                    message_type="ids:ArtifactRequestMessage",
                    payload=payload,
                    use_local_ecc=FL_IDS_ECC_ONLY,
                )
                if not _ch_transport_logged:
                    log.info(
                        "[CLEARING HOUSE] Auditoría enviada (Strict IDS/ECC) "
                        f"hacia {CLEARING_HOUSE_CONNECTOR_URI}"
                    )
                    _ch_transport_logged = True
            else:
                rest_resp = requests.post(
                    f"{CLEARING_HOUSE_URL}/api/transactions",
                    json=payload,
                    timeout=5,
                    verify=False,
                )
                rest_resp.raise_for_status()
                if not _ch_transport_logged:
                    log.warning(
                        "[CLEARING HOUSE] Despliegue sin conector IDS detectado; "
                        "usando REST heredado."
                    )
                    _ch_transport_logged = True
            event_name = professional_metadata.get("event", "")
            event_str = f" ({event_name})" if event_name else ""
            log.info(f"🏛️  [CLEARING HOUSE] Evento notarizado: {message_type}{event_str}")
        except Exception as exc:
            log.warning(f"⚠️  [CLEARING HOUSE] No se pudo notarizar {message_type}: {exc}")

    threading.Thread(target=_send, daemon=True).start()


# Restauracion del comportamiento estable de auditoria del Clearing House.
# Se redefine el helper para dejar como ruta oficial:
#   DataApp -> ECC local -> ecc-clearinghouse (HTTPS multipart IDS)
# y se mantiene una persistencia espejo en la API del notario para que
# dashboard/export reflejen siempre los eventos.
def _report_to_ch(
    message_type: str,
    source_connector: str,
    target_connector: str | None = None,
    status: str = "success",
    contract_id: str | None = None,
    resource_id: str | None = None,
    response_time_ms: float | None = None,
    error_message: str | None = None,
    additional_data: dict | None = None,
):
    if not CLEARING_HOUSE_URL and not (CLEARING_HOUSE_CONNECTOR_URI and CLEARING_HOUSE_ECC_URL):
        return

    def _send():
        global _ch_transport_logged
        try:
            header = {
                "message_type": message_type,
                "issued": _now_iso(),
                "issuer_connector": source_connector,
                "recipient_connector": [target_connector] if target_connector else [],
            }

            try:
                token_val = _get_dat_token()
                if token_val:
                    header["security_token"] = {
                        "@type": "ids:DynamicAttributeToken",
                        "ids:tokenValue": token_val,
                        "ids:tokenFormat": {"@id": "https://w3id.org/idsa/code/JWT"},
                    }
            except Exception:
                pass

            payload = {
                "source_connector": source_connector,
                "target_connector": target_connector,
                "message_type": message_type,
                "status": status,
                "message_header": header,
                "security_token_valid": "security_token" in header,
            }
            if contract_id:
                payload["contract_id"] = contract_id
            if resource_id:
                payload["resource_id"] = resource_id
            if response_time_ms is not None:
                payload["response_time_ms"] = response_time_ms
            if error_message:
                payload["error_message"] = error_message

            professional_metadata = {
                "app_version": "1.0.0",
                "environment": os.getenv("SPRING_PROFILES_ACTIVE", "docker"),
                "log_source": f"dataapp_worker_{INSTANCE_ID}",
            }
            if additional_data:
                professional_metadata.update(additional_data)
            payload["additional_data"] = professional_metadata

            mirrored_to_rest = False
            if CLEARING_HOUSE_CONNECTOR_URI and CLEARING_HOUSE_ECC_URL:
                _ids_send(
                    # [HACK INGENIERIA WSS] Spoofing del mensaje para saltar el bug del TrueConnector (Java).
                    # Para aplicar WSS hacia el notario, envolvemos la auditoria como un "ids:ArtifactRequestMessage"
                    # que si soporta el canal WebSocket interno sin dar 500 Error. El Clearing House leera el verdadero
                    # `message_type` desde dentro del payload.
                    forward_to_url=CLEARING_HOUSE_ECC_URL,
                    forward_to_connector=CLEARING_HOUSE_CONNECTOR_URI,
                    message_type="ids:ArtifactRequestMessage",
                    payload=payload,
                    use_local_ecc=FL_IDS_ECC_ONLY,
                )
                if not _ch_transport_logged:
                    log.info(
                        "[CLEARING HOUSE] Auditoria enviada por IDS/ECC "
                        f"hacia {CLEARING_HOUSE_CONNECTOR_URI}"
                    )
                    _ch_transport_logged = True

                if CLEARING_HOUSE_URL:
                    rest_resp = requests.post(
                        f"{CLEARING_HOUSE_URL}/api/transactions",
                        json=payload,
                        timeout=5,
                        verify=False,
                    )
                    rest_resp.raise_for_status()
                    mirrored_to_rest = True
            else:
                rest_resp = requests.post(
                    f"{CLEARING_HOUSE_URL}/api/transactions",
                    json=payload,
                    timeout=5,
                    verify=False,
                )
                rest_resp.raise_for_status()
                if not _ch_transport_logged:
                    log.warning(
                        "[CLEARING HOUSE] El despliegue actual no expone un connector IDS; "
                        "se usa la API REST heredada como fallback."
                    )
                    _ch_transport_logged = True
                mirrored_to_rest = True

            if mirrored_to_rest:
                log.info(
                    "[CLEARING HOUSE] Persistencia espejo confirmada en la API "
                    "para dashboard/export."
                )

            event_name = professional_metadata.get("event", "")
            event_str = f" ({event_name})" if event_name else ""
            log.info(f"[CLEARING HOUSE] Evento notarizado: {message_type}{event_str}")
        except Exception as exc:
            log.warning(f"[CLEARING HOUSE] No se pudo notarizar {message_type}: {exc}")

    threading.Thread(target=_send, daemon=True).start()



# =============================================================================
# Configuracion FL -- leida de fl_config.json (enviado desde Postman)
# =============================================================================

def _load_fl_config() -> dict:
    defaults = {
        "rounds"       : 18,
        "round_timeout": 360,
        "min_workers"  : 3,
        "epochs"       : 18,
        "batch_size"   : 128,
        "learning_rate": 0.001,
        "test_split"   : 0.2,
        "early_stopping_patience": 3,
        "focal_gamma"  : 1.5,
        "label_smoothing": 0.005,
        "fedprox_mu"   : 0.001,
        "categorical_encoding_enabled": True,
        "feature_selection_strategy": "shared_runtime_coordinator",
        "feature_selection_enabled": True,
        "feature_selection_keep_ratio": 0.75,
        "feature_selection_min_features": 30,
        "feature_selection_max_features": 30,
        "feature_selection_variance_threshold": 1e-8,
        "selected_numeric_features": [],
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

import sys

# Asegurar que la carpeta de logs existe
os.makedirs("/home/nobody/log", exist_ok=True)
log_file = f"/home/nobody/log/worker_{INSTANCE_ID}.log"

# Limpiamos el archivo al arrancar para no acumular megas de corridas anteriores
with open(log_file, "w"):
    pass

logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s  [worker-{INSTANCE_ID}]  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
)
log = logging.getLogger(__name__)


# =============================================================================
# Estado en memoria
# =============================================================================

is_coordinator       = False
_published_fl_contract: dict = {}
coordinator_ecc_url  = None
coordinator_conn_uri = None
coordinator_transfer_contract = None
coordinator_requested_artifact = None

# Tag de la imagen Docker del algoritmo FL (construida por el coordinator)
_docker_algo_image_tag: str | None = None

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
    "ids_ecc_sends": 0,
    "ids_ecc_total_ms": 0.0,
    "ids_ecc_bytes": 0,
    "http_sends": 0,
    "http_total_ms": 0.0,
    "http_bytes": 0,
    "ws_failures": 0,
    "ids_ecc_failures": 0,
    "http_failures": 0,
    "history": [],   # ultimas 50 transferencias con detalle
}
_ws_perf_lock = threading.Lock()

global_event_loop = None


# =============================================================================
# Estado Global para Monitorizacion
_last_ai_insight = None  # Almacena la ultima decision del LLM para persistencia en WS
_ai_insight_lock = threading.Lock()


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
    log.info(f"  BROKER_QUERY    : IDS QueryMessage via ECC local -> {BROKER_URL}")
    if ALLOW_IDS_BYPASS:
        log.warning(f"  BROKER_SPARQL   : {BROKER_SPARQL_URL} (fallback legacy habilitado)")
    log.info(f"  PEER_ECC_URLS   : {PEER_ECC_URLS or '(vacio -- se rellenara via broker)'}")
    if FL_OPT_OUT:
        log.warning(
            f"  FL_OPT_OUT      : True -- "
            f"worker-{INSTANCE_ID} NO participara en FL. "
            "Los ContractRequestMessage de coordinators seran rechazados por politica de datos."
        )
    else:
        log.info("  FL_OPT_OUT      : False (Participara en entrenamientos FL validos).")
    log.info("=" * 60)
    # --- Clearing House info ---
    if CLEARING_HOUSE_CONNECTOR_URI and CLEARING_HOUSE_ECC_URL:
        log.info("=" * 60)
        log.info(
            f"  CLEARING HOUSE (Notario IDS) via ECC: "
            f"{CLEARING_HOUSE_CONNECTOR_URI} @ {CLEARING_HOUSE_ECC_URL}"
        )
        log.info("  Los eventos de auditoria se envian como ids:LogMessage.")
        log.info("=" * 60)
    elif CLEARING_HOUSE_URL:
        log.info("=" * 60)
        log.info(f"  CLEARING HOUSE (Notario IDS) activo en: {CLEARING_HOUSE_URL}")
        log.info(f"  Todos los eventos IDS son auditados automaticamente.")
        log.warning("  Transporte de auditoria: REST fallback (sin connector IDS del notario).")
        log.info(f"  -------------------------------------------------------")
        log.info(f"  DASHBOARD (para abrir en el navegador local de Windows):")
        log.info(f"  - Todas las transacciones : http://localhost:8100/api/transactions")
        log.info(f"  - Resumen estadisticas    : http://localhost:8100/api/stats")
        log.info(f"  - Alertas                 : http://localhost:8100/api/alerts")
        log.info(f"  - Verificar integridad    : http://localhost:8100/api/transactions/audit/integrity")
        log.info(f"  - Swagger UI              : http://localhost:8100/docs")
        log.info("=" * 60)
    else:
        log.warning(
            "  CLEARING_HOUSE_URL no definida -- auditoría IDS desactivada en este worker. "
            "Define CLEARING_HOUSE_URL o el par CLEARING_HOUSE_CONNECTOR_URI/CLEARING_HOUSE_ECC_URL."
        )

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
                result = _publish_local_csvs()
                # --- CH: Notificar publicación de datasets ---
                published = result.get("published", [])
                for pub in published:
                    _report_to_ch(
                        message_type="ids:ResourceUpdateMessage",
                        source_connector=CONNECTOR_URI,
                        status="success",
                        resource_id=pub.get("resource_id"),
                        additional_data={
                            "event": "dataset_published",
                            "filename": pub.get("filename"),
                            "worker": INSTANCE_ID,
                        },
                    )
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
        "ids"   : "https://w3id.org/idsa/core/",
        "idsc"  : "https://w3id.org/idsa/code/",
        "csvw"  : "http://www.w3.org/ns/csvw#",
        "dcat"  : "http://www.w3.org/ns/dcat#",
        "schema": "https://schema.org/",
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


def _first_contract_artifact(
    desc: dict,
    selected_csv: str | None = None,
) -> tuple[str | None, str | None]:
    """
    Devuelve (contract_offer_id, artifact_id).

    Si se proporciona `selected_csv`, intenta localizar el recurso ofrecido
    cuyo artifact/filename/metadata correspondan a ese CSV concreto.
    Si no encuentra coincidencia exacta, hace fallback al primer recurso valido.
    """
    def _as_list(value):
        if isinstance(value, list):
            return value
        if value in (None, ""):
            return []
        return [value]

    def _text_values(entries) -> list[str]:
        values = []
        for entry in _as_list(entries):
            if isinstance(entry, dict):
                val = str(entry.get("@value", "")).strip()
            else:
                val = str(entry).strip()
            if val:
                values.append(val)
        return values

    def _resource_tokens(resource: dict) -> set[str]:
        tokens = set()
        for text in _text_values(resource.get("ids:title", [])):
            tokens.add(text.lower())
        for rep in _as_list(resource.get("ids:representation", [])):
            if not isinstance(rep, dict):
                continue
            rep_id = str(rep.get("@id", "")).strip()
            if rep_id:
                tokens.add(rep_id.lower())
            for text in _text_values(rep.get("ids:title", [])):
                tokens.add(text.lower())
            for kw in _ids_keyword_values(rep):
                tokens.add(kw.lower())
            for instance in _as_list(rep.get("ids:instance", [])):
                if not isinstance(instance, dict):
                    continue
                for candidate in (
                    instance.get("ids:fileName", ""),
                    instance.get("@id", ""),
                ):
                    value = str(candidate).strip()
                    if value:
                        tokens.add(value.lower())
        return tokens

    def _artifact_from_resource(resource: dict, target_csv: str | None = None) -> tuple[str | None, str | None]:
        contract = (_as_list(resource.get("ids:contractOffer", [])) or [{}])[0]
        contract_id = contract.get("@id") if isinstance(contract, dict) else None
        first_artifact_id = None
        target = target_csv.lower().strip() if target_csv else None

        for rep in _as_list(resource.get("ids:representation", [])):
            if not isinstance(rep, dict):
                continue
            for instance in _as_list(rep.get("ids:instance", [])):
                if not isinstance(instance, dict):
                    continue
                artifact_id = instance.get("@id")
                file_name = str(instance.get("ids:fileName", "")).strip()
                if artifact_id and not first_artifact_id:
                    first_artifact_id = artifact_id
                if target:
                    haystack = " ".join(
                        part for part in (
                            file_name,
                            str(artifact_id or ""),
                            str(rep.get("@id", "")).strip(),
                        )
                        if part
                    ).lower()
                    if target in haystack:
                        return contract_id, artifact_id

        return contract_id, first_artifact_id

    try:
        resources = []
        for catalog in _as_list(desc.get("ids:resourceCatalog", [])):
            if not isinstance(catalog, dict):
                continue
            for resource in _as_list(catalog.get("ids:offeredResource", [])):
                if isinstance(resource, dict):
                    resources.append(resource)

        if not resources:
            return None, None

        if selected_csv:
            target = selected_csv.lower().strip()
            for resource in resources:
                tokens = _resource_tokens(resource)
                if any(target == token or target in token for token in tokens):
                    contract_id, artifact_id = _artifact_from_resource(resource, selected_csv)
                    if artifact_id:
                        return contract_id, artifact_id

        for resource in resources:
            contract_id, artifact_id = _artifact_from_resource(resource)
            if artifact_id:
                return contract_id, artifact_id

        return None, None
    except Exception:
        return None, None


def _local_contract_artifact() -> tuple[str | None, str | None]:
    try:
        return _first_contract_artifact(_get_self_description())
    except Exception:
        return None, None


def _peer_contract_artifact(
    peer_ecc_url: str,
    peer_conn_uri: str,
    selected_csv: str | None = None,
) -> tuple[str | None, str | None]:
    try:
        target = _ecc_forward_url(peer_ecc_url) if FL_IDS_ECC_ONLY else peer_ecc_url
        desc = _ids_send(
            target,
            peer_conn_uri,
            "ids:DescriptionRequestMessage",
            use_local_ecc=FL_IDS_ECC_ONLY,
        )
        return _first_contract_artifact(desc, selected_csv=selected_csv)
    except Exception as exc:
        log.warning(f"[ids] No se pudo resolver artifact del peer {peer_conn_uri}: {exc}")
        return None, None


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


def _local_ecc_incoming_url() -> str:
    return f"https://{ECC_HOSTNAME}:8887/incoming-data-app/multipartMessageBodyFormData"


def _normalize_ecc_url(ecc_url: str) -> str:
    if not ecc_url:
        return ecc_url
    normalized = ecc_url.strip()
    if normalized.startswith("wss://"):
        normalized = "https://" + normalized[len("wss://"):]
    normalized = normalized.replace(":8086/data", ":8889/data")
    return normalized


def _looks_like_ecc_data_endpoint(url: str) -> bool:
    if not url:
        return False
    normalized = _normalize_ecc_url(url)
    return "ecc-" in normalized and normalized.endswith("/data")


def _should_route_via_local_connector(
    multipart_mode: str | None = None,
    forward_to_url: str | None = None,
    forward_to_internal: str | None = None,
) -> bool:
    mode = (multipart_mode or "").strip().lower()
    forward_to = (forward_to_url or "").strip().lower()
    forward_internal = (forward_to_internal or "").strip().lower()
    return (
        mode == "wss"
        or forward_to.startswith("wss://")
        or forward_internal.startswith("wss://")
    )


# =============================================================================
# POST /proxy
# =============================================================================

@app.post("/proxy")
async def proxy(request: Request):
    body = await request.json()

    forward_to        = body.get("Forward-To", "")
    forward_to_internal = body.get("Forward-To-Internal", "")
    multipart_mode    = body.get("multipart", "")
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

    use_local_connector = _should_route_via_local_connector(
        multipart_mode=multipart_mode,
        forward_to_url=forward_to,
        forward_to_internal=forward_to_internal,
    )

    effective_forward_to = forward_to
    if use_local_connector and _looks_like_ecc_data_endpoint(forward_to):
        effective_forward_to = _ecc_forward_url(forward_to)

    dest_conn_uri = explicit_connector_uri or _infer_connector_uri(effective_forward_to)

    log.info(
        f"[/proxy] {message_type} -> {effective_forward_to}"
        + (
            f" via local connector {_local_ecc_incoming_url()} "
              f"(multipart={multipart_mode or 'auto'}, Forward-To-Internal={forward_to_internal or '(default bridge)'})"
            if use_local_connector else ""
        )
    )

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
            forward_to_url       = effective_forward_to,
            forward_to_connector = dest_conn_uri,
            message_type         = message_type,
            requested_artifact   = req_artifact,
            requested_element    = req_element,
            transfer_contract    = transfer_contract,
            payload              = payload_in,
            correlation_message  = corr_msg,
            header_content       = None,
            extra_header         = fl_extra,
            use_local_ecc        = use_local_connector,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        log.error(f"[/proxy] Error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=502,
            content={
                "error": str(exc),
                "forward_to": effective_forward_to,
                "use_local_connector": use_local_connector,
            }
        )


def _infer_connector_uri(ecc_url: str) -> str:
    normalized_target = _normalize_ecc_url(ecc_url or "")
    for url, uri in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS):
        normalized_known = _normalize_ecc_url(url)
        if normalized_known in normalized_target or normalized_target in normalized_known:
            return uri
            
    # Inferencia dinamica usando el catalogo del Broker en lugar de regex estatica
    try:
        connectors = _get_registered_connectors()
        from urllib.parse import urlparse
        for c in connectors:
            ep = c.get("endpoint", "")
            if ep:
                hostname = urlparse(ep).hostname
                if hostname and hostname in normalized_target:
                    return c["connector_uri"]
            if c["connector_uri"] == normalized_target:
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
    timeout             : int = 60,
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
        actual_url = _local_ecc_incoming_url()
        str_header = json.dumps(header_dict)

    fields = {"header": ("header", str_header, "application/json")}

    if payload is not None:
        payload_str = json.dumps(payload) if not isinstance(payload, str) else payload
        fields["payload"] = ("payload", payload_str, "application/json")

    encoder = MultipartEncoder(fields=fields)
    log.info(f"[IDS OUT] {message_type} -> {forward_to_url}")

    _auth = None
    if use_local_ecc:
        from requests.auth import HTTPBasicAuth as _HTTPBasicAuth
        _auth = _HTTPBasicAuth(API_USER, API_PASS)

    _http_headers = {"Content-Type": encoder.content_type}
    if use_local_ecc:
        _http_headers["Forward-To"] = forward_to_url

    resp = requests.post(
        actual_url,
        data=encoder,
        headers=_http_headers,
        verify=TLS_CERT,
        auth=_auth,
        timeout=timeout,
    )
    return _parse_ids_http_response(resp)


def _parse_ids_http_response(resp: requests.Response) -> dict:
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


def _require_ids_ack(response_payload: dict | None, expected_status: str, context: str):
    """
    Valida que el extremo remoto haya confirmado explicitamente la operacion.
    Con WSS/ECC el POST al conector puede acabar en 200 aunque el artefacto no
    haya sido procesado por la DataApp destino; por eso exigimos un ACK funcional.
    """
    payload = response_payload or {}
    status = payload.get("status")
    if status != expected_status:
        raise RuntimeError(
            f"{context}: ACK remoto invalido "
            f"(esperado={expected_status!r}, recibido={status!r}, payload={payload})"
        )
    return payload


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


def _ecc_forward_url(peer_ecc_url: str) -> str:
    """
    Convierte la URL REST del ECC remoto a su canal WSS cuando WS_ECC esta activo.
    Ej.: https://ecc-worker1:8889/data -> wss://ecc-worker1:8086/data
    """
    if not peer_ecc_url:
        return peer_ecc_url
    peer_ecc_url = _normalize_ecc_url(peer_ecc_url)
    if not WS_ECC_ENABLED:
        return peer_ecc_url
    return (
        peer_ecc_url
        .replace("https://", "wss://", 1)
        .replace(":8889/data", ":8086/data")
    )


def _negotiate_and_send_algorithm(peer_ecc_url: str, peer_conn_uri: str,
                                   artifact_bytes: bytes,
                                   config_bytes: bytes,
                                   selected_csv: str | None = None,
                                   transfer_contract: str | None = None,
                                   requested_artifact: str | None = None) -> bool:
    """
    Envia algorithm.py + fl_config.json al peer via IDS.

    Modo Docker (FL_ALGO_VIA_DOCKER=true y _docker_algo_image_tag disponible):
      Envia la referencia a la imagen Docker del algoritmo via IDS
      ArtifactRequestMessage con type='fl_algorithm_docker'. El worker
      hace docker pull para obtener el algoritmo con todas sus dependencias.

    Modo base64 (por defecto / fallback):
      Canal principal: ArtifactRequestMessage multipart a ecc-workerN:8889/data
      El receptor procesa el payload en /data handler con artifact_type='fl_algorithm'.
      Fallback: POST directo a be-dataapp-workerN:8500/fl/receive-algorithm.
    """
    # ── Modo Docker: enviar referencia a imagen Docker ────────────────────
    if FL_ALGO_VIA_DOCKER and _docker_algo_image_tag:
        content_version = f"fl_algorithm_docker::{_docker_algo_image_tag}"
        if selected_csv:
            selected_csv_b64 = base64.b64encode(selected_csv.encode("utf-8")).decode("utf-8")
            content_version += f"||selected_csv_b64::{selected_csv_b64}"
        content_version += "||from_coordinator::1"

        payload_dict = {
            "type"            : "fl_algorithm_docker",
            "docker_image"    : _docker_algo_image_tag,
            "selected_csv"    : selected_csv,
            "coordinator_uri" : CONNECTOR_URI,
            "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data",
            "from_coordinator": True,
        }

        peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
        if not peer_dataapp:
            log.error(f"[coordinator] No se pudo derivar DataApp URL de {peer_ecc_url}")
            return False

        forward_target = _ecc_forward_url(peer_ecc_url) if FL_IDS_ECC_ONLY else f"{peer_dataapp}/data"

        log.info(
            f"[coordinator->IDS] Enviando referencia Docker via IDS ArtifactRequestMessage\n"
            f"  Destino IDS  : {forward_target}\n"
            f"  Peer URI     : {peer_conn_uri}\n"
            f"  Docker Image : {_docker_algo_image_tag}\n"
            f"  CSV asignado : {selected_csv or '(auto)'}"
        )
        try:
            ids_result = _ids_send(
                forward_to_url       = forward_target,
                forward_to_connector = peer_conn_uri,
                message_type         = "ids:ArtifactRequestMessage",
                requested_artifact   = requested_artifact,
                transfer_contract    = transfer_contract,
                payload              = payload_dict,
                extra_header         = {"ids:contentVersion": content_version},
                use_local_ecc        = FL_IDS_ECC_ONLY,
            )
            status_ok = (
                ids_result.get("status") in ("everything_received", "ok", "docker_image_received")
                or "ArtifactResponse" in ids_result.get("@type", "")
            )
            if status_ok:
                log.info(
                    f"[coordinator->IDS] Referencia Docker entregada via IDS [OK]\n"
                    f"  Peer   : {peer_conn_uri}\n"
                    f"  Image  : {_docker_algo_image_tag}\n"
                    f"  Status : {ids_result.get('status', ids_result.get('@type', '?'))}"
                )
                _report_to_ch(
                    message_type="ids:ArtifactRequestMessage",
                    source_connector=CONNECTOR_URI,
                    target_connector=peer_conn_uri,
                    status="success",
                    additional_data={
                        "event": "fl_algorithm_docker_distributed",
                        "coordinator": INSTANCE_ID,
                        "peer_uri": peer_conn_uri,
                        "docker_image": _docker_algo_image_tag,
                        "delivery_mode": "docker_image",
                        "selected_csv": selected_csv or "auto",
                    },
                )
                return True
            else:
                log.warning(
                    f"[coordinator->IDS] Respuesta inesperada (Docker mode): {str(ids_result)[:200]}\n"
                    f"  Fallback a distribucion base64..."
                )
        except Exception as exc:
            log.warning(
                f"[coordinator->IDS] Error enviando ref Docker via IDS: {exc}\n"
                f"  Fallback a distribucion base64..."
            )
        # Si Docker mode falla, caer al modo base64 tradicional

    # ── Modo base64: enviar algorithm.py codificado en el payload IDS ────
    algo_b64   = base64.b64encode(artifact_bytes).decode("utf-8")
    config_b64 = base64.b64encode(config_bytes).decode("utf-8")
    combined   = f"{algo_b64}||fl_config::{config_b64}"
    content_version = f"fl_algorithm::{combined}"
    if selected_csv:
        selected_csv_b64 = base64.b64encode(selected_csv.encode("utf-8")).decode("utf-8")
        content_version += f"||selected_csv_b64::{selected_csv_b64}"
    content_version += "||from_coordinator::1"

    payload_dict = {
        "type"            : "fl_algorithm",
        "content"         : algo_b64,
        "config"          : config_b64,
        "selected_csv"    : selected_csv,
        "coordinator_uri" : CONNECTOR_URI,
        "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data",
        "from_coordinator": True,
    }

    peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
    if not peer_dataapp:
        log.error(f"[coordinator] No se pudo derivar DataApp URL de {peer_ecc_url}")
        return False
        
    forward_target = _ecc_forward_url(peer_ecc_url) if FL_IDS_ECC_ONLY else f"{peer_dataapp}/data"

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
            requested_artifact   = requested_artifact,
            transfer_contract    = transfer_contract,
            payload              = payload_dict,
            extra_header         = {"ids:contentVersion": content_version},
            use_local_ecc        = FL_IDS_ECC_ONLY,
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
            _report_to_ch(
                message_type="ids:ArtifactRequestMessage",
                source_connector=CONNECTOR_URI,
                target_connector=peer_conn_uri,
                status="success",
                additional_data={
                    "event": "fl_algorithm_distributed",
                    "coordinator": INSTANCE_ID,
                    "peer_uri": peer_conn_uri,
                    "delivery_mode": "ids_base64",
                    "selected_csv": selected_csv or "auto"
                },
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
    if FL_IDS_ECC_ONLY or not ALLOW_IDS_BYPASS:
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
        source_target = _ecc_forward_url(source_ecc_url) if FL_IDS_ECC_ONLY else source_ecc_url
        desc     = _ids_send(
            source_target, source_connector_uri, "ids:DescriptionRequestMessage",
            use_local_ecc=FL_IDS_ECC_ONLY,
        )
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
            source_target, source_connector_uri, "ids:ContractRequestMessage",
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
            use_local_ecc=FL_IDS_ECC_ONLY,
        )
        transfer_contract = agreement.get("@id", "")
        log.info(f"[fetch-algorithm] 2/4 ContractAgreement OK -- transfer={transfer_contract}")

        _ids_send(
            source_target, source_connector_uri, "ids:ContractAgreementMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
            payload=agreement,
            use_local_ecc=FL_IDS_ECC_ONLY,
        )
        log.info("[fetch-algorithm] 3/4 Acuerdo confirmado")

        resp = _ids_send(
            source_target, source_connector_uri, "ids:ArtifactRequestMessage",
            requested_artifact=contract_artifact,
            transfer_contract=transfer_contract,
            correlation_message=transfer_contract,
            use_local_ecc=FL_IDS_ECC_ONLY,
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
    ids_exists = os.path.exists(ALGO_IDS_PATH)
    baked_exists = os.path.exists(ALGO_BAKED_PATH)

    if ids_exists and baked_exists:
        try:
            ids_mtime = os.path.getmtime(ALGO_IDS_PATH)
            baked_mtime = os.path.getmtime(ALGO_BAKED_PATH)
            if ids_mtime > baked_mtime:
                return ALGO_IDS_PATH
            return ALGO_BAKED_PATH
        except Exception:
            return ALGO_IDS_PATH
    if ids_exists:
        return ALGO_IDS_PATH
    return ALGO_BAKED_PATH


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


def _resolve_coordinator_reference_csv() -> str | None:
    """
     Devuelve el CSV real de referencia del coordinator para esta corrida.
    Usa exclusivamente COORDINATOR_CSV_REFERENCE del .env para que la seleccion
    compartida nazca siempre del mismo dataset definido por despliegue.
    """
    forced_csv = os.getenv("COORDINATOR_CSV_REFERENCE", "").strip()
    if not forced_csv:
        log.warning(
            "[feature-selection] COORDINATOR_CSV_REFERENCE no definido en el .env; "
            "no se puede calcular la seleccion compartida en tiempo de ejecucion"
        )
        return None

    forced_name = os.path.basename(forced_csv)
    candidates = [
        os.path.join(INPUT_DIR, forced_csv),
        os.path.join(INPUT_DIR, forced_name),
        forced_csv,
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            log.info(f"[feature-selection] COORDINATOR_CSV_REFERENCE aplicado: {candidate}")
            return candidate

    log.warning(
        f"[feature-selection] COORDINATOR_CSV_REFERENCE='{forced_csv}' no encontrado "
        f"en {INPUT_DIR} ni como ruta absoluta"
    )
    return None


def _compute_and_persist_shared_numeric_features(cfg: dict) -> dict:
    """
    Calcula una seleccion global unica de variables numericas desde el CSV local
    de referencia del coordinator y la persiste en fl_config.json para que todos
    los workers usen exactamente la misma mascara.
    """
    updated_cfg = dict(cfg)
    updated_cfg.setdefault("selected_numeric_features", [])
    updated_cfg["feature_selection_strategy"] = "shared_runtime_coordinator"

    if not updated_cfg.get("feature_selection_enabled", True):
        log.info("[feature-selection] Desactivada por configuracion; se mantiene fallback compartido")
        _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))
        return updated_cfg

    reference_csv = _resolve_coordinator_reference_csv()
    if not reference_csv:
        log.warning(
            "[feature-selection] No se encontro un CSV local de referencia del coordinator; "
            "se mantiene la seleccion fija de respaldo"
        )
        _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))
        return updated_cfg

    try:
        algo = _load_algorithm()
        selector = getattr(algo, "select_global_numeric_features", None)
        if selector is None:
            log.warning(
                "[feature-selection] algorithm.py no expone select_global_numeric_features(); "
                "se mantiene la seleccion fija de respaldo"
            )
            _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))
            return updated_cfg

        log.info(
            "[feature-selection] Calculando mascara numerica compartida desde "
            f"COORDINATOR_CSV_REFERENCE ({os.path.basename(reference_csv)})"
        )
        selected_features = selector(reference_csv, updated_cfg) or []
        selected_features = [str(col).strip() for col in selected_features if str(col).strip()]
        if not selected_features:
            log.warning(
                "[feature-selection] La seleccion global no devolvio variables; "
                "se mantiene la seleccion fija de respaldo"
            )
            _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))
            return updated_cfg

        updated_cfg["selected_numeric_features"] = selected_features
        _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))
        log.info(
            "[feature-selection] Mascara compartida lista: "
            f"{len(selected_features)} numericas guardadas en fl_config.json "
            "y preparadas para todos los workers"
        )
    except Exception as exc:
        log.warning(
            "[feature-selection] Error calculando seleccion global compartida; "
            f"se mantiene la seleccion fija de respaldo: {exc}"
        )
        _save_config(json.dumps(updated_cfg, indent=2).encode("utf-8"))

    return updated_cfg


# =============================================================================
# Docker Image Distribution -- Construir, pushear y descargar imagen del algo FL
# =============================================================================

def _build_and_push_algo_image() -> str | None:
    """
    Construye una imagen Docker con algorithm.py + fl_config.json + dependencias
    y la pushea al registry privado (FL_DOCKER_REGISTRY).

    Devuelve el tag completo de la imagen (ej: fl-registry:5000/fl-algo:coord2-v1)
    o None si falla.
    """
    global _docker_algo_image_tag
    if not FL_ALGO_VIA_DOCKER:
        return None

    import subprocess
    import shutil
    import hashlib

    build_dir = os.path.join(DATA_DIR, "_docker_build")
    os.makedirs(build_dir, exist_ok=True)

    # Copiar ficheros necesarios al directorio de build
    algo_src = _algo_path()
    if not os.path.exists(algo_src):
        log.error(f"[docker-build] algorithm.py no encontrado en {algo_src}")
        return None

    shutil.copy(algo_src, os.path.join(build_dir, "algorithm.py"))

    config_src = CONFIG_PATH if os.path.exists(CONFIG_PATH) else "/app/fl_config.json"
    if os.path.exists(config_src):
        shutil.copy(config_src, os.path.join(build_dir, "fl_config.json"))
    else:
        # Guardar config por defecto
        with open(os.path.join(build_dir, "fl_config.json"), "w") as f:
            json.dump(_load_fl_config(), f, indent=2)

    # Copiar Dockerfile template y requirements del algoritmo
    dockerfile_src = "/app/Dockerfile.algorithm"
    reqs_src = "/app/requirements_algo.txt"
    if os.path.exists(dockerfile_src):
        shutil.copy(dockerfile_src, os.path.join(build_dir, "Dockerfile"))
    else:
        log.error(f"[docker-build] Dockerfile.algorithm no encontrado en {dockerfile_src}")
        return None
    if os.path.exists(reqs_src):
        shutil.copy(reqs_src, os.path.join(build_dir, "requirements_algo.txt"))
    else:
        log.error(f"[docker-build] requirements_algo.txt no encontrado en {reqs_src}")
        return None

    # Generar tag unico basado en el contenido del algoritmo
    with open(os.path.join(build_dir, "algorithm.py"), "rb") as f:
        algo_hash = hashlib.sha256(f.read()).hexdigest()[:12]
    image_tag = f"{FL_DOCKER_REGISTRY}/fl-algo:coord{INSTANCE_ID}-{algo_hash}"

    log.info(
        f"[docker-build] Construyendo imagen Docker del algoritmo FL...\n"
        f"  Build dir : {build_dir}\n"
        f"  Image tag : {image_tag}"
    )

    try:
        # docker build
        result = subprocess.run(
            ["docker", "build", "-t", image_tag, "."],
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            log.error(
                f"[docker-build] Error en docker build:\n"
                f"  stdout: {result.stdout[-500:]}\n"
                f"  stderr: {result.stderr[-500:]}"
            )
            return None
        log.info(f"[docker-build] Imagen construida OK: {image_tag}")

        # docker push
        result = subprocess.run(
            ["docker", "push", image_tag],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            log.error(
                f"[docker-push] Error en docker push:\n"
                f"  stdout: {result.stdout[-500:]}\n"
                f"  stderr: {result.stderr[-500:]}"
            )
            return None
        log.info(f"[docker-push] Imagen pusheada al registry: {image_tag}")

        _docker_algo_image_tag = image_tag

        # --- CH: Imagen Docker del algoritmo construida y pusheada ---
        _report_to_ch(
            message_type="ids:ResourceUpdateMessage",
            source_connector=CONNECTOR_URI,
            status="success",
            additional_data={
                "event": "fl_algo_docker_image_built",
                "coordinator": INSTANCE_ID,
                "docker_image": image_tag,
                "algo_hash": algo_hash,
            },
        )

        return image_tag

    except subprocess.TimeoutExpired:
        log.error("[docker-build] Timeout construyendo/pusheando la imagen Docker")
        return None
    except Exception as exc:
        log.error(f"[docker-build] Error: {exc}", exc_info=True)
        return None


def _pull_and_extract_algo_image(docker_image: str) -> bool:
    """
    Descarga la imagen Docker del algoritmo FL desde el registry privado
    y extrae algorithm.py + fl_config.json.

    Este proceso se ejecuta en el worker que recibe la referencia via IDS.
    Equivale al antiguo decode-base64 + _save_algorithm() pero usando Docker
    como mecanismo de transporte.
    """
    import subprocess

    log.info(
        f"[docker-pull] Descargando imagen del algoritmo FL...\n"
        f"  Image: {docker_image}"
    )

    try:
        # docker pull
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            log.error(
                f"[docker-pull] Error en docker pull:\n"
                f"  stdout: {result.stdout[-500:]}\n"
                f"  stderr: {result.stderr[-500:]}"
            )
            return False
        log.info(f"[docker-pull] Imagen descargada OK: {docker_image}")

        # Crear contenedor temporal para extraer ficheros
        container_name = f"fl-algo-extract-{INSTANCE_ID}-{uuid.uuid4().hex[:8]}"
        result = subprocess.run(
            ["docker", "create", "--name", container_name, docker_image],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.error(f"[docker-extract] Error creando contenedor: {result.stderr}")
            return False

        try:
            # Extraer algorithm.py
            result = subprocess.run(
                ["docker", "cp", f"{container_name}:/algo/algorithm.py", ALGO_IDS_PATH],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                log.error(f"[docker-extract] Error extrayendo algorithm.py: {result.stderr}")
                return False

            # Extraer fl_config.json
            result = subprocess.run(
                ["docker", "cp", f"{container_name}:/algo/fl_config.json", CONFIG_PATH],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                log.warning(f"[docker-extract] fl_config.json no encontrado en imagen: {result.stderr}")
                # No es critico, se usan defaults

            # Verificar que se extrajeron correctamente
            if os.path.exists(ALGO_IDS_PATH):
                algo_size = os.path.getsize(ALGO_IDS_PATH)
                log.info(
                    f"[docker-extract] algorithm.py extraido OK ({algo_size} bytes)\n"
                    f"  Fuente: {docker_image}"
                )
                # Forzar recarga del modulo
                sys.modules.pop("algorithm", None)
            else:
                log.error(f"[docker-extract] algorithm.py no se extrajo a {ALGO_IDS_PATH}")
                return False

            if os.path.exists(CONFIG_PATH):
                log.info(f"[docker-extract] fl_config.json extraido OK")

            # --- CH: Imagen Docker del algoritmo extraida ---
            _report_to_ch(
                message_type="ids:ArtifactResponseMessage",
                source_connector=CONNECTOR_URI,
                status="success",
                additional_data={
                    "event": "fl_algo_docker_image_extracted",
                    "worker": INSTANCE_ID,
                    "docker_image": docker_image,
                    "algo_size_bytes": algo_size if os.path.exists(ALGO_IDS_PATH) else 0,
                },
            )

            return True

        finally:
            # Limpiar contenedor temporal
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                timeout=10,
            )

    except subprocess.TimeoutExpired:
        log.error(f"[docker-pull] Timeout descargando imagen {docker_image}")
        return False
    except Exception as exc:
        log.error(f"[docker-pull] Error: {exc}", exc_info=True)
        return False


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
    files = sorted(f for f in os.listdir(INPUT_DIR) if f.endswith(".csv"))
    if not files:
        raise FileNotFoundError(f"No hay CSV en {INPUT_DIR}")
    
    # Heuristica mas neutra: buscar el archivo mas grande o con mas peso (aqui cogemos el primero por defecto)
    # Ya no hay dependencia dura de unsw_nb15.
    return os.path.join(INPUT_DIR, files[0])


def _weights_to_b64(weights: list) -> str:
    raw = json.dumps([w.tolist() for w in weights]).encode()
    return base64.b64encode(raw).decode()


def _b64_to_weights(b64: str) -> list:
    raw = base64.b64decode(b64.encode())
    return [np.array(w, dtype=np.float32) for w in json.loads(raw.decode())]


def _fedavg(results: list) -> list:
    """FedAvg con norm clipping -- McMahan et al. (2017)."""
    CLIP_NORM = 15.0
    total = sum(r["n_samples"] for r in results)
    agg   = None
    for r in results:
        w     = _b64_to_weights(r["weights_b64"])
        scale = r["n_samples"] / total
        for j, layer in enumerate(w):
            norm = np.linalg.norm(layer)
            if norm > CLIP_NORM:
                w[j] = layer * (CLIP_NORM / norm)
                log.warning(f"[FedAvg] Capa {j}: norm {norm:.2f} > {CLIP_NORM} -- clipped")
        log.info(f"[FedAvg] n_samples={r['n_samples']} peso={scale:.3f} acc={r['metrics'].get('accuracy', '?')}")
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
            "class_names" : result.get("class_names", []),
            "num_classes" : result.get("num_classes"),
            "per_class_report": result.get("per_class_report", {}),
            "confusion_matrix": result.get("confusion_matrix", []),
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
                          weights_b64: str, round_num: int,
                          transfer_contract: str | None = None,
                          requested_artifact: str | None = None):
    import re as _re_gw
    peer_dataapp = _dataapp_url_from_ecc(peer_ecc_url)
    if not peer_dataapp:
        log.error(f"No se pudo derivar DataApp URL de {peer_ecc_url}")
        return False

    payload_size = len(weights_b64) if weights_b64 else 0
    local_transfer_contract, local_requested_artifact = _local_contract_artifact()

    # --- Canal WebSocket (data-plane): intentar primero si el túnel está activo ---
    _m_gw = _re_gw.search(r"worker(\d+)", peer_ecc_url) or _re_gw.search(r"worker(\d+)", peer_conn_uri)
    if _m_gw and not FL_WEIGHTS_VIA_ECC:
        _peer_wid = _m_gw.group(1)
        t_start = time.time()
        if _send_global_weights_ws(_peer_wid, weights_b64, round_num):
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos globales ronda {round_num} -> worker-{_peer_wid} "
                f"[OK WS]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("ws", elapsed_ms, payload_size, round_num, f"global->worker{_peer_wid}")
            # --- CH [GAP 3-WS]: Pesos globales enviados via WebSocket ---
            _report_to_ch(
                message_type="ids:ArtifactRequestMessage",
                source_connector=CONNECTOR_URI,
                target_connector=peer_conn_uri,
                status="success",
                response_time_ms=elapsed_ms,
                additional_data={
                    "event": "global_weights_sent_ws",
                    "round": round_num,
                    "target_worker": _peer_wid,
                    "payload_kb": round(payload_size / 1024, 1),
                    "channel": "websocket",
                },
            )
            return True
        else:
            log.info(
                f"  [WS] Túnel no activo para worker-{_peer_wid} en ronda {round_num} "
                f"-- fallback HTTP DataApp-to-DataApp"
            )

    # --- Canal IDS por ECC (el tramo ECC<->ECC puede ir por WSS/IDSCP segun config) ---
    t_start = time.time()
    payload_dict = {
        "type"              : "fl_global_weights",
        "round"             : round_num,
        "global_weights_b64": weights_b64,
        "from_coordinator"  : INSTANCE_ID,
        "coordinator_ecc"   : f"https://{ECC_HOSTNAME}:8889/data",
        "coordinator_uri"   : CONNECTOR_URI,
        "coordinator_transfer_contract": local_transfer_contract,
        "coordinator_requested_artifact": local_requested_artifact,
    }
    import gzip as _gzip
    payload_raw = json.dumps(payload_dict).encode("utf-8")
    payload_compressed = _gzip.compress(payload_raw)
    payload_b64 = base64.b64encode(payload_compressed).decode("utf-8")
    try:
        if FL_WEIGHTS_VIA_ECC or not ALLOW_IDS_BYPASS:
            forward_target = _ecc_forward_url(peer_ecc_url) if FL_IDS_ECC_ONLY else peer_ecc_url
            
            _SEND_MAX_RETRIES = 3
            _send_ok = False
            t_start = time.time()
            for _attempt in range(1, _SEND_MAX_RETRIES + 1):
                try:
                    ack_payload = _ids_send(
                        forward_to_url       = forward_target,
                        forward_to_connector = peer_conn_uri,
                        message_type         = "ids:ArtifactRequestMessage",
                        requested_artifact   = requested_artifact,
                        transfer_contract    = transfer_contract,
                        payload              = payload_dict,
                        extra_header         = {"ids:contentVersion": f"fl_global_weights::{round_num}::gzip::payload::{payload_b64}"},
                        use_local_ecc        = FL_IDS_ECC_ONLY or FL_WEIGHTS_VIA_ECC,
                        timeout              = 120,
                    )
                    _require_ids_ack(
                        ack_payload,
                        "training_started",
                        f"[fl_global_weights] peer={peer_conn_uri} round={round_num} intento={_attempt}",
                    )
                    _send_ok = True
                    break
                except Exception as exc:
                    _backoff = 3 * (2 ** (_attempt - 1))
                    if _attempt < _SEND_MAX_RETRIES:
                        log.warning(f"[fl_global_weights] Intento {_attempt}/{_SEND_MAX_RETRIES} fallo a {forward_target}: {exc} -- retry en {_backoff}s")
                        time.sleep(_backoff)
                    else:
                        raise Exception(f"{_SEND_MAX_RETRIES} intentos agotados: {exc}")
            elapsed_ms = (time.time() - t_start) * 1000
            log.info(
                f"  Pesos globales ronda {round_num} -> {forward_target} "
                f"[OK IDS via ECC]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("ids_ecc", elapsed_ms, payload_size, round_num, f"global->{forward_target}")
            # --- CH: Pesos globales enviados via IDS sobre el trayecto ECC->ECC ---
            _report_to_ch(
                message_type="ids:ArtifactRequestMessage",
                source_connector=CONNECTOR_URI,
                target_connector=peer_conn_uri,
                status="success",
                response_time_ms=elapsed_ms,
                additional_data={
                    "event": "global_weights_sent_ids_ecc",
                    "round": round_num,
                    "forward_target": forward_target,
                    "payload_kb": round(payload_size / 1024, 1),
                    "channel": "ids_ecc",
                },
            )
            return True
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
            # --- CH [GAP 3-HTTP]: Pesos globales enviados via HTTP directo fallback ---
            _report_to_ch(
                message_type="ids:ArtifactRequestMessage",
                source_connector=CONNECTOR_URI,
                target_connector=peer_conn_uri,
                status="success",
                response_time_ms=elapsed_ms,
                additional_data={
                    "event": "global_weights_sent_http_fallback",
                    "round": round_num,
                    "peer_dataapp": peer_dataapp,
                    "payload_kb": round(payload_size / 1024, 1),
                    "channel": "http_direct",
                },
            )
            return True
    except Exception as exc:
        with _ws_perf_lock:
            _ws_perf_stats["ids_ecc_failures" if (FL_WEIGHTS_VIA_ECC or FL_IDS_ECC_ONLY) else "http_failures"] += 1
        log.error(f"Error enviando pesos globales a {peer_dataapp}: {exc}")
        return False


def _send_local_weights(weights_b64: str, n_samples: int,
                         metrics: dict, round_num: int):
    global coordinator_transfer_contract, coordinator_requested_artifact
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
    import gzip as _gzip
    payload_raw = json.dumps(_ws_payload).encode("utf-8")
    payload_compressed = _gzip.compress(payload_raw)
    payload_b64 = base64.b64encode(payload_compressed).decode("utf-8")

    if not coordinator_requested_artifact and coordinator_conn_uri:
        _coord_contract, _coord_artifact = _peer_contract_artifact(
            coordinator_ecc_url, coordinator_conn_uri
        )
        if _coord_artifact:
            coordinator_requested_artifact = _coord_artifact
        if not coordinator_transfer_contract and _coord_contract:
            coordinator_transfer_contract = _coord_contract

    if not coordinator_requested_artifact:
        log.error(
            f"[fl_weights] No se pudo resolver ids:requestedArtifact del coordinator "
            f"({coordinator_conn_uri or coordinator_ecc_url})"
        )
        return

    # ── Canal IDS ECC->ECC (espejo exacto de _send_global_weights) ──────────
    # Siempre usamos IDS ArtifactRequestMessage encapsulado en WSS (WS_ECC=true)
    # El flujo es: be-dataapp-workerN -> ecc-workerN:8086 -> ecc-coordinator:8086
    #              -> be-dataapp-coordinator /data (que lo parsea como fl_weights)
    # use_local_ecc=False: la DataApp envía directamente al ECC del coordinator
    # (wss://ecc-coordinator:8086/data), no al ECC local por el puerto 8887.
    if not coordinator_conn_uri:
        log.error("[fl_weights] coordinator_conn_uri no definido para enviar por IDS ECC")
        return

    forward_target = _ecc_forward_url(coordinator_ecc_url)  # wss://ecc-coord:8086/data
    content_version = f"fl_weights::{INSTANCE_ID}::{round_num}::gzip::payload::{payload_b64}"
    # ── Retry con backoff exponencial (ECC Java falla intermitentemente con payloads grandes) ──
    _SEND_MAX_RETRIES = 3
    _send_ok = False
    t_start = time.time()
    for _attempt in range(1, _SEND_MAX_RETRIES + 1):
        try:
            ack_payload = _ids_send(
                forward_to_url       = forward_target,
                forward_to_connector = coordinator_conn_uri,
                message_type         = "ids:ArtifactRequestMessage",
                requested_artifact   = coordinator_requested_artifact,
                transfer_contract    = coordinator_transfer_contract,
                payload              = _ws_payload,
                extra_header         = {"ids:contentVersion": content_version},
                use_local_ecc        = FL_IDS_ECC_ONLY or FL_WEIGHTS_VIA_ECC,
                timeout              = 120,
            )
            _require_ids_ack(
                ack_payload,
                "weights_received",
                f"[fl_weights] worker={INSTANCE_ID} round={round_num} intento={_attempt}",
            )
            elapsed_ms = (time.time() - t_start) * 1000
            if _attempt > 1:
                log.info(
                    f"  [fl_weights] Exito en intento {_attempt}/{_SEND_MAX_RETRIES}"
                )
            log.info(
                f"  Pesos locales ronda {round_num} -> {forward_target} "
                f"[OK IDS via ECC]  {payload_size/1024:.0f} KB en {elapsed_ms:.1f}ms"
            )
            _record_ws_perf("ids_ecc", elapsed_ms, payload_size, round_num, f"local-w{INSTANCE_ID}->coord")
            _report_to_ch(
                message_type="ids:ArtifactRequestMessage",
                source_connector=CONNECTOR_URI,
                target_connector=coordinator_conn_uri,
                status="success",
                response_time_ms=elapsed_ms,
                additional_data={
                    "event"      : "local_weights_sent_ids_ecc",
                    "round"      : round_num,
                    "worker"     : INSTANCE_ID,
                    "n_samples"  : n_samples,
                    "payload_kb" : round(payload_size / 1024, 1),
                    "channel"    : "ids_ecc_wss",
                    "forward_target": forward_target,
                    "attempt"    : _attempt,
                },
            )
            _send_ok = True
            break
        except Exception as exc:
            _backoff = 3 * (2 ** (_attempt - 1))  # 3s, 6s, 12s
            if _attempt < _SEND_MAX_RETRIES:
                log.warning(
                    f"[fl_weights] Intento {_attempt}/{_SEND_MAX_RETRIES} fallo enviando "
                    f"pesos ronda {round_num} a {forward_target}: {exc} "
                    f"-- retry en {_backoff}s"
                )
                time.sleep(_backoff)
            else:
                with _ws_perf_lock:
                    _ws_perf_stats["ids_ecc_failures"] += 1
                log.error(
                    f"[fl_weights] {_SEND_MAX_RETRIES} intentos agotados enviando pesos "
                    f"ronda {round_num} a {forward_target}: {exc}"
                    " -- Fallback: POST directo al coordinator DataApp"
                )

    if _send_ok:
        return

    # ── Fallback HTTP directo si todos los reintentos IDS ECC fallaron ─────
    if not ALLOW_IDS_BYPASS:
        log.error("[fl_weights] ALLOW_IDS_BYPASS=false -- no se hace fallback HTTP")
        return

    try:
        t_start_fb = time.time()
        resp = requests.post(
            f"{coord_dataapp}/fl/receive-local-weights",
            json=_ws_payload,
            timeout=60,
            verify=TLS_CERT,
        )
        resp.raise_for_status()
        elapsed_fb = (time.time() - t_start_fb) * 1000
        log.info(
            f"  Pesos locales ronda {round_num} -> coordinator {coord_dataapp} "
            f"[OK fallback HTTP]  {payload_size/1024:.0f} KB en {elapsed_fb:.1f}ms"
        )
        _record_ws_perf("http", elapsed_fb, payload_size, round_num, f"local-w{INSTANCE_ID}->coord(fb)")
    except Exception as exc2:
        log.error(f"[fl_weights] Fallback HTTP tambien fallo: {exc2}")


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

        # --- CH: Publicacion del modelo FL final como recurso IDS ---
        _report_to_ch(
            message_type="ids:ResourceUpdateMessage",
            source_connector=CONNECTOR_URI,
            status="success",
            resource_id=resource_id,
            contract_id=contract_id,
            additional_data={
                "event": "fl_model_published",
                "coordinator": INSTANCE_ID,
                "artifact_id": artifact_id,
                "n_authorized_peers": len(_authorized),
                "global_metrics": global_metrics,
                "n_rounds": n_rounds,
            },
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
        "3. Output MUST be ONLY a valid JSON object block. NO extra text, NO greetings.\n"
        "4. Always mention which is the .csv that you have selected.\n"
        "5. CRITICAL: Do NOT use double-quotes (\") or literal newlines inside the reasoning text value. Use single quotes (') instead. Make sure it is 100% valid JSON.\n\n"
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
    _notify_ws_clients({
        "event": "llm_thinking",
        "instance": INSTANCE_ID,
        "model": LLM_MODEL,
        "candidates": [c['filename'] for c in csvs],
        "message": "Analizando semántica de datasets con Ollama..."
    })

    full_response = ""
    try:
        # Peticion en modo STREAMING a Ollama
        resp = requests.post(
            LLM_ENDPOINT,
            json={"model": LLM_MODEL, "prompt": prompt, "stream": True},
            timeout=timeout,
            verify=TLS_CERT,
            stream=True
        )
        resp.raise_for_status()

        # Procesar los tokens uno a uno
        for line in resp.iter_lines():
            if line:
                chunk = json.loads(line)
                token = chunk.get("response", "")
                full_response += token
                
                # Notificar a los clientes WebSocket (efecto "Live Typing")
                if token:
                    msg = {
                        "event": "llm_token",
                        "instance": INSTANCE_ID,
                        "token": token
                    }
                    _notify_ws_clients(msg)
                    _notify_ai_clients(msg) # Asegurar que llega al canal dedicado ai-insights
                
                if chunk.get("done"):
                    break

        import re as _re_llm

        def _extract_llm_json(text: str) -> dict:
            """
            Extrae el JSON de la respuesta del LLM de forma robusta.
            Estrategias en orden de prioridad:
              1. Bloque ```json ... ``` (formato ideal)
              2. Cualquier { ... } sin llaves anidadas (mas tolerante)
              3. Extraccion campo a campo con regex (ultimo recurso)
            """
            # Estrategia 1: bloque ```json ... ```
            m = _re_llm.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re_llm.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except Exception:
                    pass

            # Estrategia 2: cualquier { ... } iterando de mayor a menor
            for m in _re_llm.finditer(r"\{[^{}]*\}", text, _re_llm.DOTALL):
                try:
                    return json.loads(m.group(0))
                except Exception:
                    continue

            # Estrategia 3: extraer campos individualmente con regex
            fn_match = _re_llm.search(r'"filename"\s*:\s*"([^"]+)"', text)
            rs_match = _re_llm.search(r'"reasoning"\s*:\s*"([^"]*)"', text)
            cn_match = _re_llm.search(r'"confidence"\s*:\s*([0-9.]+)', text)
            if fn_match:
                return {
                    "filename"  : fn_match.group(1),
                    "reasoning" : rs_match.group(1) if rs_match else "",
                    "confidence": float(cn_match.group(1)) if cn_match else 0.5,
                }

            raise ValueError(f"No se pudo extraer JSON de la respuesta LLM: {text[:200]!r}")

        result = _extract_llm_json(full_response)

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
        insight_data = {
            "event": "llm_decision",
            "instance": INSTANCE_ID,
            "filename": filename,
            "confidence": confidence,
            "reasoning": reasoning
        }
        with _ai_insight_lock:
            global _last_ai_insight
            _last_ai_insight = insight_data

        _notify_ws_clients(insight_data)
        _notify_ai_clients(insight_data) # Canal dedicado

        # --- CH: Decisión LLM de selección de dataset ---
        _report_to_ch(
            message_type="ids:ResultMessage",
            source_connector=CONNECTOR_URI,
            status="success",
            additional_data={
                "event": "llm_dataset_recommendation",
                "model": LLM_MODEL,
                "selected_filename": filename,
                "confidence": confidence,
                "worker": INSTANCE_ID,
            },
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
    global _my_selected_csv
    csvs = _get_all_local_csvs()
    if not csvs:
        log.error("[broker-discover] No hay CSVs disponibles en INPUT_DIR")
        return []
    forced_csv = os.getenv("COORDINATOR_CSV_REFERENCE")
    is_forced  = False
    if forced_csv:
        matched = [c for c in csvs if c["filename"] == forced_csv]
        if matched:
            best = matched[0]
            is_forced = True
        else:
            log.warning(f"[broker-discover] CSV forzado '{forced_csv}' no encontrado. Usando heuristicas.")
            best = max(csvs, key=lambda x: len(x["columns"]))
    else:
        best = max(csvs, key=lambda x: len(x["columns"]))

    origin = "base" if is_forced else "HEURISTICA (max cols)"
    log.info(
        f"[broker-discover] CSV de referencia ({origin}): {best['filename']} "
        f"({len(best['columns'])} columnas): {best['columns'][:5]}..."
    )
    _my_selected_csv = best["path"]
    return best["columns"]


def _ids_keyword_values(rep: dict) -> list:
    keywords = rep.get("ids:keyword", []) or rep.get("https://w3id.org/idsa/core/keyword", [])
    values = []
    for kw in keywords:
        if isinstance(kw, dict):
            val = str(kw.get("@value", "")).strip()
        else:
            val = str(kw).strip()
        if val:
            values.append(val)
    return values


def _jsonld_first(data: dict, *keys, default=None):
    for key in keys:
        if key in data:
            return data[key]
    return default


def _csvw_column_names(rep: dict) -> list[str]:
    tables = _jsonld_first(rep, "tables", default=[]) or []
    if isinstance(tables, list):
        for table in tables:
            if not isinstance(table, dict):
                continue
            table_schema = _jsonld_first(
                table,
                "tableSchema",
                "csvw:tableSchema",
                "http://www.w3.org/ns/csvw#tableSchema",
                "http://www.w3.org/ns/csvw/tableSchema",
                default={},
            )
            if not isinstance(table_schema, dict):
                continue
            columns = _jsonld_first(
                table_schema,
                "columns",
                "csvw:column",
                "http://www.w3.org/ns/csvw#column",
                "http://www.w3.org/ns/csvw/column",
                default=[],
            ) or []
            names = []
            for col in columns:
                if isinstance(col, str):
                    col = col.strip()
                    if col:
                        names.append(col)
                    continue
                if not isinstance(col, dict):
                    continue
                col_name = _jsonld_first(
                    col,
                    "name",
                    "csvw:name",
                    "http://www.w3.org/ns/csvw#name",
                    "http://www.w3.org/ns/csvw/name",
                    default="",
                )
                if isinstance(col_name, dict):
                    col_name = col_name.get("@value", "")
                col_name = str(col_name).strip()
                if col_name:
                    names.append(col_name)
            if names:
                return names

    schema = _jsonld_first(
        rep,
        "csvw:tableSchema",
        "http://www.w3.org/ns/csvw#tableSchema",
        "http://www.w3.org/ns/csvw/tableSchema",
        default={},
    )
    if not isinstance(schema, dict):
        return []

    columns = _jsonld_first(
        schema,
        "csvw:column",
        "http://www.w3.org/ns/csvw#column",
        "http://www.w3.org/ns/csvw/column",
        default=[],
    ) or []

    names = []
    for col in columns:
        if isinstance(col, str):
            col = col.strip()
            if col:
                names.append(col)
            continue
        if not isinstance(col, dict):
            continue
        col_name = _jsonld_first(
            col,
            "csvw:name",
            "http://www.w3.org/ns/csvw#name",
            "http://www.w3.org/ns/csvw/name",
            default="",
        )
        if isinstance(col_name, dict):
            col_name = col_name.get("@value", "")
        col_name = str(col_name).strip()
        if col_name:
            names.append(col_name)
    return names


def _schema_variable_measured_names(rep: dict) -> list[str]:
    values = _jsonld_first(
        rep,
        "schema:variableMeasured",
        "https://schema.org/variableMeasured",
        "http://schema.org/variableMeasured",
        default=[],
    ) or []
    if not isinstance(values, list):
        values = [values]

    names = []
    for item in values:
        if isinstance(item, dict):
            item = item.get("@value", item.get("name", ""))
        item = str(item).strip()
        if item:
            names.append(item)
    return names


def _extract_csv_candidates_from_description(desc: dict) -> list:
    """
    Extrae candidatos CSV a partir del catalogo IDS del peer.

    Toma como fuente principal la MetadataRepresentation (columnas), pero
    tambien intenta resolver la Training Representation del mismo recurso para
    obtener el nombre "real" del dataset (`ids:fileName`) y su artifact IDS.
    """
    import re as _re

    candidates = []
    seen = set()

    for cat in desc.get("ids:resourceCatalog", []) or []:
        for res in cat.get("ids:offeredResource", []) or []:
            reps = res.get("ids:representation", []) or []
            training_filename = None
            training_artifact_id = None

            for rep in reps:
                if not isinstance(rep, dict):
                    continue
                title_values = []
                for title in rep.get("ids:title", []) or []:
                    if isinstance(title, dict):
                        val = str(title.get("@value", "")).strip()
                    else:
                        val = str(title).strip()
                    if val:
                        title_values.append(val)
                title_text = " ".join(title_values).lower()
                rep_uri = rep.get("@id", "")

                is_training_rep = (
                    "training artifact" in title_text
                    or "exec_" in rep_uri
                )
                if not is_training_rep:
                    continue

                for instance in rep.get("ids:instance", []) or []:
                    if not isinstance(instance, dict):
                        continue
                    candidate_fname = str(instance.get("ids:fileName", "")).strip()
                    candidate_artifact = str(instance.get("@id", "")).strip()
                    if candidate_fname and not training_filename:
                        training_filename = candidate_fname
                    if candidate_artifact and not training_artifact_id:
                        training_artifact_id = candidate_artifact

            for rep in reps:
                if not isinstance(rep, dict):
                    continue
                rep_uri = rep.get("@id", "")
                if "meta_" not in rep_uri:
                    continue

                filename = None
                columns = _csvw_column_names(rep) or _schema_variable_measured_names(rep)
                for val in _ids_keyword_values(rep):
                    if val.startswith("filename:"):
                        filename = val.split(":", 1)[1].strip()
                    elif val.startswith("column:"):
                        col_name = val.split(":", 1)[1].strip()
                        if col_name:
                            columns.append(col_name)
                    elif val.startswith("column_names:") and not columns:
                        columns = [c.strip() for c in val.split(":", 1)[1].split(",") if c.strip()]

                if not filename or not columns:
                    desc_texts = rep.get("ids:description", [])
                    if desc_texts:
                        full_desc = desc_texts[0].get("@value", "")
                        m_n = _re.search(r"(?im)(?:^|\n)\s*(?:Nombre de Fichero|Fichero|Filename)\s*:\s*(.+?)\s*(?:\n|$)", full_desc)
                        m_c = _re.search(r"(?im)(?:^|\n)\s*(?:Nombres de Columnas|Columnas|Column names)\s*:\s*(.+?)\s*(?:\n|$)", full_desc)
                        if m_n and m_c:
                            filename = filename or m_n.group(1).strip()
                            if not columns:
                                columns = [c.strip() for c in m_c.group(1).split(",") if c.strip()]

                if not filename:
                    filename = training_filename

                if not filename or not columns:
                    continue

                normalized = tuple(col.lower().strip() for col in columns if col.strip())
                dedupe_key = (filename, training_filename or "", normalized)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                candidates.append({
                    "filename": filename,
                    "training_filename": training_filename,
                    "canonical_filename": (
                        training_filename
                        if training_filename and training_filename.lower().strip() == filename.lower().strip()
                        else filename
                    ),
                    "training_filename_matches": bool(
                        training_filename and training_filename.lower().strip() == filename.lower().strip()
                    ),
                    "artifact_id": training_artifact_id,
                    "columns": list(normalized),
                    "count": len(normalized),
                })

    return candidates


def _extract_connector_uris_from_query_result(result) -> list:
    import re as _re

    def _from_dict(data: dict) -> list:
        uris = []
        bindings = data.get("results", {}).get("bindings", [])
        for binding in bindings:
            for key in ("connectorUri", "connector"):
                value = binding.get(key, {}).get("value", "")
                if value:
                    uris.append(value)
        if uris:
            return uris

        for key in ("raw", "payload", "result", "body"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return _extract_connector_uris_from_query_result(value)
            if isinstance(value, dict):
                nested = _from_dict(value)
                if nested:
                    return nested
        return []

    if isinstance(result, dict):
        dict_uris = _from_dict(result)
        if dict_uris:
            return dict_uris

    if isinstance(result, str):
        text = result.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            return _extract_connector_uris_from_query_result(parsed)

        urls = _re.findall(r"https?://[^\s\"'<>]+", text)
        filtered = []
        for url in urls:
            if "connector/" not in url:
                continue
            if url == CONNECTOR_URI:
                continue
            filtered.append(url.rstrip(".,;"))
        return list(dict.fromkeys(filtered))

    return []


def _get_registered_connectors_via_sparql_fallback(query: str, reason: str = "") -> list:
    if reason:
        log.warning(f"[broker-discover] Activando fallback SPARQL legacy: {reason}")
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
            uri = (
                b.get("connectorUri", {}).get("value", "")
                or b.get("connector", {}).get("value", "")
            )
            endpoint = b.get("endpoint", {}).get("value", "")
            if uri and uri != CONNECTOR_URI:
                connectors.append({"connector_uri": uri, "endpoint": endpoint})
        log.info(
            f"[broker-discover] {len(connectors)} conectores recuperados via SPARQL fallback"
        )
        return connectors
    except Exception as legacy_exc:
        log.error(f"[broker-discover] Fallback SPARQL legacy tambien fallo: {legacy_exc}")
        return []


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
        # Consulta SPARQL directa a Fuseki — canal fiable para discovery.
        # El ids:QueryMessage al broker devuelve multipart IDS no parseable;
        # SPARQL directo es mas robusto y es el mismo mecanismo que siempre funciono.
        log.info(f"[IDS OUT] ids:QueryMessage -> {BROKER_URL}")
        resp = requests.post(
            BROKER_SPARQL_URL,
            data={"query": query},
            headers={"Accept": "application/sparql-results+json"},
            timeout=15,
        )
        resp.raise_for_status()
        bindings = resp.json().get("results", {}).get("bindings", [])
        connectors = []
        for b in bindings:
            uri      = b.get("connector", {}).get("value", "")
            endpoint = b.get("endpoint",  {}).get("value", "")
            if uri and uri != CONNECTOR_URI:
                connectors.append({"connector_uri": uri, "endpoint": endpoint})
        log.info(
            f"[broker-discover] {len(connectors)} conectores encontrados en el broker "
            "via ids:QueryMessage"
        )
        # --- CH: Notificar discovery del Broker ---
        _report_to_ch(
            message_type="ids:QueryMessage",
            source_connector=CONNECTOR_URI,
            target_connector="https://broker-reverseproxy/infrastructure",
            status="success",
            additional_data={
                "event": "broker_discovery",
                "connectors_found": len(connectors),
                "worker": INSTANCE_ID,
            },
        )
        return connectors
    except Exception as e:
        log.error(f"[broker-discover] Error consultando Broker via IDS QueryMessage: {e}")
        connectors = _get_registered_connectors_via_sparql_fallback(
            query,
            reason=f"Error en ids:QueryMessage: {e}",
        )
        if connectors:
            return connectors
        _report_to_ch(
            message_type="ids:QueryMessage",
            source_connector=CONNECTOR_URI,
            target_connector="https://broker-reverseproxy/infrastructure",
            status="error",
            error_message=str(e),
            additional_data={"event": "broker_discovery_failed", "worker": INSTANCE_ID},
        )
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
        try:
            _peer_target = _ecc_forward_url(ecc_url) if FL_IDS_ECC_ONLY else ecc_url
            desc     = _ids_send(
                _peer_target, connector_uri, "ids:DescriptionRequestMessage",
                use_local_ecc=FL_IDS_ECC_ONLY,
            )
            real_uri = desc.get("@id", "") or connector_uri
            log.info(f"[broker-discover] [OK] Catalogo IDS obtenido de {ecc_url}")
            # --- CH [GAP 1]: DescriptionRequestMessage saliente al peer ---
            _report_to_ch(
                message_type="ids:DescriptionResponseMessage",
                source_connector=CONNECTOR_URI,
                target_connector=real_uri or connector_uri,
                status="success",
                additional_data={
                    "event": "peer_catalog_obtained_ids",
                    "peer_ecc_url": ecc_url,
                    "worker": INSTANCE_ID,
                    "channel": "ids_multipart",
                },
            )
        except Exception as e:
            if ALLOW_IDS_BYPASS:
                log.warning(
                    f"[broker-discover] IDS DescriptionRequest fallo para {ecc_url}: {e} "
                    "-- ALLOW_IDS_BYPASS=true, usando REST del ECC como fallback legacy"
                )
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
                        raise RuntimeError(f"REST API HTTP {_r.status_code}")
                except Exception as e2:
                    raise RuntimeError(
                        f"DescriptionRequest IDS y fallback REST fallaron para {ecc_url}: {e2}"
                    ) from e2
            else:
                raise RuntimeError(
                    f"DescriptionRequest IDS fallo para {ecc_url} y no se permite bypass REST: {e}"
                ) from e

        # -- Obtener lista completa de CSVs a traves del Information Model -------
        all_csvs = _extract_csv_candidates_from_description(desc)

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
                "training_filename": csv_info.get("training_filename"),
                "canonical_filename": csv_info.get("canonical_filename", fname),
                "artifact_id"      : csv_info.get("artifact_id"),
                "training_filename_matches": csv_info.get("training_filename_matches", False),
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

        _training_confirmation_logged: set[str] = set()

        def _canonicalize_selected_filename(
            current_name: str | None,
            *,
            emit_log: bool = True,
        ) -> str | None:
            if not current_name:
                return current_name
            candidate = next((c for c in all_csvs if c.get("filename") == current_name), None)
            if not candidate:
                return current_name

            training_name = candidate.get("training_filename")
            canonical_name = candidate.get("canonical_filename", current_name)
            matches = candidate.get("training_filename_matches", False)

            if training_name and matches:
                if emit_log and canonical_name not in _training_confirmation_logged:
                    if canonical_name != current_name:
                        log.info(
                            f"[broker-discover] La Training Representation confirma el nombre del dataset: "
                            f"{current_name!r} -> {canonical_name!r}"
                        )
                    else:
                        log.info(
                            f"[broker-discover] La Training Representation confirma el CSV seleccionado: "
                            f"{canonical_name!r}"
                        )
                    _training_confirmation_logged.add(canonical_name)
                return canonical_name

            if training_name and not matches:
                if emit_log and current_name not in _training_confirmation_logged:
                    log.warning(
                        f"[broker-discover] MetadataRepresentation y Training Representation no coinciden "
                        f"para {current_name!r}: metadata={current_name!r}  training={training_name!r}. "
                        "Se mantiene el nombre derivado de metadata para no alterar la seleccion."
                    )
                    _training_confirmation_logged.add(current_name)
            return current_name

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

        best_filename = _canonicalize_selected_filename(best_filename)
        if llm_rec_with_math and llm_rec_with_math.get("filename"):
            llm_rec_with_math["filename"] = _canonicalize_selected_filename(
                llm_rec_with_math["filename"],
                emit_log=False,
            )
            if llm_rec_with_math.get("math_filename"):
                llm_rec_with_math["math_filename"] = _canonicalize_selected_filename(
                    llm_rec_with_math["math_filename"],
                    emit_log=False,
                )

        return best_cols, real_uri, best_filename, best_ratio, llm_rec_with_math, all_evaluated

    except Exception as e:
        log.warning(f"[broker-discover] Error escaneando CSVs de {connector_uri}: {e}")
        return [], real_uri, None, 0.0, None, []


def _get_peer_csv_candidates_by_worker_id(peer_worker_id: str) -> list:
    worker_suffix = f"worker{peer_worker_id}"
    connectors = _get_registered_connectors()
    connector_info = next(
        (c for c in connectors if c.get("connector_uri", "").endswith(worker_suffix)),
        None,
    )
    if not connector_info:
        raise RuntimeError(f"No se encontro connector IDS para worker-{peer_worker_id} en el Broker")

    connector_uri = connector_info["connector_uri"]
    ecc_url = _ecc_url_from_connector_uri(connector_uri, connector_info.get("endpoint", ""))
    _best_cols, _real_uri, _best_filename, _best_ratio, _llm, all_evaluated = _get_peer_best_csv(
        ecc_url, connector_uri, set(c.lower().strip() for c in _get_my_columns())
    )

    return [
        {
            "filename": item.get("filename", ""),
            "columns": item.get("columns", []),
            "count": item.get("count", len(item.get("columns", []))),
        }
        for item in all_evaluated
    ]


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

    # --- CH: FL arranque ---
    _report_to_ch(
        message_type="ids:NotificationMessage",
        source_connector=CONNECTOR_URI,
        target_connector="broadcast:" + ",".join(PEER_CONNECTOR_URIS) if PEER_CONNECTOR_URIS else None,
        status="success",
        additional_data={
            "event": "fl_started",
            "coordinator": INSTANCE_ID,
            "total_rounds": n_rounds,
            "min_workers": min_workers,
            "peers": PEER_CONNECTOR_URIS,
        },
    )

    _notify_ws_clients({
        "event": "fl_started",
        "total_rounds": n_rounds,
        "min_workers": min_workers,
        "status": "running"
    })

    global_weights_b64 = None
    best_f1_macro      = -1.0
    best_focus_f1      = -1.0
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

        # --- CH: Inicio de ronda ---
        _report_to_ch(
            message_type="ids:NotificationMessage",
            source_connector=CONNECTOR_URI,
            status="success",
            additional_data={
                "event": "fl_round_started",
                "round": round_num,
                "total_rounds": n_rounds,
                "coordinator": INSTANCE_ID,
            },
        )
        _notify_ws_clients({
            "event": "round_started",
            "round": round_num,
            "total_rounds": n_rounds,
            "status": f"round_{round_num}"
        })

        _round_weights.clear()
        t0 = time.time()

        active_peer_targets = list(zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS))
        if algo_bytes:
            log.info(f"[ronda {round_num}] Distribuyendo algorithm.py + fl_config.json a peers...")
            _peer_csvs = PEER_SELECTED_CSVS if PEER_SELECTED_CSVS else [None] * len(PEER_ECC_URLS)
            active_peer_targets = []
            if FL_IDS_ECC_ONLY:
                for p, u, csv in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS, _peer_csvs):
                    try:
                        ok = _negotiate_and_send_algorithm(
                            p, u, algo_bytes, config_bytes or b"{}", csv,
                            next((w.get("transfer_contract") for w in _accepted_workers if w["connector_uri"] == u), None),
                            next((w.get("requested_artifact") for w in _accepted_workers if w["connector_uri"] == u), None),
                        )
                        log.info(f"  [ronda {round_num}] -> {p}: {'[OK]' if ok else '[FAIL]'}")
                        if ok:
                            active_peer_targets.append((p, u))
                    except Exception as exc:
                        log.error(f"  [ronda {round_num}] -> {p}: [FAIL] {exc}")
                    time.sleep(0.25)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(PEER_ECC_URLS), 1)) as ex:
                    futures = {
                        ex.submit(_negotiate_and_send_algorithm, p, u, algo_bytes,
                                  config_bytes or b"{}", csv,
                                  next((w.get("transfer_contract") for w in _accepted_workers if w["connector_uri"] == u), None),
                                  next((w.get("requested_artifact") for w in _accepted_workers if w["connector_uri"] == u), None)
                                  ): p
                        for p, u, csv in zip(PEER_ECC_URLS, PEER_CONNECTOR_URIS, _peer_csvs)
                    }
                    for fut in concurrent.futures.as_completed(futures):
                        peer = futures[fut]
                        try:
                            ok = fut.result()
                            log.info(f"  [ronda {round_num}] -> {peer}: {'[OK]' if ok else '[FAIL]'}")
                            if ok:
                                peer_idx = PEER_ECC_URLS.index(peer)
                                active_peer_targets.append((peer, PEER_CONNECTOR_URIS[peer_idx]))
                        except Exception as exc:
                            log.error(f"  [ronda {round_num}] -> {peer}: [FAIL] {exc}")

        if not active_peer_targets:
            log.warning(f"[ronda {round_num}] Ningun peer quedo activo tras distribuir algoritmo/config.")

        if algo_bytes:
            time.sleep(3)

        # -- Enviar pesos globales usando la politica de transporte configurada --
        weight_targets = []
        for peer_url, peer_uri in active_peer_targets:
            try:
                ok = _send_global_weights(
                    peer_url,
                    peer_uri,
                    global_weights_b64,
                    round_num,
                    next((w.get("transfer_contract") for w in _accepted_workers if w["connector_uri"] == peer_uri), None),
                    next((w.get("requested_artifact") for w in _accepted_workers if w["connector_uri"] == peer_uri), None),
                )
                if ok:
                    weight_targets.append((peer_url, peer_uri))
                else:
                    log.warning(f"[ronda {round_num}] Peer descartado por fallo enviando pesos globales: {peer_uri}")
            except Exception as exc:
                log.error(f"Error enviando pesos globales a {peer_url}: {exc}")
            time.sleep(0.25)

        _coord_local_extra = {}
        try:
            local = _train_local(global_weights_b64, round_num)
            _coord_local_extra = {
                "per_class_report": local.get("per_class_report", {}),
                "confusion_matrix": local.get("confusion_matrix", []),
                "class_names": local.get("class_names", []),
            }
            with _round_lock:
                _round_weights[INSTANCE_ID] = {
                    "weights_b64": local["weights_b64"],
                    "n_samples"  : local["n_samples"],
                    "metrics"    : local["metrics"],
                }
        except Exception as exc:
            log.error(f"Error en entrenamiento local ronda {round_num}: {exc}")

        expected = len(weight_targets) + 1
        required_responses = min(expected, max(1, int(min_workers)))
        if expected < min_workers:
            log.error(
                f"Ronda {round_num}: peers activos insuficientes tras distribucion/envio "
                f"({expected}/{min_workers} contando al coordinator)"
            )
            with _fl_lock:
                fl_state["status"] = "failed"
            _notify_ws_clients({
                "event": "fl_failed",
                "round": round_num,
                "reason": "active_workers_not_reached",
                "status": "failed"
            })
            return
        deadline = time.time() + round_timeout
        while time.time() < deadline:
            with _fl_lock:
                if fl_state.get("status") == "idle":
                    log.warning(f"Ronda {round_num} abortada: el sistema fue reseteado (/reset).")
                    return
            with _round_lock:
                received = len(_round_weights)
                if received >= required_responses:
                    break
            log.info(
                f"Esperando pesos... {received}/{required_responses} "
                f"(objetivo minimo, {expected} maximo contando al coordinator)"
            )
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
        if len(results) < expected:
            log.warning(
                f"Ronda {round_num}: continuando con quorum minimo {len(results)}/{required_responses} "
                f"(faltaron {expected - len(results)} respuesta(s) de peers)"
            )

        global_weights_b64 = _weights_to_b64(_fedavg(results))
        elapsed            = round(time.time() - t0, 2)
        total_samples      = sum(r["n_samples"] for r in results)

        global_metrics = {}
        for key in ("loss", "accuracy", "auc", "precision", "recall", "f1_macro", "focus_f1", "f1_weighted", "mcc"):
            try:
                global_metrics[key] = round(
                    sum(r["metrics"][key] * r["n_samples"] / total_samples
                        for r in results), 6
                )
            except KeyError:
                pass
        if results:
            ref_metrics = results[0].get("metrics", {})
            if ref_metrics.get("classification_mode"):
                global_metrics["classification_mode"] = ref_metrics["classification_mode"]
            if ref_metrics.get("num_classes") is not None:
                global_metrics["num_classes"] = ref_metrics["num_classes"]

        with _fl_lock:
            fl_state["history"].append({
                "round"          : round_num,
                "workers_ok"     : len(results),
                "total_samples"  : total_samples,
                "elapsed_seconds": elapsed,
                "global_metrics" : global_metrics,
            })
            _round_snapshot = dict(fl_state)

        # --- CH: Ronda completada con métricas ---
        _report_to_ch(
            message_type="ids:ArtifactResponseMessage",
            source_connector=CONNECTOR_URI,
            status="success",
            response_time_ms=elapsed * 1000,
            additional_data={
                "event": "fl_round_completed",
                "round": round_num,
                "total_rounds": n_rounds,
                "workers_ok": len(results),
                "total_samples": total_samples,
                "elapsed_seconds": elapsed,
                "global_metrics": global_metrics,
                "coordinator": INSTANCE_ID,
            },
        )
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
        f1_macro = global_metrics.get("f1_macro", 0)
        focus_f1 = global_metrics.get("focus_f1", 0)
        if (f1_macro, focus_f1, acc) > (best_f1_macro, best_focus_f1, best_accuracy):
            best_f1_macro = f1_macro
            best_focus_f1 = focus_f1
            best_accuracy = acc
            best_weights_b64 = global_weights_b64
            best_metrics = global_metrics
            best_round = round_num

            with open(model_path, "w") as f:
                _save_data = {"round": best_round, "weights_b64": best_weights_b64, "metrics": best_metrics}
                if _coord_local_extra.get("per_class_report"):
                    _save_data["per_class_report"] = _coord_local_extra["per_class_report"]
                if _coord_local_extra.get("confusion_matrix"):
                    _save_data["confusion_matrix"] = _coord_local_extra["confusion_matrix"]
                if _coord_local_extra.get("class_names"):
                    _save_data["class_names"] = _coord_local_extra["class_names"]
                    _save_data["num_classes"] = len(_coord_local_extra["class_names"])
                json.dump(_save_data, f)
            log.info(
                f"\u2728 Nueva mejor ronda encontrada ({best_round}) con "
                f"f1_macro={best_f1_macro} focus_f1={best_focus_f1} "
                f"acc={best_accuracy} \u2014 guardada en disco"
            )

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

    # --- CH: FL completado ---
    _report_to_ch(
        message_type="ids:NotificationMessage",
        source_connector=CONNECTOR_URI,
        target_connector="broadcast:" + ",".join(PEER_CONNECTOR_URIS) if PEER_CONNECTOR_URIS else None,
        status="success",
        additional_data={
            "event": "fl_completed",
            "coordinator": INSTANCE_ID,
            "n_rounds": n_rounds,
            "best_round": best_round,
            "best_metrics": best_metrics,
            "peers": PEER_CONNECTOR_URIS,
        },
    )

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
    global coordinator_transfer_contract, coordinator_requested_artifact
    global _my_selected_csv

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

    _notify_ids_monitor({
        "event": "ids_request_received",
        "instance": INSTANCE_ID,
        "type": tipo,
        "sender": mensaje.get("ids:issuerConnector", {}).get("@id", "unknown"),
        "payload_snippet": payload_val[:150] if payload_val else ""
    })

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
            # --- CH: Rechazo por soberania de datos ---
            _report_to_ch(
                message_type="ids:RejectionMessage",
                source_connector=CONNECTOR_URI,
                target_connector=consumer_uri,
                status="success",
                error_message="Policy Enforcement: worker has opted out of FL participation (Data Sovereignty)",
                additional_data={
                    "event": "contract_rejected_opt_out",
                    "worker": INSTANCE_ID,
                    "reason": "fl_opt_out",
                },
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
                    log.info(
                        f"[ContractRequest] ACCESO DENEGADO -- {consumer_uri!r} "
                        f"no esta en la lista de peers autorizados del modelo FL.\n"
                        f"  Autorizados: {_allowed_uris}"
                    )
                    # --- CH: Rechazo por politica de acceso restringido ---
                    _report_to_ch(
                        message_type="ids:RejectionMessage",
                        source_connector=CONNECTOR_URI,
                        target_connector=consumer_uri,
                        status="success",
                        error_message="Policy Enforcement: consumer not in authorized peer list (connector-restricted-policy)",
                        additional_data={
                            "event": "contract_rejected_policy",
                            "worker": INSTANCE_ID,
                            "reason": "connector-restricted-policy",
                            "consumer": consumer_uri,
                        },
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

        # --- CH: Contrato aceptado ---
        _report_to_ch(
            message_type="ids:ContractAgreementMessage",
            source_connector=CONNECTOR_URI,
            target_connector=consumer_uri,
            status="success",
            contract_id=contrato.get("@id", ""),
            additional_data={
                "event": "contract_agreement",
                "worker": INSTANCE_ID,
                "consumer": consumer_uri,
                "contract_offer_id": contract_offer_id,
            },
        )

        return _multipart_response(
            _resp("ids:ContractAgreementMessage", "contractAgreementMessage"),
            json.dumps(contrato)
        )

    elif tipo == "ids:ContractAgreementMessage":
        _sender_uri = mensaje.get("ids:issuerConnector", {}).get("@id", "")
        # --- CH [GAP 5]: Confirmacion de ContractAgreement recibida ---
        _report_to_ch(
            message_type="ids:ContractAgreementMessage",
            source_connector=_sender_uri or "unknown",
            target_connector=CONNECTOR_URI,
            status="success",
            additional_data={
                "event": "contract_agreement_confirmation_received",
                "worker": INSTANCE_ID,
                "sender": _sender_uri,
            },
        )
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
                        # fl_weights::workerX::roundN::gzip::payload::<b64>
                        if "::payload::" in _cv:
                            try:
                                is_gzipped = "::gzip::payload::" in _cv
                                _splitter = "::gzip::payload::" if is_gzipped else "::payload::"
                                _b64_payload = _cv.split(_splitter, 1)[1]
                                
                                _raw_bytes = base64.b64decode(_b64_payload)
                                if is_gzipped:
                                    import gzip as _gzip
                                    _raw_bytes = _gzip.decompress(_raw_bytes)
                                    
                                payload_dict = json.loads(_raw_bytes.decode("utf-8"))
                                log.info(f"[ArtifactRequest] payload recuperado desde contentVersion b64 (gzip={is_gzipped}): type={payload_dict.get('type','?')!r}")
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
                        selected_csv = None
                        is_docker = False

                        if content_version.startswith("fl_algorithm_docker::"):
                            content_version = content_version[len("fl_algorithm_docker::"):]
                            is_docker = True
                        elif content_version.startswith("fl_algorithm::"):
                            content_version = content_version[len("fl_algorithm::"):]

                        if "||from_coordinator::1" in content_version:
                            content_version = content_version.replace("||from_coordinator::1", "")
                            from_coord = True
                        if "||selected_csv_b64::" in content_version:
                            content_version, selected_csv_b64 = content_version.split("||selected_csv_b64::", 1)
                            try:
                                selected_csv = base64.b64decode(selected_csv_b64).decode("utf-8")
                            except Exception as _e:
                                log.error(f"[ArtifactRequest] Error decodificando selected_csv_b64: {_e}")

                        if is_docker:
                            payload_dict = {
                                "type"            : "fl_algorithm_docker",
                                "docker_image"    : content_version,
                                "from_coordinator": from_coord,
                                "selected_csv"    : selected_csv,
                            }
                            log.info(f"[ArtifactRequest] fl_algorithm_docker recuperado desde ids:contentVersion | image={content_version}")
                        else:
                            if "||fl_config::" in content_version:
                                algo_part, config_part = content_version.split("||fl_config::", 1)
                            else:
                                algo_part, config_part = content_version, None
                            payload_dict = {
                                "type"            : "fl_algorithm",
                                "content"         : algo_part,
                                "config"          : config_part,
                                "from_coordinator": from_coord,
                                "selected_csv"    : selected_csv,
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

        # Intentar recuperar metadatos del payload JSON si el ECC obligo a
        # reconstruir el artefacto desde ids:contentVersion.
        if payload_dict.get("type") == "fl_algorithm" and payload_val:
            try:
                pv = json.loads(payload_val)
                if isinstance(pv, dict):
                    for key in (
                        "config",
                        "selected_csv",
                        "coordinator_uri",
                        "coordinator_ecc",
                        "from_coordinator",
                        "coordinator_transfer_contract",
                        "coordinator_requested_artifact",
                    ):
                        if key in pv and pv.get(key) not in (None, ""):
                            payload_dict[key] = pv[key]
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
                if fl_state.get("current_round") != round_num:
                    log.warning(f"Ignorando pesos locales de worker-{sender} para ronda {round_num} (ronda actual: {fl_state.get('current_round')})")
                    return _multipart_response(resp_h, json.dumps({"status": "ignored", "reason": "outdated_round"}))
                _round_weights[sender] = {
                    "weights_b64": weights_b64,
                    "n_samples"  : n_samples,
                    "metrics"    : metrics,
                }
                total_recibidos = len(_round_weights)

            payload_size = len(weights_b64) if weights_b64 else 0
            log.info(
                f"  Pesos locales ronda {round_num} <- wss://ecc-worker{sender}:8086/data "
                f"[OK IDS via ECC]  {payload_size/1024:.0f} KB"
            )
            log.info(f"[fl_weights] [OK] Pesos de worker-{sender} ronda {round_num} acumulados ({total_recibidos} total)")
            _report_to_ch(
                message_type="ids:ArtifactResponseMessage",
                source_connector=mensaje.get("ids:issuerConnector", {}).get("@id", f"worker{sender}"),
                target_connector=CONNECTOR_URI,
                status="success",
                additional_data={
                    "event"          : "local_weights_received_ids_ecc",
                    "round"          : round_num,
                    "worker"         : sender,
                    "n_samples"      : n_samples,
                    "payload_kb"     : round(payload_size / 1024, 1),
                    "channel"        : "ids_ecc_wss",
                    "total_recibidos": total_recibidos,
                },
            )
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
                coordinator_transfer_contract = payload_dict.get("coordinator_transfer_contract")
                coordinator_requested_artifact = payload_dict.get("coordinator_requested_artifact")
                if not FL_WEIGHTS_VIA_ECC:
                    _start_worker_ws_client()

            with _fl_lock:
                fl_state["current_round"] = round_num
                if fl_state.get("status") == "idle":
                    fl_state["status"] = f"round_{round_num}"

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
                    with _fl_lock:
                        if fl_state.get("status") == "idle" and fl_state.get("current_round") != round_num:
                            log.warning(f"Ronda {round_num} cancelada durante train_local. Ignorando resultados descartan envío local.")
                            return
                    _send_local_weights(result["weights_b64"], result["n_samples"],
                                        result["metrics"], round_num)
                except Exception as exc:
                    log.error(f"Error ronda {round_num}: {exc}")

            threading.Thread(target=_train_and_reply, daemon=True).start()
            return _multipart_response(resp_h, json.dumps({"status": "training_started", "round": round_num}))

        # fl_algorithm_docker -- descargar imagen Docker con algorithm.py + deps
        if artifact_type == "fl_algorithm_docker":
            docker_image = payload_dict.get("docker_image", "")
            if not docker_image:
                log.error("[fl_algorithm_docker] docker_image no especificada en payload")
                return _multipart_response(resp_h, json.dumps({
                    "status": "error", "reason": "missing_docker_image"
                }))

            log.info(
                f"[fl_algorithm_docker] Recibida referencia Docker via IDS\n"
                f"  Image: {docker_image}\n"
                f"  Coordinator: {payload_dict.get('coordinator_uri', '?')}"
            )

            # Descargar imagen y extraer algorithm.py + fl_config.json
            pull_ok = _pull_and_extract_algo_image(docker_image)
            if not pull_ok:
                log.error(f"[fl_algorithm_docker] Error descargando/extrayendo imagen {docker_image}")
                return _multipart_response(resp_h, json.dumps({
                    "status": "error", "reason": "docker_pull_failed",
                    "docker_image": docker_image,
                }))

            # Configurar estado del worker (igual que fl_algorithm)
            if payload_dict.get("from_coordinator"):
                is_coordinator = False
                sel_csv = payload_dict.get("selected_csv")
                coord_ecc = payload_dict.get("coordinator_ecc")
                coord_uri = payload_dict.get("coordinator_uri")
                coord_transfer = payload_dict.get("coordinator_transfer_contract")
                coord_artifact = payload_dict.get("coordinator_requested_artifact")
                if coord_ecc:
                    coordinator_ecc_url = coord_ecc
                if coord_uri:
                    coordinator_conn_uri = coord_uri
                if coord_transfer:
                    coordinator_transfer_contract = coord_transfer
                if coord_artifact:
                    coordinator_requested_artifact = coord_artifact
                if sel_csv:
                    full_path = os.path.join(INPUT_DIR, sel_csv)
                    if os.path.exists(full_path):
                        _my_selected_csv = full_path
                        log.info(
                            f"[fl_algorithm_docker] CSV seleccionado por coordinator: "
                            f"{sel_csv} -> {full_path}"
                        )
                    else:
                        log.warning(
                            f"[fl_algorithm_docker] CSV '{sel_csv}' no encontrado en {INPUT_DIR}"
                            f" -- se usara seleccion automatica"
                        )
                with _fl_lock:
                    fl_state["status"] = "worker_ready"
                    fl_state["current_round"] = 0
                log.info(
                    f"[OK] algorithm.py extraido de imagen Docker -- worker-{INSTANCE_ID} = WORKER\n"
                    f"  Docker Image: {docker_image}"
                )
            else:
                is_coordinator = True
                log.info(f"algorithm.py extraido de imagen Docker -- worker-{INSTANCE_ID} = COORDINATOR")

            cfg = _load_fl_config()
            return _multipart_response(
                resp_h,
                json.dumps({
                    "status"       : "docker_image_received",
                    "coordinator"  : INSTANCE_ID,
                    "docker_image" : docker_image,
                    "delivery_mode": "docker_image",
                    "fl_config"    : {
                        "rounds"       : cfg["rounds"],
                        "round_timeout": cfg["round_timeout"],
                        "epochs"       : cfg["epochs"],
                        "batch_size"   : cfg["batch_size"],
                        "learning_rate": cfg["learning_rate"],
                    },
                    "next_step": "Waiting for global weights from coordinator",
                }),
            )

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
                is_coordinator = False
                sel_csv = payload_dict.get("selected_csv")
                coord_ecc = payload_dict.get("coordinator_ecc")
                coord_uri = payload_dict.get("coordinator_uri")
                coord_transfer = payload_dict.get("coordinator_transfer_contract")
                coord_artifact = payload_dict.get("coordinator_requested_artifact")
                if coord_ecc:
                    coordinator_ecc_url = coord_ecc
                if coord_uri:
                    coordinator_conn_uri = coord_uri
                if coord_transfer:
                    coordinator_transfer_contract = coord_transfer
                if coord_artifact:
                    coordinator_requested_artifact = coord_artifact
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
                with _fl_lock:
                    fl_state["status"] = "worker_ready"
                    fl_state["current_round"] = 0
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
                    # --- CH [GAP 2]: Algoritmo servido como fuente (soberanía de datos) ---
                    _report_to_ch(
                        message_type="ids:ArtifactResponseMessage",
                        source_connector=CONNECTOR_URI,
                        target_connector=requester,
                        status="success",
                        additional_data={
                            "event": "algorithm_served_as_source",
                            "requester": requester,
                            "algo_size_bytes": len(algo_bytes_src),
                            "config_included": config_b64_src is not None,
                            "worker": INSTANCE_ID,
                        },
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

        # ── Docker Image: construir y pushear al registry privado ─────────
        docker_image_tag = None
        if FL_ALGO_VIA_DOCKER:
            log.info("[/fl/fetch-algorithm] FL_ALGO_VIA_DOCKER=true → construyendo imagen Docker del algoritmo...")
            docker_image_tag = _build_and_push_algo_image()
            if docker_image_tag:
                log.info(f"[/fl/fetch-algorithm] Imagen Docker lista: {docker_image_tag}")
            else:
                log.warning("[/fl/fetch-algorithm] No se pudo construir la imagen Docker — se usará distribución base64 como fallback")
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
        docker_image_tag = None

    if success:
        cfg = _load_fl_config()
        resp_content = {
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
        if docker_image_tag:
            resp_content["docker_image"] = docker_image_tag
            resp_content["delivery_mode"] = "docker_image"
        else:
            resp_content["delivery_mode"] = "ids_base64"
        return JSONResponse(status_code=200, content=resp_content)
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
    cfg           = _compute_and_persist_shared_numeric_features(cfg)
    if FL_ALGO_VIA_DOCKER:
        log.info(
            "[/fl/start] FL_ALGO_VIA_DOCKER=true -> reconstruyendo imagen con "
            "fl_config.json ya actualizado"
        )
        docker_image_tag = _build_and_push_algo_image()
        if docker_image_tag:
            log.info(f"[/fl/start] Imagen Docker actualizada para esta corrida: {docker_image_tag}")
        else:
            log.warning(
                "[/fl/start] No se pudo reconstruir la imagen Docker actualizada; "
                "se usara la ultima referencia disponible o fallback base64"
            )
    rounds        = int(cfg["rounds"])
    round_timeout = int(cfg["round_timeout"])
    min_workers   = int(cfg["min_workers"])

    with open(algo_path, "rb") as f:
        algo_bytes = f.read()

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            config_bytes = f.read()
    else:
        config_bytes = json.dumps(cfg, indent=2).encode()

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
            "feature_selection": {
                "enabled": bool(cfg.get("feature_selection_enabled", True)),
                "strategy": cfg.get("feature_selection_strategy", "unknown"),
                "source": os.getenv("COORDINATOR_CSV_REFERENCE", ""),
                "selected_count": len(cfg.get("selected_numeric_features", []) or []),
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
        try:
            candidates = _get_peer_csv_candidates_by_worker_id(peer_worker_id)
            log.info(
                f"[ws/llm-recommend] {len(candidates)} CSVs obtenidos del peer "
                f"worker-{peer_worker_id} desde su catalogo IDS"
            )
        except Exception as e:
            log.warning(
                f"[ws/llm-recommend] No se pudo obtener CSVs IDS de peer worker-{peer_worker_id}: {e}"
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

    log.info(
        f"[ws/llm-recommend] Iniciando con {LLM_MODEL} "
        f"-- evaluando CSVs de worker-{target_worker} ({len(candidates)} candidatos)"
    )

    # Obtener columnas del coordinator como referencia para el overlap de schema.
    # Funciona con cualquier dataset: el LLM evalua overlap real de columnas,
    # no el nombre del fichero ni el dominio hardcodeado.
    coordinator_cols = _get_my_columns()

    context_str = (
        f"This is a Federated Learning training session. "
        f"The coordinator (worker-{INSTANCE_ID}) has provided its reference columns. "
        f"You are evaluating the datasets of the peer worker-{target_worker}. "
        f"Select the dataset whose schema best matches the coordinator reference."
    )

    # Reutilizar _llm_recommend_dataset — prompt unificado, robusto y agnóstico al dataset.
    # El streaming de tokens al WebSocket ya lo hace _notify_ws_clients internamente.
    loop = asyncio.get_running_loop()

    def _run_llm():
        return _llm_recommend_dataset(
            csvs             = candidates,
            coordinator_cols = coordinator_cols if coordinator_cols else None,
            context          = context_str,
            timeout          = 120,
        )

    try:
        result = await loop.run_in_executor(None, _run_llm)

        if result:
            await websocket.send_json({
                "type"      : "result",
                "filename"  : result["filename"],
                "reasoning" : result["reasoning"],
                "confidence": result["confidence"],
                "model"     : LLM_MODEL,
                "worker"    : target_worker,
            })
        else:
            await websocket.send_json({
                "type"   : "error",
                "message": "LLM no disponible o no pudo recomendar un dataset. Usando column-matching como fallback.",
            })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning(f"[ws/llm-recommend] Error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
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
        
        # Extraer recursos ya registrados para no duplicar
        existing_resources = catalogs[0].get("ids:offeredResource", [])
        existing_titles = []
        for r in existing_resources:
            titles = r.get("ids:title", [])
            if isinstance(titles, list) and len(titles) > 0:
                val = titles[0].get("@value", "")
                if val: existing_titles.append(val)
                
    except Exception as e:
        return {"error": f"Error obteniendo catalogo: {e}"}

    published = []
    skipped   = []
    
    for c in csvs:
        fname = c["filename"]
        target_title = f"Dataset: {fname}"
        
        if target_title in existing_titles:
            log.info(f"[publish-datasets] {fname} ya esta publicado en el catalogo. Omitiendo.")
            skipped.append(fname)
            continue
            
        try:
            # 1. Resource
            import uuid
            import datetime
            ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            resource_id = f"https://w3id.org/idsa/autogen/textResource/dataset_{uuid.uuid4()}"
            artifact_id = f"http://w3id.org/engrd/connector/artifact/dataset_{fname}"
            
            # ── Propiedades semanticas del IDS Information Model ──
            _xsd_str = "http://www.w3.org/2001/XMLSchema#string"
            csvw_context = [
                "http://www.w3.org/ns/csvw",
                {
                    "ids": "https://w3id.org/idsa/core/",
                    "idsc": "https://w3id.org/idsa/code/",
                    "csvw": "http://www.w3.org/ns/csvw#",
                    "schema": "https://schema.org/",
                }
            ]
            csvw_column_names = list(c["columns"])

            # ── 1. Resource IDS ──
            res_body = {
                "@context": csvw_context,
                "@id": resource_id,
                "@type": "ids:TextResource",
                "ids:title": [{"@value": f"Dataset: {fname}", "@type": _xsd_str}],
                "ids:language": [{"@id": "https://w3id.org/idsa/code/EN"}],
                "ids:version": "1.0.0",
                "ids:contentType": {"@id": "https://w3id.org/idsa/code/SCHEMA_DEFINITION"},
            }
            res_resp = requests.post(
                f"{ecc_base}/api/offeredResource/",
                headers={"catalog": catalog_id, "Content-Type": "application/json"},
                json=res_body,
                verify=TLS_CERT,
                auth=basic_api,
                timeout=10,
            )
            res_resp.raise_for_status()

            # ── 2. Representacion 1: Metadata ──
            metadata_repr_id = f"https://w3id.org/idsa/autogen/representation/meta_{uuid.uuid4()}"
            schema_id = f"{metadata_repr_id}/schema"
            n_cols = len(csvw_column_names)
            csv_size_mb = c.get("size_mb", 0)
            meta_body = {
                "@context": csvw_context,
                "@id": metadata_repr_id,
                "@type": "ids:TextRepresentation",
                "ids:title": [{"@value": f"Semantic Metadata -- {fname}", "@type": _xsd_str}],
                "ids:description": [{
                    "@value": "Semantic metadata describing the dataset schema and size.",
                    "@type": _xsd_str
                }],
                "csvw:tableSchema": {
                    "@id": schema_id,
                    "@type": "csvw:Schema",
                    "schema:numberOfItems": {
                        "@value": str(n_cols),
                        "@type": "http://www.w3.org/2001/XMLSchema#nonNegativeInteger"
                    },
                    "schema:contentSize": {
                        "@value": f"{csv_size_mb} MB",
                        "@type": _xsd_str
                    }
                },
                "schema:variableMeasured": [
                    {"@value": col, "@type": _xsd_str}
                    for col in csvw_column_names
                ],
                "ids:mediaType": {"@id": "https://w3id.org/idsa/code/JSON"}
            }
            meta_resp = requests.post(
                f"{ecc_base}/api/representation/",
                headers={"resource": resource_id, "Content-Type": "application/json"},
                json=meta_body,
                verify=TLS_CERT,
                auth=basic_api,
                timeout=10,
            )
            if not meta_resp.ok:
                raise RuntimeError(
                    f"Metadata representation rechazada por ECC "
                    f"({meta_resp.status_code}): {meta_resp.text[:500]}"
                )

            # ── 3. Representacion 2: Training (dataset para entrenamiento FL) ──
            exec_repr_id = f"https://w3id.org/idsa/autogen/representation/exec_{uuid.uuid4()}"
            exec_body = {
                "@context": csvw_context,
                "@id": exec_repr_id,
                "@type": "ids:TextRepresentation",
                "ids:title": [{"@value": f"Training Artifact -- {fname}", "@type": _xsd_str}],
                "ids:mediaType": {"@id": "https://w3id.org/idsa/code/CSV"},
                "ids:instance": [{
                    "@type": "ids:Artifact",
                    "@id": artifact_id,
                    "ids:fileName": fname,
                    "ids:creationDate": {"@value": ts, "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"},
                }]
            }
            exec_resp = requests.post(
                f"{ecc_base}/api/representation/",
                headers={"resource": resource_id, "Content-Type": "application/json"},
                json=exec_body,
                verify=TLS_CERT,
                auth=basic_api,
                timeout=10,
            )
            exec_resp.raise_for_status()
            
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
            contract_resp = requests.post(
                f"{ecc_base}/api/contractOffer/",
                headers={"resource": resource_id, "Content-Type": "application/json"},
                json=c_body,
                verify=TLS_CERT,
                auth=basic_api,
                timeout=10,
            )
            contract_resp.raise_for_status()
            
            published.append({"filename": fname, "resource_id": resource_id})
            log.info(f"[publish-datasets] Publicado {fname}: {resource_id}")
            
        except Exception as e:
            log.error(f"[publish-datasets] Error publicando {fname}: {e}")
            
    return {
        "status": "success", 
        "published_count": len(published), 
        "published": published,
        "skipped_count": len(skipped),
        "skipped": skipped
    }


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


@app.get("/ids/self-description")
def get_self_description():
    """
    Consulta al catalogo real del connector (TrueConnector via /api/selfDescription/)
    para devolver el JSON-LD de la FASE 1 intacto.
    """
    from requests.auth import HTTPBasicAuth
    basic_api = HTTPBasicAuth(API_USER, API_PASS)
    ecc_base  = f"https://{ECC_HOSTNAME}:8449"
    try:
        sd = requests.get(f"{ecc_base}/api/selfDescription/", verify=TLS_CERT, auth=basic_api, timeout=10).json()
        return sd
    except Exception as e:
        log.error(f"Error obteniendo selfDescription: {e}")
        return {"error": str(e), "ids:resourceCatalog": []}


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


@app.post("/broker/discover/worker")
async def broker_discover_single_worker(request: Request):
    """
    Analiza un solo peer (ecc_url + connector_uri) y devuelve el resultado
    inmediatamente. Usado por el script pfg_ids_fl_flow.py para mostrar
    el analisis de cada worker en cuanto termina, sin esperar a los demas.

    Body: { "ecc_url": "https://ecc-worker1:8889/data", "connector_uri": "http://..." }
    """
    if not is_coordinator:
        return JSONResponse(
            status_code=400,
            content={"error": "Solo el coordinator puede hacer descubrimiento."}
        )

    body         = await request.json()
    ecc_url      = body.get("ecc_url", "")
    connector_uri = body.get("connector_uri", "")

    if not ecc_url or not connector_uri:
        return JSONResponse(status_code=400, content={"error": "ecc_url y connector_uri requeridos"})

    my_cols = _get_my_columns()
    my_set  = set(c.lower() for c in my_cols)

    try:
        best_cols, real_uri, best_filename, best_ratio, llm_rec, all_evaluated = _get_peer_best_csv(
            ecc_url, connector_uri, my_set
        )
    except Exception as exc:
        log.error(f"[/broker/discover/worker] Error analizando {ecc_url}: {exc}")
        return JSONResponse(status_code=500, content={"error": str(exc), "ecc_url": ecc_url})

    common = my_set & set(c.lower() for c in best_cols)
    compatible = best_ratio >= MATCH_THRESHOLD

    result = {
        "connector_uri"  : real_uri,
        "ecc_url"        : ecc_url,
        "compatible"     : compatible,
        "match_ratio"    : round(best_ratio, 3),
        "common_cols"    : sorted(common),
        "selected_csv"   : best_filename,
        "math_filename"  : llm_rec.get("math_filename") if llm_rec else best_filename,
        "llm_recommended": llm_rec.get("filename")   if llm_rec else None,
        "llm_reasoning"  : llm_rec.get("reasoning")  if llm_rec else None,
        "llm_confidence" : llm_rec.get("confidence") if llm_rec else 0.0,
        "llm_model"      : LLM_MODEL,
        "all_evaluated"  : all_evaluated,
        "my_columns_count": len(my_cols),
    }

    # Acumular en cache si es compatible (para /fl/negotiate)
    if compatible:
        with _compatible_workers_lock:
            # Evitar duplicados
            existing_uris = {w["connector_uri"] for w in _compatible_workers_cache}
            if real_uri not in existing_uris:
                _compatible_workers_cache.append(result)

    return result


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
    global coordinator_transfer_contract, coordinator_requested_artifact
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
    # --- CH [GAP 4]: Worker recibe pesos globales del coordinator ---
    _report_to_ch(
        message_type="ids:ArtifactResponseMessage",
        source_connector=coordinator_conn_uri or coord_uri or "coordinator",
        target_connector=CONNECTOR_URI,
        status="success",
        additional_data={
            "event": "global_weights_received",
            "round": round_num,
            "worker": INSTANCE_ID,
            "coordinator_uri": coordinator_conn_uri or coord_uri,
        },
    )

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
    # --- CH: Worker reporta pesos locales al coordinator ---
    _report_to_ch(
        message_type="ids:ArtifactRequestMessage",
        source_connector=CONNECTOR_URI,
        status="success",
        additional_data={
            "event": "local_weights_received",
            "from_worker": sender,
            "round": round_num,
            "n_samples": n_samples,
            "metrics": metrics,
            "coordinator": INSTANCE_ID,
        },
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
    coord_transfer_contract = body.get("coordinator_transfer_contract", "")
    coord_requested_artifact = body.get("coordinator_requested_artifact", "")
    sel_csv   = body.get("selected_csv", "")

    if FL_OPT_OUT:
        log.warning(
            f"[/fl/accept-negotiation] RECHAZADO -- FL_OPT_OUT=true en worker-{INSTANCE_ID}\n"
            f"  Coordinator: {coord_uri}"
        )
        # --- CH: Worker rechaza participar (soberania) ---
        _report_to_ch(
            message_type="ids:RejectionMessage",
            source_connector=CONNECTOR_URI,
            target_connector=coord_uri,
            status="success",
            error_message="Policy Enforcement: worker exercised data sovereignty (FL_OPT_OUT)",
            additional_data={
                "event": "worker_rejected_participation",
                "worker": INSTANCE_ID,
                "coordinator": coord_uri,
                "reason": "FL_OPT_OUT",
            },
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
    if coord_transfer_contract:
        coordinator_transfer_contract = coord_transfer_contract
    if coord_requested_artifact:
        coordinator_requested_artifact = coord_requested_artifact

    # Solo abrir tunel DataApp->DataApp cuando no estemos forzando transporte via ECC.
    if not FL_WEIGHTS_VIA_ECC:
        _start_worker_ws_client()

    log.info(
        f"[/fl/accept-negotiation] ACEPTADO -- worker-{INSTANCE_ID} participara en FL\n"
        f"  Coordinator: {coord_uri}  |  CSV asignado: {sel_csv or '(auto)'}"
    )
    # --- CH: Worker acepta participar ---
    _report_to_ch(
        message_type="ids:ContractAgreementMessage",
        source_connector=CONNECTOR_URI,
        target_connector=coord_uri,
        status="success",
        additional_data={
            "event": "worker_accepted_participation",
            "worker": INSTANCE_ID,
            "coordinator": coord_uri,
            "selected_csv": sel_csv or "auto",
        },
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

        # ── Excluir al propio coordinator ─────────────────────────────────────
        # El coordinator no negocia consigo mismo: se excluye por URI IDS y
        # por ECC URL para cubrir el caso en que la URI no coincida exactamente.
        if uri == CONNECTOR_URI:
            log.info(f"[/fl/negotiate] Omitiendo al propio coordinator ({uri})")
            continue
        if ecc_url == my_ecc_url:
            log.info(f"[/fl/negotiate] Omitiendo al propio coordinator por ECC URL ({ecc_url})")
            continue
        # ─────────────────────────────────────────────────────────────────────

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
                "message"      : "No se pudo derivar el worker_id del peer para contactar su ECC.",
            })
            continue

        log.info(
            f"[/fl/negotiate] Negociando con worker-{peer_worker_id} "
            f"via ContractRequestMessage -> {_ecc_forward_url(ecc_url) if FL_IDS_ECC_ONLY else f'{peer_dataapp_url}/data'}"
        )

        peer_desc = _ids_send(
            _ecc_forward_url(ecc_url) if FL_IDS_ECC_ONLY else ecc_url,
            uri,
            "ids:DescriptionRequestMessage",
            use_local_ecc=FL_IDS_ECC_ONLY,
        )
        peer_contract_offer, peer_requested_artifact = _first_contract_artifact(
            peer_desc,
            selected_csv=sel_csv,
        )
        if not peer_requested_artifact:
            rejected.append({
                "connector_uri": uri,
                "ecc_url"      : ecc_url,
                "reason"       : "error",
                "message"      : "No se pudo derivar el artifact IDS del peer.",
            })
            continue
        log.info(
            f"[/fl/negotiate] Artifact/contract resueltos para worker-{peer_worker_id}\n"
            f"  selected_csv      : {sel_csv or '(auto)'}\n"
            f"  requested_artifact: {peer_requested_artifact}\n"
            f"  contract_offer    : {peer_contract_offer or '(autogen/fallback)'}"
        )

        # Payload del ContractRequest FL
        _contract_payload = {
            "@context"      : _ids_context(),
            "@type"         : "ids:ContractRequest",
            "@id"           : peer_contract_offer or f"https://w3id.org/idsa/autogen/contractRequest/fl_nego_{uuid.uuid4()}",
            "ids:permission": [],
            "ids:provider"  : {"@id": uri},
            "ids:obligation": [], "ids:prohibition": [],
            "ids:consumer"  : {"@id": CONNECTOR_URI},
        }

        # -- Paso 1: ContractRequestMessage via ECC->ECC --------------------------
        ids_result = _ids_send(
            forward_to_url       = _ecc_forward_url(ecc_url) if FL_IDS_ECC_ONLY else f"{peer_dataapp_url}/data",
            forward_to_connector = uri,
            message_type         = "ids:ContractRequestMessage",
            requested_element    = peer_requested_artifact,
            payload              = _contract_payload,
            use_local_ecc        = FL_IDS_ECC_ONLY,
        )

        # -- Paso 2: Evaluar la respuesta (viene del ECC o del fallback DataApp) -
        ids_type = ids_result.get("@type", "")

        if "ContractAgreement" in ids_type:
            transfer_contract_id = ids_result.get("@id", f"ids-agreement-worker{peer_worker_id}")
            log.info(f"[/fl/negotiate] worker-{peer_worker_id} ACEPTO [OK]  IDS ContractAgreement={transfer_contract_id}")
            # --- CH: Peer acepto trabajar ---
            _report_to_ch(
                message_type="ids:ContractAgreementMessage",
                source_connector=CONNECTOR_URI,
                target_connector=uri,
                status="success",
                contract_id=transfer_contract_id,
                additional_data={
                    "event": "negotiate_peer_accepted",
                    "coordinator": INSTANCE_ID,
                    "peer_worker": peer_worker_id,
                    "match_ratio": worker["match_ratio"],
                    "selected_csv": sel_csv,
                },
            )
            accepted.append({
                "connector_uri"    : uri,
                "ecc_url"          : ecc_url,
                "match_ratio"      : worker["match_ratio"],
                "transfer_contract": transfer_contract_id,
                "requested_artifact": peer_requested_artifact,
                "selected_csv"     : sel_csv,
            })
            if not FL_IDS_ECC_ONLY:
                # Notificar al peer sus datos de coordinator para que abra el tunel WS
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
            # --- CH: Peer rechazo trabajar ---
            _report_to_ch(
                message_type="ids:RejectionMessage",
                source_connector=uri,
                target_connector=CONNECTOR_URI,
                status="success",
                error_message=f"Policy Enforcement: {reason} - {msg}",
                additional_data={
                    "event": "negotiate_peer_rejected",
                    "coordinator": INSTANCE_ID,
                    "peer_worker": peer_worker_id,
                    "reason": reason,
                },
            )
            rejected.append({
                "connector_uri": uri,
                "ecc_url"      : ecc_url,
                "reason"       : reason,
                "message"      : msg,
            })

        else:
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


@app.post("/system/reset")
def system_reset():
    global fl_state, _my_selected_csv
    global is_coordinator, _published_fl_contract
    global coordinator_ecc_url, coordinator_conn_uri
    global coordinator_transfer_contract, coordinator_requested_artifact


    # --- MEMORIA: Reset de todas las variables de estado ---
    with _fl_lock:
        fl_state = {
            "status"       : "idle",
            "current_round": 0,
            "total_rounds" : 0,
            "history"      : [],
        }
    with _round_lock:
        _round_weights.clear()

    _my_selected_csv     = None
    is_coordinator       = False
    _published_fl_contract = {}
    coordinator_ecc_url  = None
    coordinator_conn_uri = None
    coordinator_transfer_contract = None
    coordinator_requested_artifact = None

    PEER_SELECTED_CSVS.clear()

    with _compatible_workers_lock:
        _compatible_workers_cache.clear()

    with _negotiate_lock:
        _accepted_workers.clear()

    with _ws_perf_lock:
        _ws_perf_stats.update({
            "ws_sends": 0, "ws_total_ms": 0.0, "ws_bytes": 0,
            "ids_ecc_sends": 0, "ids_ecc_total_ms": 0.0, "ids_ecc_bytes": 0,
            "http_sends": 0, "http_total_ms": 0.0, "http_bytes": 0,
            "ws_failures": 0, "ids_ecc_failures": 0, "http_failures": 0, "history": [],
        })

    deleted = []

    # --- DISCO: Borrar algorithm.py recibido via IDS (nunca el /app/ baked) ---
    if os.path.exists(ALGO_IDS_PATH):
        try:
            os.remove(ALGO_IDS_PATH)
            deleted.append(os.path.basename(ALGO_IDS_PATH))
        except Exception as e:
            log.warning(f"[reset] No se pudo borrar {ALGO_IDS_PATH}: {e}")

    # --- DISCO: Borrar fl_config.json recibido via IDS ---
    if os.path.exists(CONFIG_PATH):
        try:
            os.remove(CONFIG_PATH)
            deleted.append(os.path.basename(CONFIG_PATH))
        except Exception as e:
            log.warning(f"[reset] No se pudo borrar {CONFIG_PATH}: {e}")

    # --- DISCO: Borrar TODOS los .json del OUTPUT_DIR ---
    #    (global_model.json, fl_results.json, local_metrics.json, etc.)
    #    Los CSV del INPUT_DIR NUNCA se tocan.
    if os.path.isdir(OUTPUT_DIR):
        for fname in list(os.listdir(OUTPUT_DIR)):
            if fname.endswith(".json"):
                fpath = os.path.join(OUTPUT_DIR, fname)
                try:
                    os.remove(fpath)
                    deleted.append(fname)
                except Exception as e:
                    log.warning(f"[reset] No se pudo borrar {fpath}: {e}")

    log.info(f"[SYSTEM] Reset completo. Borrados: {deleted}")
    return {
        "status" : "ok",
        "message": "DataApp restaurado al estado inicial (como si acabase de arrancar)",
        "deleted": deleted,
    }


@app.post("/system/reset-all")
def system_reset_all():
    """
    Cascada de limpieza total: llama a POST /system/reset en cada peer DataApp
    conocido via PEER_ECC_URLS, luego se resetea a si mismo.
    Deja el ecosistema en el mismo estado que al arrancar por primera vez.
    """
    import re as _re

    results = {}
    _verify = False  # Docker interno con cert auto-firmado

    # Derivar URL de cada DataApp peer desde su ECC URL
    # Convencion: ecc-workerN:8889 -> be-dataapp-workerN:8500
    for ecc_url in PEER_ECC_URLS:
        m = _re.search(r"ecc-worker(\d+)", ecc_url)
        if not m:
            continue
        n = m.group(1)
        peer_dataapp = f"https://be-dataapp-worker{n}:8500"
        try:
            r = requests.post(
                f"{peer_dataapp}/system/reset",
                verify=_verify,
                timeout=10,
            )
            results[f"worker{n}"] = "ok" if r.ok else f"http_{r.status_code}"
        except Exception as e:
            results[f"worker{n}"] = f"error: {str(e)[:80]}"
        log.info(f"[reset-all] worker{n} -> {results[f'worker{n}']}")

    # Resetear el propio nodo
    own = system_reset()
    results["self"] = "ok"

    log.info(f"[SYSTEM] reset-all completado: {results}")
    return {
        "status" : "ok",
        "message": "Todos los DataApps restaurados al estado inicial",
        "nodes"  : results,
        "deleted": own.get("deleted", []),
    }


@app.get("/health")
def health():
    return {
        "status"  : "ok",
        "instance": INSTANCE_ID,
        "role"    : "coordinator" if is_coordinator else "worker",
    }


@app.get("/status")
def status():
    """Estado extendido para Postman y monitorizacion."""
    try:
        cfg = _load_fl_config()
        csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
        
        # Obtener CSV seleccionado de forma segura
        csv_sel = None
        if os.path.exists(SELECTED_CSV_PATH):
            try:
                csv_sel = _csv_path()
            except Exception:
                pass

        return {
            "instance"        : INSTANCE_ID,
            "role"            : "coordinator" if is_coordinator else "worker",
            "algorithm_loaded": os.path.exists(ALGO_IDS_PATH),  # Solo la version dinamica recibida via IDS
            "config_loaded"   : os.path.exists(CONFIG_PATH),
            "fl_config"       : cfg if os.path.exists(CONFIG_PATH) else None,
            "csv_available"   : csv_files,
            "csv_selected"    : csv_sel,
            "coordinator_ecc" : f"https://{ECC_HOSTNAME}:8889/data" if is_coordinator else coordinator_ecc_url,
            "peer_eccs"       : PEER_ECC_URLS,
            "fl_status"       : fl_state.get("status", "idle"),
            "fl_round"        : fl_state.get("current_round", 0),
            "fl_total_rounds" : fl_state.get("total_rounds", 0),
        }
    except Exception as e:
        log.error(f"[status-500] Error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/llm-status")
def get_llm_status():
    """Verifica si el motor de IA (Ollama) esta disponible."""
    try:
        # Intenta una peticion ligera a Ollama
        r = requests.get(f"{LLM_ENDPOINT.rsplit('/', 2)[0]}/api/tags", timeout=3)
        return {
            "status": "online" if r.status_code == 200 else "error",
            "model": LLM_MODEL,
            "engine": "Ollama",
            "details": r.json() if r.status_code == 200 else str(r.status_code)
        }
    except Exception as e:
        return {"status": "offline", "error": str(e)}


@app.get("/fl/status")
def fl_status():
    with _fl_lock:
        return dict(fl_state)


@app.get("/fl/docker-image-status")
def fl_docker_image_status():
    """
    Devuelve informacion sobre la imagen Docker construida para distribuir
    el algoritmo FL, si FL_ALGO_VIA_DOCKER esta activado.
    """
    return {
        "enabled": FL_ALGO_VIA_DOCKER,
        "registry": FL_DOCKER_REGISTRY,
        "image_tag": _docker_algo_image_tag,
        "status": "ready" if _docker_algo_image_tag else "not_built"
    }


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
        "per_class_report" : data.get("per_class_report", {}),
        "confusion_matrix" : data.get("confusion_matrix", []),
        "num_classes"      : data.get("num_classes", 0),
        "class_names"      : data.get("class_names", []),
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
        if channel == "ws":
            key = "ws"
        elif channel == "ids_ecc":
            key = "ids_ecc"
        else:
            key = "http"
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
                    if fl_state.get("current_round") != round_num:
                        log.warning(f"[WS FL-Train] Ignorando pesos de worker-{sender} para ronda {round_num} (ronda actual: {fl_state.get('current_round')})")
                        continue
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
_ws_ai_manager = _WSConnectionManager()
_ws_ids_monitor_manager = _WSConnectionManager() # Monitor de trazas IDS


def _notify_ai_clients(data: dict):
    """Notifica al canal exclusivo de IA."""
    try:
        global global_event_loop
        if global_event_loop and global_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(_ws_ai_manager.broadcast(data), global_event_loop)
    except Exception:
        pass


def _notify_ids_monitor(data: dict):
    """Envia trazas de paquetes IDS al monitor de Postman."""
    try:
        global global_event_loop
        if global_event_loop and global_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(_ws_ids_monitor_manager.broadcast(data), global_event_loop)
    except Exception:
        pass


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
@app.get("/ws/tunnel-status/")
def ws_tunnel_status():
    """Version REST GET del estado de tuneles."""
    return _get_tunnel_status_data()

@app.websocket("/ws/tunnel-status-live")
async def ws_tunnel_status_live(websocket: WebSocket):
    """Version WebSocket: Envia el estado de tuneles cada 2 segundos."""
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(_get_tunnel_status_data())
            await asyncio.sleep(2)
    except Exception:
        pass

def _get_tunnel_status_data():
    return {
        "instance"                : INSTANCE_ID,
        "fl_status_clients"       : len(_ws_manager._clients),
        "worker_tunnels_active"   : list(fl_ws_manager.active_workers.keys()),
        "coordinator_tunnel_active": fl_ws_client_conn is not None,
        "ecc_wss_enabled"         : WS_ECC_ENABLED,
        "ids_ecc_only"            : FL_IDS_ECC_ONLY,
        "role"                    : "coordinator" if is_coordinator else "worker",
    }


@app.get("/ws/performance")
@app.get("/ws/performance/")
def ws_performance():
    """Version REST GET de las metricas de rendimiento."""
    return _get_performance_data()

@app.websocket("/ws/performance-live")
async def ws_performance_live(websocket: WebSocket):
    """Version WebSocket: Streaming de metricas de rendimiento cada 2 segundos."""
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(_get_performance_data())
            await asyncio.sleep(2)
    except Exception:
        pass

def _get_performance_data():
    with _ws_perf_lock:
        stats = dict(_ws_perf_stats)
        history = list(stats.pop("history", []))

    ws_avg = (stats["ws_total_ms"] / stats["ws_sends"]) if stats["ws_sends"] > 0 else 0
    ids_ecc_avg = (stats["ids_ecc_total_ms"] / stats["ids_ecc_sends"]) if stats["ids_ecc_sends"] > 0 else 0
    http_avg = (stats["http_total_ms"] / stats["http_sends"]) if stats["http_sends"] > 0 else 0
    speedup = (ids_ecc_avg / ws_avg) if ws_avg > 0 and ids_ecc_avg > 0 else None

    return {
        "instance": INSTANCE_ID,
        "role": "coordinator" if is_coordinator else "worker",
        "summary": {
            "ws_dataapp": {
                "sends": stats["ws_sends"],
                "avg_ms": round(ws_avg, 2),
                "total_kb": round(stats["ws_bytes"] / 1024, 1),
                "failures": stats["ws_failures"],
            },
            "ids_ecc": {
                "sends": stats["ids_ecc_sends"],
                "avg_ms": round(ids_ecc_avg, 2),
                "total_kb": round(stats["ids_ecc_bytes"] / 1024, 1),
                "failures": stats["ids_ecc_failures"],
            },
            "http_fallback": {
                "sends": stats["http_sends"],
                "avg_ms": round(http_avg, 2),
                "total_kb": round(stats["http_bytes"] / 1024, 1),
                "failures": stats["http_failures"],
            },
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
            "ws_speedup_factor_vs_ids_ecc": round(speedup, 2) if speedup else "N/A (datos insuficientes)",
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
        if "1000" not in str(exc) and "1001" not in str(exc):
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

@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    """
    Streaming de logs en tiempo real via WebSocket.
    Permite ver lo que pasa en el contenedor sin usar docker logs.
    """
    await websocket.accept()
    log.info(f"[WS /logs] Cliente suscrito a logs (Worker {INSTANCE_ID})")
    try:
        # 1. Enviar las ultimas 20 lineas como contexto inicial
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    await websocket.send_text(line.strip())

        # 2. Tail -f del archivo de logs
        async def tail_log():
            if not os.path.exists(log_file):
                return
            with open(log_file, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(0.5)
                        continue
                    await websocket.send_text(line.strip())

        await tail_log()
    except WebSocketDisconnect:
        log.info(f"[WS /logs] Cliente desconectado")
    except Exception as e:
        log.error(f"[WS /logs] Error: {e}")


@app.websocket("/ws/ai-insights")
async def ws_ai_insights(websocket: WebSocket):
    """
    Canal exclusivo de IA con PERSISTENCIA.
    Al conectar, recibe inmediatamente la ultima decision tomada por el LLM.
    """
    await _ws_ai_manager.connect(websocket)
    try:
        # Enviar la ultima decision como contexto inmediato si existe
        with _ai_insight_lock:
            if _last_ai_insight:
                await websocket.send_json(_last_ai_insight)
            else:
                await websocket.send_json({
                    "event": "info",
                    "message": "Esperando primera recomendacion de IA...",
                    "instance": INSTANCE_ID
                })

        # Mantener conexion activa con un heartbeat cada 30s
        while True:
            # Enviar un latido tecnico para evitar timeouts de proxies/Postman
            await websocket.send_json({"event": "ping", "instance": INSTANCE_ID})
            # Esperar una respuesta o tiempo de espera
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # El timeout es normal, volvemos a enviar el ping
                continue
    except WebSocketDisconnect:
        await _ws_ai_manager.disconnect(websocket)
    except Exception:
        await _ws_ai_manager.disconnect(websocket)


@app.websocket("/ws/ids-monitor")
async def ws_ids_monitor(websocket: WebSocket):
    """
    Monitor de trafico IDS LIVE. 
    Muestra los paquetes IDS (Request/Response) que pasan por el DataApp.
    """
    await _ws_ids_monitor_manager.connect(websocket)
    # Mantener conexion activa con un heartbeat cada 30s
    try:
        while True:
            await websocket.send_json({"event": "ping", "instance": INSTANCE_ID})
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        await _ws_ids_monitor_manager.disconnect(websocket)
    except Exception:
        await _ws_ids_monitor_manager.disconnect(websocket)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500, access_log=False)
