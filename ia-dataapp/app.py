"""
app.py — IA DataApp API  (FL Worker + IDS Connector endpoint)
=============================================================
Cada instancia (ia-dataapp-1/2/3) expone:

  Endpoints sistema:
    GET  /health
    GET  /status

  Endpoints IDS Connector (Java ECC → aquí):
    POST /data                  ← ECC Provider enruta mensajes IDS aquí
    POST /incoming-data-app/routerBodyBinary  ← WSS fallback

  Endpoints algoritmo:
    POST /upload-algorithm      ← carga directa (interno / tests)
    POST /execute
    GET  /result

  Endpoints Federated Learning:
    POST /fl/train
    POST /fl/set-model
    GET  /fl/model
    GET  /fl/history

Flujo IDS para upload-algorithm:
  Consumer → ECC-Consumer → ECC-Provider → /data  (multipart IDS)
  → parse_ids_multipart()
  → guarda algorithm.py en /app-src/algorithm.py
  → distribuye a workers 2 y 3 vía POST /upload-algorithm directo
  → responde IDS multipart al ECC-Provider
"""

import os
import importlib.util
import logging
import json
import sys
import re
import email
import email.policy
import requests
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn

app = FastAPI(
    title="IA DataApp — FL Worker + IDS",
    description="Worker FL con endpoint IDS Connector para recepción de algorithm.py",
    version="3.0.0"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Instance-%(name)s] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

DATA_DIR       = "/home/nobody/data"
INPUT_DIR      = os.path.join(DATA_DIR, "input")
OUTPUT_DIR     = os.path.join(DATA_DIR, "output")
_ALGO_MOUNTED  = "/app-src/algorithm.py"
_ALGO_BAKED    = "/app/algorithm.py"
INSTANCE_ID    = os.getenv("INSTANCE_ID", "1")

# Flag explícito: solo True cuando algorithm.py llega vía IDS o /upload-algorithm
# NO depende del fichero baked en la imagen — ese no cuenta como "recibido"
_algorithm_received_via_ids = False

def get_algorithm_path() -> str:
    """Devuelve la ruta del algorithm.py disponible, priorizando el recibido vía IDS."""
    if os.path.exists(_ALGO_MOUNTED):
        return _ALGO_MOUNTED
    return _ALGO_BAKED

def is_algorithm_loaded() -> bool:
    """True si algorithm.py está disponible en el volumen compartido.
    
    El fichero llega al volumen ia_algorithm cuando cualquier instancia lo
    recibe vía IDS o /upload-algorithm. Las demás instancias lo ven de
    inmediato porque comparten el mismo volumen montado en /app-src.
    No se depende del flag en memoria (_algorithm_received_via_ids), que
    solo es True en el proceso que recibió el fichero directamente.
    """
    return os.path.exists(_ALGO_MOUNTED)

# URLs de los otros workers (solo usadas por instancia 1 para distribuir)
WORKER_2_URL   = os.getenv("WORKER_2_URL", "http://ia-dataapp-2:8500")
WORKER_3_URL   = os.getenv("WORKER_3_URL", "http://ia-dataapp-3:8500")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(INPUT_DIR,  exist_ok=True)

LOCAL_MODEL_FILE = os.path.join(OUTPUT_DIR, f"local_model_{INSTANCE_ID}.json")

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_algorithm_module():
    path = get_algorithm_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"algorithm.py no encontrado en {path}")
    spec   = importlib.util.spec_from_file_location("algorithm", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algorithm"] = module
    spec.loader.exec_module(module)
    return module


def get_csv_path() -> str:
    specific = os.path.join(INPUT_DIR, f"unsw_nb15_worker_{INSTANCE_ID}.csv")
    if os.path.exists(specific):
        return specific
    csv_files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")])
    if not csv_files:
        raise FileNotFoundError(
            f"No hay CSV en {INPUT_DIR}. Ejecuta prepare_dataset.py primero."
        )
    idx = min(int(INSTANCE_ID) - 1, len(csv_files) - 1)
    return os.path.join(INPUT_DIR, csv_files[idx])


def _save_algorithm(content_bytes: bytes) -> str:
    """Guarda algorithm.py en el volumen montado, marca el flag IDS y recarga el módulo."""
    global _algorithm_received_via_ids
    save_path = _ALGO_MOUNTED
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(content_bytes)
    # Invalida caché para que próxima llamada use la versión nueva
    if "algorithm" in sys.modules:
        del sys.modules["algorithm"]
    # ← Marca recepción real. Solo aquí se activa algorithm_loaded=True
    _algorithm_received_via_ids = True
    logger.info(f"algorithm.py guardado en {save_path} ({len(content_bytes)} bytes) — algorithm_loaded=True")
    return save_path


def _distribute_algorithm_to_workers(content_bytes: bytes):
    """
    Instancia 1 distribuye algorithm.py a workers 2 y 3 directamente (red interna).
    Esto garantiza que los 3 workers tienen la misma versión del algoritmo
    antes de arrancar cualquier ronda FL.
    """
    if INSTANCE_ID != "1":
        return  # solo el coordinador distribuye

    for worker_url in [WORKER_2_URL, WORKER_3_URL]:
        try:
            resp = requests.post(
                f"{worker_url}/upload-algorithm",
                files={"algorithm": ("algorithm.py", content_bytes, "text/x-python")},
                timeout=30
            )
            resp.raise_for_status()
            logger.info(f"algorithm.py distribuido a {worker_url}: {resp.json()}")
        except Exception as e:
            logger.error(f"Error distribuyendo algorithm.py a {worker_url}: {e}")


# ── Parser multipart IDS ──────────────────────────────────────────────────────

def parse_ids_multipart(body: bytes, content_type: str) -> dict:
    """
    Parsea el cuerpo multipart/form-data enviado por el ECC del TRUE Connector.

    El ECC Provider envía a /data un multipart con dos partes:
      - header  : JSON-LD con el IDS Message (ArtifactRequestMessage, etc.)
      - payload : contenido real (en nuestro caso, el fichero algorithm.py)

    Devuelve:
      {
        "ids_message_type": str,   # tipo del mensaje IDS
        "ids_header"      : dict,  # JSON-LD del header parseado
        "payload_bytes"   : bytes, # contenido del payload
        "payload_name"    : str,   # nombre sugerido del fichero (si hay)
      }
    """
    # Construimos un mensaje MIME para aprovechar el parser estándar de Python
    # El Content-Type ya viene en el header de la request HTTP
    mime_msg = email.message_from_bytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body,
        policy=email.policy.default
    )

    ids_header     = {}
    payload_bytes  = b""
    payload_name   = "algorithm.py"

    for part in mime_msg.iter_parts():
        disposition = part.get("Content-Disposition", "")
        part_name   = ""
        fname_match = re.search(r'name="([^"]+)"', disposition)
        if fname_match:
            part_name = fname_match.group(1)

        fname_match2 = re.search(r'filename="([^"]+)"', disposition)
        if fname_match2:
            payload_name = fname_match2.group(1)

        raw_payload = part.get_payload(decode=True)
        if raw_payload is None:
            raw_payload = part.get_payload()
            if isinstance(raw_payload, str):
                raw_payload = raw_payload.encode("utf-8")
            else:
                raw_payload = b""

        if part_name == "header":
            try:
                ids_header = json.loads(raw_payload.decode("utf-8"))
            except Exception:
                ids_header = {"raw": raw_payload.decode("utf-8", errors="replace")}
        elif part_name == "payload":
            payload_bytes = raw_payload
        else:
            # Si no hay name explícito, el primer bloque suele ser el header
            if not ids_header:
                try:
                    ids_header = json.loads(raw_payload.decode("utf-8"))
                except Exception:
                    payload_bytes = raw_payload
            else:
                payload_bytes = raw_payload

    ids_message_type = (
        ids_header.get("@type", "")
        or ids_header.get("ids:type", "")
        or "unknown"
    )

    return {
        "ids_message_type": ids_message_type,
        "ids_header"      : ids_header,
        "payload_bytes"   : payload_bytes,
        "payload_name"    : payload_name,
    }


def build_ids_response(success: bool, detail: str, connector_uri: str) -> str:
    """
    Construye un IDS ResultMessage en JSON-LD para responder al ECC.
    El ECC espera este formato para propagar la respuesta de vuelta al Consumer.
    """
    import datetime
    return json.dumps({
        "@context"          : "https://w3id.org/idsa/contexts/context.jsonld",
        "@type"             : "ids:ResultMessage" if success else "ids:RejectionMessage",
        "@id"               : f"https://w3id.org/idsa/autogen/resultMessage/{connector_uri}",
        "ids:modelVersion"  : "4.1.0",
        "ids:issued"        : {"@value": datetime.datetime.utcnow().isoformat() + "Z",
                               "@type" : "xsd:dateTimeStamp"},
        "ids:issuerConnector": {"@id": connector_uri},
        "ids:recipientConnector": [],
        "ids:senderAgent"   : {"@id": connector_uri},
        "ids:contentVersion": "1.0",
        "ids:result"        : detail
    }, indent=2)


# ── Schemas ───────────────────────────────────────────────────────────────────

class FLTrainRequest(BaseModel):
    global_weights_b64: Optional[str] = None
    round: int = 1

class FLSetModelRequest(BaseModel):
    weights_b64: str
    round: int


# ── Endpoints sistema ─────────────────────────────────────────────────────────

@app.get("/health", tags=["Sistema"])
def health():
    return {"status": "ok", "instance": INSTANCE_ID, "role": "fl_worker"}


@app.get("/status", tags=["Sistema"])
def status():
    csv_files    = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    output_files = os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else []
    try:
        csv_selected = get_csv_path()
    except FileNotFoundError:
        csv_selected = None

    return {
        "instance"        : INSTANCE_ID,
        "algorithm_loaded": is_algorithm_loaded(),   # ← True SOLO tras recepción IDS real
        "algorithm_path"  : get_algorithm_path() if is_algorithm_loaded() else None,
        "csv_available"   : csv_files,
        "csv_selected"    : csv_selected,
        "fl_model_loaded" : os.path.exists(LOCAL_MODEL_FILE),
        "outputs"         : output_files
    }


# ── Endpoint IDS principal (/data) ────────────────────────────────────────────
#
# El ECC Provider (TRUE Connector) enruta aquí TODOS los mensajes IDS
# que llegan desde el ECC Consumer.
#
# Flujo completo:
#   1. Consumer envía multipart a ECC-Consumer  (puerto 8449/8091)
#   2. ECC-Consumer → ECC-Provider  (IDS protocol, TLS)
#   3. ECC-Provider → POST /data    (multipart form, esta función)
#   4. Aquí parseamos, actuamos, respondemos con IDS ResultMessage
#   5. ECC-Provider reenvía la respuesta al ECC-Consumer
#   6. ECC-Consumer la devuelve al Consumer original
#
# Ref: TRUE Connector docs — DATA_APP_ENDPOINT = https://be-dataapp-provider:8183/data
# ─────────────────────────────────────────────────────────────────────────────

CONNECTOR_URI = os.getenv(
    "ISSUER_CONNECTOR_URI",
    "http://w3id.org/engrd/connector/provider"
)

@app.post("/data", tags=["IDS Connector"])
async def ids_data_endpoint(request: Request):
    """
    Endpoint principal del IDS Connector (DATA_APP_ENDPOINT).
    Recibe mensajes IDS multipart del ECC Provider y los procesa.

    Mensajes soportados:
      - ArtifactRequestMessage con payload = algorithm.py
        → guarda algorithm.py y lo distribuye a workers 2 y 3
      - Cualquier otro mensaje
        → responde con ResultMessage genérico (extensible)
    """
    content_type = request.headers.get("Content-Type", "")
    body         = await request.body()

    logger.info(f"[/data] ═══ Mensaje IDS recibido ═══")
    logger.info(f"[/data] Content-Type : {content_type[:120]}")
    logger.info(f"[/data] Body size    : {len(body)} bytes")
    logger.info(f"[/data] Body preview : {body[:200]}")

    # ── 1. Parsear multipart IDS ──────────────────────────────────────────────
    try:
        parsed = parse_ids_multipart(body, content_type)
    except Exception as e:
        logger.error(f"[/data] Error parseando multipart: {e}")
        return Response(
            content=build_ids_response(False, f"Parse error: {e}", CONNECTOR_URI),
            media_type="application/json",
            status_code=400
        )

    msg_type     = parsed["ids_message_type"]
    payload_bytes = parsed["payload_bytes"]
    payload_name  = parsed["payload_name"]

    logger.info(
        f"[/data] IDS message type: {msg_type} | "
        f"payload: {payload_name} ({len(payload_bytes)} bytes)"
    )

    # ── 2. Procesar según tipo de mensaje IDS ─────────────────────────────────

    # El payload puede llegar en base64 (cuando ids_auto_send.py lo codifica en JSON)
    # o en crudo (multipart binario directo). Detectar y decodificar si es necesario.
    if payload_bytes:
        try:
            decoded = __import__("base64").b64decode(payload_bytes)
            # Verificar que el resultado parece un script Python válido
            if decoded[:6] in (b'"""', b"'''", b"impo", b"# ===", b"#!") or b"def " in decoded[:200]:
                payload_bytes = decoded
                logger.info(f"[/data] Payload decodificado desde base64 ({len(payload_bytes)} bytes)")
        except Exception:
            pass  # No era base64, usar como está

    # ── Caso A: ArtifactRequestMessage con algorithm.py ──────────────────────
    #    El Consumer envía algorithm.py para que el Provider lo ejecute en FL.
    #    Detectamos por tipo de mensaje O por nombre del fichero en el payload.
    is_algorithm_upload = (
        "ArtifactRequestMessage" in msg_type
        or "artifact" in msg_type.lower()
        or payload_name.endswith(".py")
        or (payload_bytes and payload_bytes[:6] in (b"import", b"\"\"\"", b"#"))
    )

    if is_algorithm_upload and payload_bytes:
        try:
            save_path = _save_algorithm(payload_bytes)
            _distribute_algorithm_to_workers(payload_bytes)

            detail = (
                f"algorithm.py recibido y guardado en {save_path}. "
                f"Distribuido a workers 2 y 3. "
                f"Instancia {INSTANCE_ID} lista para FL."
            )
            logger.info(f"[/data] {detail}")

            return Response(
                content=build_ids_response(True, detail, CONNECTOR_URI),
                media_type="application/json",
                status_code=200
            )

        except Exception as e:
            logger.error(f"[/data] Error guardando algorithm.py: {e}", exc_info=True)
            return Response(
                content=build_ids_response(False, str(e), CONNECTOR_URI),
                media_type="application/json",
                status_code=500
            )

    # ── Caso B: ArtifactRequestMessage para fl_global_model ─────────────────
    #    El Consumer solicita el modelo global cuando detecta FL completado.
    #    Solo instancia 1 (coordinador) tiene el modelo global.
    requested = (
        parsed.get("ids_header", {}).get("ids:requestedArtifact", {})
        if isinstance(parsed.get("ids_header"), dict) else {}
    )
    requested_id = (
        requested.get("@id", "") if isinstance(requested, dict) else str(requested)
    )
    header_str = str(parsed.get("ids_header", ""))

    is_model_request = (
        "fl_global_model" in requested_id
        or "fl_global_model" in header_str
    )
    is_results_request = (
        "fl_results" in requested_id
        or "fl_results" in header_str
    )

    if is_model_request or is_results_request:
        artifact_label = "fl_global_model" if is_model_request else "fl_results"
        model_file   = os.path.join(OUTPUT_DIR, "global_model.json")
        results_file = os.path.join(OUTPUT_DIR, "fl_results.json")

        target_file = model_file if is_model_request else results_file

        if not os.path.exists(target_file):
            detail = f"Artefacto {artifact_label} no disponible todavía. FL no completado."
            logger.warning(f"[/data] {detail}")
            return Response(
                content=build_ids_response(False, detail, CONNECTOR_URI),
                media_type="application/json",
                status_code=404
            )

        try:
            import base64 as _b64, datetime as _dt
            with open(target_file) as _f:
                artifact_data = json.load(_f)

            # Enriquecer con metadata IDS
            artifact_data["artifact_type"] = artifact_label
            artifact_data["source"]        = "fl_coordinator"
            artifact_data["provider_uri"]  = CONNECTOR_URI
            artifact_data["served_at"]     = _dt.datetime.utcnow().isoformat() + "Z"

            # Si es modelo, añadir global_metrics con el nombre que espera el Consumer
            if is_model_request and "metrics" in artifact_data and "global_metrics" not in artifact_data:
                artifact_data["global_metrics"] = artifact_data["metrics"]

            # Si es resultados, construir summary si no existe
            if is_results_request and isinstance(artifact_data, list):
                history = artifact_data
                artifact_data = {
                    "artifact_type" : "fl_results",
                    "source"        : "fl_coordinator",
                    "provider_uri"  : CONNECTOR_URI,
                    "served_at"     : _dt.datetime.utcnow().isoformat() + "Z",
                    "total_rounds"  : len(history),
                    "history"       : history,
                    "summary"       : {
                        "rounds_completed": len(history),
                        "workers_used"    : history[-1].get("workers_ok", 0) if history else 0,
                        "total_samples"   : history[-1].get("total_samples", 0) if history else 0,
                        "final_metrics"   : history[-1].get("global_metrics", {}) if history else {},
                        "first_metrics"   : history[0].get("global_metrics", {}) if history else {},
                        "accuracy_delta"  : round(
                            history[-1].get("global_metrics", {}).get("accuracy", 0) -
                            history[0].get("global_metrics", {}).get("accuracy", 0), 6
                        ) if len(history) >= 2 else 0,
                        "auc_delta"       : round(
                            history[-1].get("global_metrics", {}).get("auc", 0) -
                            history[0].get("global_metrics", {}).get("auc", 0), 6
                        ) if len(history) >= 2 else 0,
                    }
                }

            payload_b64 = _b64.b64encode(
                json.dumps(artifact_data).encode("utf-8")
            ).decode("utf-8")

            detail = f"Artefacto {artifact_label} entregado. Instancia {INSTANCE_ID}."
            logger.info(f"[/data] ✅ {detail} ({len(payload_b64)} bytes b64)")

            # Respuesta IDS con el artefacto embebido en ids:result
            response_body = {
                "@context"           : "https://w3id.org/idsa/contexts/context.jsonld",
                "@type"              : "ids:ArtifactResponseMessage",
                "@id"                : f"https://w3id.org/idsa/autogen/artifactResponseMessage/{CONNECTOR_URI}",
                "ids:modelVersion"   : "4.1.0",
                "ids:issued"         : {
                    "@value": _dt.datetime.utcnow().isoformat() + "Z",
                    "@type" : "xsd:dateTimeStamp"
                },
                "ids:issuerConnector": {"@id": CONNECTOR_URI},
                "ids:payload"        : payload_b64,
                "ids:result"         : detail
            }
            return Response(
                content=json.dumps(response_body, indent=2),
                media_type="application/json",
                status_code=200
            )

        except Exception as e:
            logger.error(f"[/data] Error sirviendo artefacto {artifact_label}: {e}", exc_info=True)
            return Response(
                content=build_ids_response(False, str(e), CONNECTOR_URI),
                media_type="application/json",
                status_code=500
            )

    # ── Caso C: Mensaje IDS genérico ─────────────────────────────────────────
    detail = (
        f"Mensaje IDS recibido por instancia {INSTANCE_ID}. "
        f"Tipo: {msg_type}. "
        f"Payload: {len(payload_bytes)} bytes."
    )
    logger.info(f"[/data] Mensaje no reconocido, respondiendo genéricamente.")
    return Response(
        content=build_ids_response(True, detail, CONNECTOR_URI),
        media_type="application/json",
        status_code=200
    )


@app.post("/incoming-data-app/routerBodyBinary", tags=["IDS Connector"])
async def ids_wss_endpoint(request: Request):
    """
    Endpoint alternativo para comunicación WSS/binaria (IDSCP2 / WS_EDGE=true).
    Redirige internamente al handler principal /data.
    """
    return await ids_data_endpoint(request)


# ── Upload directo (interno / tests / fallback) ───────────────────────────────

@app.post("/upload-algorithm", tags=["Algoritmo"])
async def upload_algorithm(algorithm: UploadFile = File(...)):
    """
    Carga directa de algorithm.py (sin pasar por IDS).
    Usado por: tests locales, distribución interna worker-a-worker, curl directo.
    """
    try:
        content_bytes = await algorithm.read()
        save_path = _save_algorithm(content_bytes)
        return {
            "status"     : "ok",
            "instance"   : INSTANCE_ID,
            "path"       : save_path,
            "size_bytes" : len(content_bytes)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/execute", tags=["Algoritmo"])
@app.get("/execute",  tags=["Algoritmo"])
def execute():
    try:
        algo      = load_algorithm_module()
        data_path = get_csv_path()
        result    = algo.run(data_path)
        out = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
        with open(out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info(f"Ejecución completada → {out}")
        return {"status": "ok", "instance": INSTANCE_ID, "result": result}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error en execute: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/result", tags=["Algoritmo"])
def get_result():
    out = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
    if not os.path.exists(out):
        raise HTTPException(status_code=404, detail="Sin resultado aún")
    with open(out) as f:
        return {"instance": INSTANCE_ID, "result": json.load(f)}


# ── Endpoints Federated Learning ──────────────────────────────────────────────

@app.post("/fl/train", tags=["Federated Learning"])
def fl_train(req: FLTrainRequest):
    logger.info(f"FL ronda {req.round} iniciada")
    try:
        algo      = load_algorithm_module()
        data_path = get_csv_path()
        result    = algo.run(data_path, global_weights_b64=req.global_weights_b64)

        round_file = os.path.join(OUTPUT_DIR, f"fl_round_{req.round}_instance_{INSTANCE_ID}.json")
        with open(round_file, "w") as f:
            json.dump({
                "round"    : req.round,
                "instance" : INSTANCE_ID,
                "n_samples": result.get("n_samples"),
                "metrics"  : result.get("metrics"),
            }, f, indent=2)

        logger.info(
            f"Ronda {req.round} OK | "
            f"acc={result['metrics']['accuracy']:.4f} | "
            f"auc={result['metrics']['auc']:.4f}"
        )
        return {
            "status"      : "ok",
            "instance"    : INSTANCE_ID,
            "round"       : req.round,
            "weights_b64" : result["weights_b64"],
            "n_samples"   : result["n_samples"],
            "metrics"     : result["metrics"],
            "input_dim"   : result.get("input_dim"),
            "feature_cols": result.get("feature_cols"),
        }

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error en fl/train ronda {req.round}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/fl/set-model", tags=["Federated Learning"])
def fl_set_model(req: FLSetModelRequest):
    with open(LOCAL_MODEL_FILE, "w") as f:
        json.dump({"round": req.round, "weights_b64": req.weights_b64}, f)
    logger.info(f"Modelo global ronda {req.round} almacenado")
    return {"status": "ok", "instance": INSTANCE_ID, "round": req.round}


@app.get("/fl/model", tags=["Federated Learning"])
def fl_get_model():
    if not os.path.exists(LOCAL_MODEL_FILE):
        raise HTTPException(status_code=404, detail="Sin modelo global aún")
    with open(LOCAL_MODEL_FILE) as f:
        return json.load(f)


@app.get("/fl/history", tags=["Federated Learning"])
def fl_history():
    files = sorted([
        f for f in os.listdir(OUTPUT_DIR)
        if f.startswith("fl_round_") and f"_instance_{INSTANCE_ID}.json" in f
    ])
    history = []
    for fname in files:
        with open(os.path.join(OUTPUT_DIR, fname)) as f:
            history.append(json.load(f))
    return {"instance": INSTANCE_ID, "history": history}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500)