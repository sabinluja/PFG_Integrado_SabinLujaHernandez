"""
app_consumer.py — Consumer IDS DataApp
=======================================
API mínima que corre en el be-dataapp-consumer (puerto 8500).

Recibe el modelo global FL enviado por el Provider vía IDS
cuando el Federated Learning termina.

Flujo IDS de retorno (Provider → Consumer):
  fl_coordinator → be-dataapp-provider:8183/proxy
    → ecc-provider:8887
      → ecc-consumer:8889
        → be-dataapp-consumer:8183/data (Java DataApp)
          → be-dataapp-consumer:8500/data (este endpoint)

Endpoints:
  POST /data          ← Java DataApp ECC enruta aquí los mensajes IDS
  GET  /fl/model      ← consulta el modelo global recibido
  GET  /fl/model/full ← modelo completo con pesos (para descarga)
  GET  /status        ← estado del consumer
  GET  /health        ← health check
"""

import os
import re
import json
import base64
import email
import email.policy
import logging
import datetime
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CONSUMER] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Consumer DataApp",
    description="Consumer IDS — recibe modelo global FL del Provider",
    version="1.0.0"
)

DATA_DIR    = "/home/nobody/data"
OUTPUT_DIR  = os.path.join(DATA_DIR, "output")
MODEL_FILE  = os.path.join(OUTPUT_DIR, "received_global_model.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

CONNECTOR_URI = os.getenv(
    "ISSUER_CONNECTOR_URI",
    "http://w3id.org/engrd/connector/consumer"
)

MODEL_FILE   = os.path.join(OUTPUT_DIR, "received_global_model.json")
RESULTS_FILE = os.path.join(OUTPUT_DIR, "received_fl_results.json")


# ── Parser multipart IDS ──────────────────────────────────────────────────────

def parse_ids_multipart(body: bytes, content_type: str) -> dict:
    """Parsea el multipart IDS enviado por el ECC."""
    mime_msg = email.message_from_bytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body,
        policy=email.policy.default
    )

    ids_header    = {}
    payload_bytes = b""

    for part in mime_msg.iter_parts():
        disposition = part.get("Content-Disposition", "")
        part_name   = ""
        m = re.search(r'name="([^"]+)"', disposition)
        if m:
            part_name = m.group(1)

        raw = part.get_payload(decode=True)
        if raw is None:
            raw = part.get_payload()
            raw = raw.encode("utf-8") if isinstance(raw, str) else b""

        if part_name == "header":
            try:
                ids_header = json.loads(raw.decode("utf-8"))
            except Exception:
                ids_header = {"raw": raw.decode("utf-8", errors="replace")}
        elif part_name == "payload":
            payload_bytes = raw
        else:
            if not ids_header:
                try:
                    ids_header = json.loads(raw.decode("utf-8"))
                except Exception:
                    payload_bytes = raw
            else:
                payload_bytes = raw

    msg_type = (
        ids_header.get("@type", "")
        or ids_header.get("ids:type", "")
        or "unknown"
    )

    return {
        "ids_message_type": msg_type,
        "ids_header"      : ids_header,
        "payload_bytes"   : payload_bytes,
    }


def build_ids_response(success: bool, detail: str) -> str:
    return json.dumps({
        "@context"           : "https://w3id.org/idsa/contexts/context.jsonld",
        "@type"              : "ids:ResultMessage" if success else "ids:RejectionMessage",
        "@id"                : f"https://w3id.org/idsa/autogen/resultMessage/{CONNECTOR_URI}",
        "ids:modelVersion"   : "4.1.0",
        "ids:issued"         : {
            "@value": datetime.datetime.utcnow().isoformat() + "Z",
            "@type" : "xsd:dateTimeStamp"
        },
        "ids:issuerConnector": {"@id": CONNECTOR_URI},
        "ids:result"         : detail
    }, indent=2)


# ── Endpoints sistema ─────────────────────────────────────────────────────────

@app.get("/health", tags=["Sistema"])
def health():
    return {"status": "ok", "role": "consumer_dataapp"}


@app.get("/status", tags=["Sistema"])
def status():
    model_received   = os.path.exists(MODEL_FILE)
    results_received = os.path.exists(RESULTS_FILE)

    model_info = results_info = None

    if model_received:
        try:
            with open(MODEL_FILE) as f:
                d = json.load(f)
            model_info = {
                "round"         : d.get("round"),
                "global_metrics": d.get("global_metrics"),
                "received_at"   : d.get("received_at"),
                "provider_uri"  : d.get("provider_uri"),
            }
        except Exception:
            pass

    if results_received:
        try:
            with open(RESULTS_FILE) as f:
                d = json.load(f)
            results_info = {
                "total_rounds"  : d.get("total_rounds"),
                "received_at"   : d.get("received_at"),
                "summary"       : d.get("summary"),
            }
        except Exception:
            pass

    return {
        "role"            : "consumer",
        "model_received"  : model_received,
        "results_received": results_received,
        "model_info"      : model_info,
        "results_info"    : results_info,
    }


# ── Endpoint IDS principal (/data) ────────────────────────────────────────────

@app.post("/data", tags=["IDS Connector"])
async def ids_data_endpoint(request: Request):
    """
    Recibe mensajes IDS del ECC Consumer.
    Procesa ArtifactResponseMessage con el modelo global FL del Provider.
    """
    content_type = request.headers.get("Content-Type", "")
    body         = await request.body()

    logger.info("═══ Mensaje IDS recibido en Consumer ═══")
    logger.info(f"Content-Type : {content_type[:120]}")
    logger.info(f"Body size    : {len(body)} bytes")

    # ── Parsear multipart ─────────────────────────────────────────────────────
    try:
        parsed = parse_ids_multipart(body, content_type)
    except Exception as e:
        logger.error(f"Error parseando multipart: {e}")
        return Response(
            content=build_ids_response(False, f"Parse error: {e}"),
            media_type="application/json",
            status_code=400
        )

    msg_type      = parsed["ids_message_type"]
    payload_bytes = parsed["payload_bytes"]

    logger.info(f"IDS message type: {msg_type} | payload: {len(payload_bytes)} bytes")

    # ── Detectar artefacto FL del Provider ────────────────────────────────────
    # El Provider responde con ArtifactResponseMessage.
    # El payload puede venir:
    #   (A) en payload_bytes del multipart (si el ECC lo desempaqueta)
    #   (B) en ids_header["ids:payload"] como base64 (si el ECC pasa el JSON tal cual)
    header_str    = str(parsed["ids_header"])
    ids_header    = parsed["ids_header"]
    header_payload = None
    if isinstance(ids_header, dict):
        header_payload = ids_header.get("ids:payload")

    is_fl_artifact = (
        "ArtifactResponseMessage" in msg_type
        or "ResultMessage"        in msg_type
        or "fl_global_model"      in header_str
        or "fl_results"           in header_str
        or header_payload is not None
        or len(payload_bytes) > 500
    )
    logger.info(f"is_fl_artifact={is_fl_artifact} | msg_type={msg_type} | "
                f"payload_bytes={len(payload_bytes)} | header_payload={'sí' if header_payload else 'no'}")

    if is_fl_artifact:
        try:
            # ── Obtener bytes del artefacto ───────────────────────────────────
            # Prioridad: header_payload (base64) → payload_bytes (multipart)
            raw_data = None

            if header_payload:
                # El payload viaja en el campo ids:payload del JSON de respuesta
                try:
                    raw_data = json.loads(base64.b64decode(header_payload).decode("utf-8"))
                    logger.info("✅ Payload decodificado desde ids:payload (base64+JSON)")
                except Exception as e:
                    logger.warning(f"ids:payload no decodificable como base64+JSON: {e}")

            if raw_data is None and payload_bytes:
                # El payload viene en la parte multipart
                for decoder_name, decoder in [
                    ("base64+JSON", lambda b: json.loads(base64.b64decode(b).decode("utf-8"))),
                    ("JSON directo", lambda b: json.loads(b.decode("utf-8", errors="replace"))),
                ]:
                    try:
                        raw_data = decoder(payload_bytes)
                        logger.info(f"✅ Payload decodificado: {decoder_name}")
                        break
                    except Exception:
                        pass

            if raw_data is None:
                raise ValueError(f"No se pudo decodificar el artefacto ({len(payload_bytes)} bytes payload, header_payload={'sí' if header_payload else 'no'})")

            data          = raw_data
            artifact_type = data.get("artifact_type", "unknown")
            logger.info(f"artifact_type detectado: {artifact_type}")

            # Enriquecer con metadatos de recepción
            data["received_at"]       = datetime.datetime.utcnow().isoformat() + "Z"
            data["ids_message_type"]  = msg_type
            data["consumer_uri"]      = CONNECTOR_URI

            # ── Caso A: modelo global (pesos + métricas finales) ──────────────
            if artifact_type == "fl_global_model":
                with open(MODEL_FILE, "w") as f:
                    json.dump(data, f, indent=2)

                metrics = data.get("global_metrics", {})
                detail  = (
                    f"Modelo global FL recibido. "
                    f"Ronda {data.get('round')} | "
                    f"acc={metrics.get('accuracy')} auc={metrics.get('auc')}"
                )
                logger.info(f"✅ [MODELO] {detail}")

            # ── Caso B: historial de resultados por ronda ─────────────────────
            elif artifact_type == "fl_results":
                with open(RESULTS_FILE, "w") as f:
                    json.dump(data, f, indent=2)

                summary = data.get("summary", {})
                detail  = (
                    f"Resultados FL recibidos. "
                    f"{data.get('total_rounds')} rondas | "
                    f"acc final={summary.get('final_metrics', {}).get('accuracy')} | "
                    f"mejora acc=+{summary.get('accuracy_delta')}"
                )
                logger.info(f"✅ [RESULTADOS] {detail}")

            # ── Caso C: artefacto desconocido — guardar como modelo por defecto ─
            else:
                with open(MODEL_FILE, "w") as f:
                    json.dump(data, f, indent=2)
                detail = f"Artefacto FL recibido (tipo: {artifact_type}). Guardado como modelo."
                logger.info(f"✅ [GENÉRICO] {detail}")

            return Response(
                content=build_ids_response(True, detail),
                media_type="application/json",
                status_code=200
            )

        except Exception as e:
            logger.error(f"Error procesando artefacto FL: {e}", exc_info=True)
            return Response(
                content=build_ids_response(False, str(e)),
                media_type="application/json",
                status_code=500
            )

    # ── Mensaje IDS genérico ──────────────────────────────────────────────────
    detail = f"Mensaje IDS recibido. Tipo: {msg_type}. Payload: {len(payload_bytes)} bytes."
    logger.info(f"Mensaje no reconocido como modelo FL — respondiendo genéricamente.")
    return Response(
        content=build_ids_response(True, detail),
        media_type="application/json",
        status_code=200
    )


# ── Endpoints modelo ──────────────────────────────────────────────────────────

@app.get("/fl/model", tags=["Federated Learning"])
def get_model():
    """Devuelve el modelo global FL recibido del Provider vía IDS (sin pesos)."""
    if not os.path.exists(MODEL_FILE):
        return JSONResponse(
            status_code=404,
            content={
                "error" : "Modelo global no recibido todavía.",
                "hint"  : "El Provider lo envía automáticamente al terminar el FL.",
                "manual": "POST http://localhost:8600/fl/send-model para forzarlo."
            }
        )
    with open(MODEL_FILE) as f:
        data = json.load(f)
    return {
        "status"           : "received",
        "round"            : data.get("round"),
        "global_metrics"   : data.get("global_metrics"),
        "received_at"      : data.get("received_at"),
        "provider_uri"     : data.get("provider_uri"),
        "ids_message_type" : data.get("ids_message_type"),
        "weights_available": data.get("weights_b64") is not None,
    }


@app.get("/fl/model/full", tags=["Federated Learning"])
def get_model_full():
    """Devuelve el modelo completo incluyendo pesos en base64."""
    if not os.path.exists(MODEL_FILE):
        return JSONResponse(status_code=404, content={"error": "Modelo no recibido todavía."})
    with open(MODEL_FILE) as f:
        return json.load(f)


@app.get("/fl/results", tags=["Federated Learning"])
def get_results():
    """
    Devuelve el historial completo de resultados FL por ronda
    recibido del Provider vía IDS.
    """
    if not os.path.exists(RESULTS_FILE):
        return JSONResponse(
            status_code=404,
            content={
                "error" : "Resultados FL no recibidos todavía.",
                "hint"  : "El Provider los envía automáticamente al terminar el FL.",
                "manual": "POST http://localhost:8600/fl/send-model para forzarlo."
            }
        )
    with open(RESULTS_FILE) as f:
        data = json.load(f)
    return {
        "status"       : "received",
        "received_at"  : data.get("received_at"),
        "provider_uri" : data.get("provider_uri"),
        "total_rounds" : data.get("total_rounds"),
        "summary"      : data.get("summary"),
        "history"      : data.get("history"),
    }


@app.get("/fl/results/summary", tags=["Federated Learning"])
def get_results_summary():
    """
    Resumen ejecutivo del FL: métricas primera vs última ronda,
    mejora de accuracy y AUC, workers utilizados.
    """
    if not os.path.exists(RESULTS_FILE):
        return JSONResponse(status_code=404, content={"error": "Resultados no recibidos todavía."})
    with open(RESULTS_FILE) as f:
        data = json.load(f)
    summary = data.get("summary", {})
    return {
        "status"            : "received",
        "received_at"       : data.get("received_at"),
        "rounds_completed"  : summary.get("rounds_completed"),
        "workers_used"      : summary.get("workers_used"),
        "total_samples"     : summary.get("total_samples"),
        "first_round"       : summary.get("first_metrics"),
        "final_round"       : summary.get("final_metrics"),
        "improvement"       : {
            "accuracy_delta": summary.get("accuracy_delta"),
            "auc_delta"     : summary.get("auc_delta"),
        }
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500)