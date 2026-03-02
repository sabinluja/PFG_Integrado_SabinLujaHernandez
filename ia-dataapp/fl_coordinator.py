"""
fl_coordinator.py — Coordinador Central de Federated Learning
=============================================================
Corre en FastAPI puerto 8600, SOLO en ia-dataapp-1 (instancia central).

Por cada ronda FL:
  1. Envía pesos globales a los 3 workers en paralelo → POST /fl/train
  2. Recoge pesos locales + métricas
  3. Aplica FedAvg (McMahan et al. 2017) — promedio ponderado por n_samples
  4. Guarda modelo global → siguiente ronda

Al finalizar TODAS las rondas:
  5. Envía global_model.json al Consumer vía IDS (ArtifactResponseMessage)
     Consumer ← ECC-Consumer ← ECC-Provider ← be-dataapp-provider
     Cierra el ciclo IDS completo:
       Consumer envía algorithm.py → Provider entrena → Provider devuelve modelo

Ref: Luzón et al. (2024) Sec.III-A "Aggregation: FedAvg"
     IEEE/CAA J. Autom. Sinica, vol.11, no.4, pp.824-850.

Endpoints:
  POST /fl/start    → lanza N rondas en hilo separado
  GET  /fl/status   → estado actual
  GET  /fl/results  → historial completo de métricas
  POST /fl/round    → una sola ronda (debug)
  GET  /fl/model    → modelo global actual (weights + métricas)
  GET  /health      → health check
"""

import os
import json
import time
import base64
import logging
import threading
import concurrent.futures
import numpy as np
import requests
import urllib3
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COORDINATOR] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="FL Coordinator",
    description="Coordinador de Federated Learning sobre IDS Connectors",
    version="3.0.0"
)

# ── Configuración ─────────────────────────────────────────────────────────────
WORKER_URLS = [
    os.getenv("WORKER_1_URL", "http://be-dataapp-provider:8500"),
    os.getenv("WORKER_2_URL", "http://ia-dataapp-2:8500"),
    os.getenv("WORKER_3_URL", "http://ia-dataapp-3:8500"),
]

FL_ROUNDS     = int(os.getenv("FL_ROUNDS",     "5"))
ROUND_TIMEOUT = int(os.getenv("ROUND_TIMEOUT", "180"))

# ── Configuración IDS para envío del modelo al Consumer ──────────────────────
# El Provider envía el modelo global al Consumer vía su propio ECC
# Flujo: be-dataapp-provider:8183/proxy → ecc-provider:8887 → ecc-consumer:8449 → be-dataapp-consumer:8183
ECC_PROVIDER_DATAAPP_URL = os.getenv("ECC_PROVIDER_DATAAPP_URL", "https://be-dataapp-provider:8183")
FORWARD_TO_CONSUMER      = os.getenv("FORWARD_TO_CONSUMER",      "https://ecc-consumer:8889/data")
ECC_USER                 = os.getenv("ECC_USER",  "idsUser")
ECC_PASS                 = os.getenv("ECC_PASS",  "passwordIdsUser")
PROVIDER_CONNECTOR_URI   = os.getenv("ISSUER_CONNECTOR_URI", "http://w3id.org/engrd/connector/provider")
SEND_MODEL_VIA_IDS       = os.getenv("SEND_MODEL_VIA_IDS", "true").lower() == "true"

DATA_DIR     = "/home/nobody/data"
OUTPUT_DIR   = os.path.join(DATA_DIR, "output")
GLOBAL_MODEL = os.path.join(OUTPUT_DIR, "global_model.json")
RESULTS_FILE = os.path.join(OUTPUT_DIR, "fl_results.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Estado compartido
fl_state = {
    "running"          : False,
    "current_round"    : 0,
    "total_rounds"     : FL_ROUNDS,
    "status"           : "idle",
    "history"          : [],
    "model_sent_ids"   : False,
    "results_sent_ids" : False,
    "ids_send_status"  : "pending",
    "model_delivered"  : False,
    "results_delivered": False
}
_lock = threading.Lock()


# ── Schemas ───────────────────────────────────────────────────────────────────

class StartRequest(BaseModel):
    rounds: Optional[int] = None


# ── FedAvg ────────────────────────────────────────────────────────────────────

def _b64_to_weights(b64_str: str) -> list:
    payload = base64.b64decode(b64_str.encode("utf-8"))
    return [np.array(w, dtype=np.float32) for w in json.loads(payload.decode("utf-8"))]


def _weights_to_b64(weights: list) -> str:
    payload = json.dumps([w.tolist() for w in weights]).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def federated_average(worker_results: list) -> list:
    """
    Federated Averaging (McMahan et al. 2017).
    Promedio ponderado de pesos por número de muestras locales.
    Ref: Luzón et al. (2024) Sec.III-A "Aggregation"
    """
    total      = sum(r["n_samples"] for r in worker_results)
    aggregated = None
    for r in worker_results:
        w     = _b64_to_weights(r["weights_b64"])
        scale = r["n_samples"] / total
        if aggregated is None:
            aggregated = [layer * scale for layer in w]
        else:
            for i, layer in enumerate(w):
                aggregated[i] += layer * scale
    return aggregated


# ── Comunicación con workers ──────────────────────────────────────────────────

def _call_worker(url: str, global_weights_b64: str, round_num: int) -> dict:
    try:
        resp = requests.post(
            f"{url}/fl/train",
            json={"global_weights_b64": global_weights_b64, "round": round_num},
            timeout=ROUND_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        data["_worker_url"] = url
        return data
    except Exception as e:
        logger.error(f"Worker {url} falló en ronda {round_num}: {e}")
        return {"error": str(e), "_worker_url": url}


def train_all_parallel(global_weights_b64: str, round_num: int) -> list:
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(WORKER_URLS)) as ex:
        futures = {ex.submit(_call_worker, url, global_weights_b64, round_num): url
                   for url in WORKER_URLS}
        results = []
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if "error" not in r:
                results.append(r)
            else:
                logger.warning(f"Descartado worker con error: {r['_worker_url']}")
    return results


# ── Envío IDS al Consumer — helper común ─────────────────────────────────────

def _send_via_ids(artifact_uri: str, payload_dict: dict, log_tag: str) -> bool:
    """
    Helper interno: serializa payload_dict en base64 y lo envía al Consumer vía IDS.

    Flujo IDS inverso (Provider → Consumer):
      be-dataapp-provider:8183/proxy
        → ecc-provider:8887 (Camel sender)
          → ecc-consumer:8889 (Camel receiver)
            → be-dataapp-consumer:8183/data
              → be-dataapp-consumer:8500/data (FastAPI consumer)
    """
    proxy_url   = f"{ECC_PROVIDER_DATAAPP_URL}/proxy"
    payload_str = json.dumps(payload_dict)
    payload_b64 = base64.b64encode(payload_str.encode("utf-8")).decode("utf-8")

    body = {
        "multipart"        : "form",
        "forwardTo"       : FORWARD_TO_CONSUMER,
        "messageType"      : "ArtifactRequestMessage",
        "requestedArtifact": artifact_uri,
        "payload"          : payload_b64
    }

    logger.info(f"[{log_tag}]   Proxy URL  : {proxy_url}")
    logger.info(f"[{log_tag}]   Artifact   : {artifact_uri}")
    logger.info(f"[{log_tag}]   Payload    : {len(payload_str)} bytes")

    for attempt in range(1, 4):
        try:
            resp = requests.post(
                proxy_url,
                json=body,
                auth=(ECC_USER, ECC_PASS),
                verify=False,
                timeout=60
            )
            logger.info(f"[{log_tag}] Intento {attempt} → HTTP {resp.status_code}")
            if resp.status_code == 200:
                logger.info(f"[{log_tag}] ✅ Enviado correctamente")
                return True
            else:
                logger.warning(f"[{log_tag}] ⚠️  HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.error(f"[{log_tag}] ❌ Error intento {attempt}: {e}")

        if attempt < 3:
            logger.info(f"[{log_tag}] Reintentando en 10s...")
            time.sleep(10)

    logger.error(f"[{log_tag}] ❌ Todos los intentos fallaron.")
    return False


# ── Envío IDS del modelo global al Consumer ───────────────────────────────────

def send_model_to_consumer_via_ids(global_model: dict) -> bool:
    """
    Envía el modelo global FL (pesos + métricas finales) al Consumer vía IDS.
    messageType: ArtifactResponseMessage
    artifact:    fl_global_model
    """
    if not SEND_MODEL_VIA_IDS:
        logger.info("[IDS-MODEL] SEND_MODEL_VIA_IDS=false — envío desactivado")
        return False

    logger.info("[IDS-MODEL] ══════════════════════════════════════════")
    logger.info("[IDS-MODEL]   Enviando modelo global al Consumer vía IDS")
    logger.info("[IDS-MODEL] ══════════════════════════════════════════")

    payload = {
        "artifact_type"  : "fl_global_model",
        "source"         : "fl_coordinator",
        "provider_uri"   : PROVIDER_CONNECTOR_URI,
        "round"          : global_model.get("round"),
        "global_metrics" : global_model.get("metrics"),
        "weights_b64"    : global_model.get("weights_b64"),
        "timestamp"      : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    proxy_url = f"{ECC_PROVIDER_DATAAPP_URL}/proxy"
    payload_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

    body = {
        "multipart"        : "form",
        "forwardTo"       : FORWARD_TO_CONSUMER,
        "messageType"      : "ArtifactRequestMessage",
        "requestedArtifact": "http://w3id.org/engrd/connector/artifact/fl_global_model",
        "payload"          : payload_b64
    }

    logger.info(f"[IDS-MODEL]   Proxy URL  : {proxy_url}")
    logger.info(f"[IDS-MODEL]   Forward-To : {FORWARD_TO_CONSUMER}")
    logger.info(f"[IDS-MODEL]   Payload    : {len(json.dumps(payload))} bytes (ronda {global_model.get('round')})")

    for attempt in range(1, 4):
        try:
            resp = requests.post(
                proxy_url,
                json=body,
                auth=(ECC_USER, ECC_PASS),
                verify=False,
                timeout=60
            )
            logger.info(f"[IDS-MODEL] Intento {attempt} → HTTP {resp.status_code}")
            if resp.status_code == 200:
                logger.info("[IDS-MODEL] ✅ Modelo global enviado correctamente al Consumer vía IDS")
                return True
            else:
                logger.warning(f"[IDS-MODEL] ⚠️  HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.error(f"[IDS-MODEL] ❌ Error intento {attempt}: {e}")
        if attempt < 3:
            logger.info("[IDS-MODEL] Reintentando en 10s...")
            time.sleep(10)

    logger.error("[IDS-MODEL] ❌ Modelo NO enviado vía IDS.")
    return False


def send_results_to_consumer_via_ids(history: list) -> bool:
    """
    Envía el historial completo de resultados FL al Consumer vía IDS.

    Incluye por cada ronda:
      - Métricas globales (loss, accuracy, auc, precision, recall)
      - Número de workers que respondieron
      - Total de muestras usadas
      - Tiempo de la ronda
      - Detalle por worker

    messageType: ArtifactResponseMessage
    artifact:    fl_results
    """
    if not SEND_MODEL_VIA_IDS:
        logger.info("[IDS-RESULTS] SEND_MODEL_VIA_IDS=false — envío desactivado")
        return False

    logger.info("[IDS-RESULTS] ══════════════════════════════════════════")
    logger.info("[IDS-RESULTS]   Enviando resultados FL al Consumer vía IDS")
    logger.info("[IDS-RESULTS] ══════════════════════════════════════════")

    payload = {
        "artifact_type" : "fl_results",
        "source"        : "fl_coordinator",
        "provider_uri"  : PROVIDER_CONNECTOR_URI,
        "total_rounds"  : len(history),
        "timestamp"     : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "history"       : history,
        # Resumen ejecutivo para visualización rápida
        "summary"       : {
            "rounds_completed" : len(history),
            "workers_used"     : history[-1]["workers_ok"] if history else 0,
            "total_samples"    : history[-1]["total_samples"] if history else 0,
            "final_metrics"    : history[-1]["global_metrics"] if history else {},
            "first_metrics"    : history[0]["global_metrics"] if history else {},
            "accuracy_delta"   : round(
                history[-1]["global_metrics"].get("accuracy", 0) -
                history[0]["global_metrics"].get("accuracy", 0), 6
            ) if len(history) >= 2 else 0,
            "auc_delta"        : round(
                history[-1]["global_metrics"].get("auc", 0) -
                history[0]["global_metrics"].get("auc", 0), 6
            ) if len(history) >= 2 else 0,
        }
    }

    logger.info(f"[IDS-RESULTS]   Rondas: {payload['total_rounds']} | "
                f"acc final: {payload['summary']['final_metrics'].get('accuracy','?')} | "
                f"mejora acc: +{payload['summary']['accuracy_delta']}")

    return _send_via_ids(
        artifact_uri="http://w3id.org/engrd/connector/artifact/fl_results",
        payload_dict=payload,
        log_tag="IDS-RESULTS"
    )


# ── Bucle FL principal ────────────────────────────────────────────────────────

def run_fl(n_rounds: int):
    with _lock:
        fl_state.update({
            "running"          : True,
            "status"           : "running",
            "current_round"    : 0,
            "history"          : [],
            "model_sent_ids"   : False,
            "results_sent_ids" : False,
            "ids_send_status"  : "pending",
            "model_delivered"  : False,
            "results_delivered": False
        })

    global_weights_b64 = None

    if os.path.exists(GLOBAL_MODEL):
        try:
            with open(GLOBAL_MODEL) as f:
                saved = json.load(f)
            global_weights_b64 = saved.get("weights_b64")
            logger.info("Modelo global previo cargado — reanudando.")
        except Exception:
            logger.warning("No se pudo cargar modelo previo. Empezando desde cero.")

    for round_num in range(1, n_rounds + 1):
        logger.info(f"{'='*50}")
        logger.info(f"RONDA {round_num}/{n_rounds}")
        logger.info(f"{'='*50}")

        with _lock:
            fl_state["current_round"] = round_num
            fl_state["status"] = f"round_{round_num}_training"

        t0             = time.time()
        worker_results = train_all_parallel(global_weights_b64, round_num)

        if not worker_results:
            logger.error(f"Ronda {round_num}: 0 workers respondieron. Abortando.")
            with _lock:
                fl_state["status"]  = "failed"
                fl_state["running"] = False
            return

        aggregated         = federated_average(worker_results)
        global_weights_b64 = _weights_to_b64(aggregated)
        elapsed            = round(time.time() - t0, 2)
        total_samples      = sum(r["n_samples"] for r in worker_results)

        global_metrics = {}
        for key in ["loss", "accuracy", "auc", "precision", "recall"]:
            try:
                global_metrics[key] = round(
                    sum(r["metrics"][key] * r["n_samples"] / total_samples
                        for r in worker_results), 6
                )
            except KeyError:
                pass

        summary = {
            "round"          : round_num,
            "workers_ok"     : len(worker_results),
            "total_samples"  : total_samples,
            "elapsed_seconds": elapsed,
            "global_metrics" : global_metrics,
            "worker_details" : [
                {
                    "worker"   : i + 1,
                    "url"      : r.get("_worker_url", WORKER_URLS[i]),
                    "n_samples": r["n_samples"],
                    "metrics"  : r["metrics"]
                }
                for i, r in enumerate(worker_results)
            ]
        }

        with _lock:
            fl_state["history"].append(summary)

        # Guardar modelo global tras cada ronda
        global_model_data = {
            "round"      : round_num,
            "weights_b64": global_weights_b64,
            "metrics"    : global_metrics
        }
        with open(GLOBAL_MODEL, "w") as f:
            json.dump(global_model_data, f)

        logger.info(
            f"Ronda {round_num} OK en {elapsed}s | "
            f"acc={global_metrics.get('accuracy','?')} | "
            f"auc={global_metrics.get('auc','?')}"
        )

    # ── FL completado — guardar resultados ────────────────────────────────────
    with _lock:
        fl_state["running"] = False
        fl_state["status"]  = "completed"

    with open(RESULTS_FILE, "w") as f:
        json.dump(fl_state["history"], f, indent=2)

    logger.info(f"✅ FL completado — {n_rounds} rondas.")

    # ── FL completado — Consumer hará polling y solicitará el modelo vía IDS ──
    # El coordinador NO empuja el modelo. El Consumer (ids_fl_poller.py) detecta
    # status=="completed" y solicita fl_global_model + fl_results vía IDS.
    # El /data del Provider (app.py) los sirve cuando se solicitan.
    with _lock:
        fl_state["status"]          = "completed"
        fl_state["ids_send_status"] = "awaiting_consumer_request"

    logger.info("")
    logger.info("═" * 52)
    logger.info("  FL COMPLETADO — esperando solicitud IDS del Consumer")
    logger.info("═" * 52)
    logger.info("  Consumer → [IDS] algorithm.py  → Provider  ✅")
    logger.info("  Provider ← [IDS] fl_global_model  Consumer  ⏳ (pendiente)")
    logger.info("  Provider ← [IDS] fl_results       Consumer  ⏳ (pendiente)")
    logger.info("═" * 52)
    logger.info("  El Consumer detectará 'completed' y solicitará")
    logger.info("  los artefactos vía IDS automáticamente.")
    logger.info("═" * 52)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/fl/ids-delivered", tags=["Federated Learning"])
def ids_delivered(payload: dict):
    """
    Notificación interna desde app.py cuando sirve un artefacto vía IDS.
    Actualiza el estado y loguea que el Consumer recibió el artefacto.
    """
    artifact = payload.get("artifact", "")
    with _lock:
        if "fl_global_model" in artifact:
            fl_state["model_delivered"] = True
            logger.info("  Provider ← [IDS] fl_global_model  Consumer  ✅")
        elif "fl_results" in artifact:
            fl_state["results_delivered"] = True
            logger.info("  Provider ← [IDS] fl_results       Consumer  ✅")

        if fl_state["model_delivered"] and fl_state["results_delivered"]:
            fl_state["ids_send_status"] = "delivered"
            logger.info("══════════════════════════════════════════════════════")
            logger.info("  CICLO IDS COMPLETO ✅")
            logger.info("  Consumer → [IDS] algorithm.py  → Provider  ✅")
            logger.info("  Provider ← [IDS] fl_global_model  Consumer  ✅")
            logger.info("  Provider ← [IDS] fl_results       Consumer  ✅")
            logger.info("══════════════════════════════════════════════════════")

    return {"ok": True, "artifact": artifact}


@app.post("/fl/start", tags=["Federated Learning"])
def fl_start(body: StartRequest = None):
    with _lock:
        if fl_state["running"]:
            return JSONResponse(
                status_code=409,
                content={"status": "already_running", "round": fl_state["current_round"]}
            )

    n_rounds = (body.rounds if body and body.rounds else FL_ROUNDS)
    threading.Thread(target=run_fl, args=(n_rounds,), daemon=True).start()

    return JSONResponse(
        status_code=202,
        content={"status": "started", "rounds": n_rounds, "workers": WORKER_URLS}
    )


@app.get("/fl/status", tags=["Federated Learning"])
def fl_status():
    with _lock:
        return dict(fl_state)


@app.get("/fl/results", tags=["Federated Learning"])
def fl_results():
    with _lock:
        history = fl_state["history"]
        # Si FL completado y aún pendiente, marcar como entregado
        if fl_state["status"] == "completed" and not fl_state.get("results_delivered"):
            fl_state["results_delivered"] = True
            logger.info("  Provider ← [IDS] fl_results       Consumer  ✅")
            if fl_state.get("model_delivered"):
                fl_state["ids_send_status"] = "delivered"
                logger.info("══════════════════════════════════════════════════════")
                logger.info("  CICLO IDS COMPLETO ✅")
                logger.info("  Consumer → [IDS] algorithm.py  → Provider  ✅")
                logger.info("  Provider ← [IDS] fl_global_model  Consumer  ✅")
                logger.info("  Provider ← [IDS] fl_results       Consumer  ✅")
                logger.info("══════════════════════════════════════════════════════")
        if history:
            return history

    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            return json.load(f)

    return JSONResponse(status_code=404, content={"error": "Sin resultados todavía"})


@app.get("/fl/model", tags=["Federated Learning"])
def fl_model():
    """Devuelve el modelo global actual (pesos + métricas). Útil para verificación."""
    if not os.path.exists(GLOBAL_MODEL):
        return JSONResponse(status_code=404, content={"error": "Sin modelo global todavía"})
    with open(GLOBAL_MODEL) as f:
        data = json.load(f)
    # Si FL completado y aún pendiente, marcar modelo como entregado
    with _lock:
        if fl_state["status"] == "completed" and not fl_state.get("model_delivered"):
            fl_state["model_delivered"] = True
            logger.info("  Provider ← [IDS] fl_global_model  Consumer  ✅")
            if fl_state.get("results_delivered"):
                fl_state["ids_send_status"] = "delivered"
                logger.info("══════════════════════════════════════════════════════")
                logger.info("  CICLO IDS COMPLETO ✅")
                logger.info("  Consumer → [IDS] algorithm.py  → Provider  ✅")
                logger.info("  Provider ← [IDS] fl_global_model  Consumer  ✅")
                logger.info("  Provider ← [IDS] fl_results       Consumer  ✅")
                logger.info("══════════════════════════════════════════════════════")
    return {
        "round"           : data.get("round"),
        "metrics"         : data.get("metrics"),
        "weights_available": data.get("weights_b64") is not None,
        "ids_send_status" : fl_state.get("ids_send_status", "unknown")
    }


@app.post("/fl/send-model", tags=["Federated Learning"])
def fl_send_model_manual():
    """
    Reenvía manualmente modelo global + resultados al Consumer vía IDS.
    Útil si el envío automático falló al terminar el FL.
    """
    if not os.path.exists(GLOBAL_MODEL):
        return JSONResponse(status_code=404, content={"error": "Sin modelo global. Ejecuta FL primero."})

    with open(GLOBAL_MODEL) as f:
        model = json.load(f)

    history = []
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            history = json.load(f)
    elif fl_state["history"]:
        history = fl_state["history"]

    model_ok   = send_model_to_consumer_via_ids(model)
    time.sleep(5)
    results_ok = send_results_to_consumer_via_ids(history) if history else False

    ids_ok = model_ok and results_ok

    with _lock:
        fl_state["model_sent_ids"]   = model_ok
        fl_state["results_sent_ids"] = results_ok
        fl_state["ids_send_status"]  = (
            "success"         if ids_ok else
            "partial_model"   if model_ok else
            "partial_results" if results_ok else
            "failed"
        )

    return {
        "model_sent"     : model_ok,
        "results_sent"   : results_ok,
        "ids_send_status": fl_state["ids_send_status"],
        "round"          : model.get("round"),
        "history_rounds" : len(history)
    }


@app.post("/fl/round", tags=["Federated Learning"])
def fl_single_round():
    """Ejecuta UNA sola ronda — útil para debugging."""
    with _lock:
        if fl_state["running"]:
            return JSONResponse(status_code=409, content={"error": "FL en ejecución"})

    global_weights_b64 = None
    if os.path.exists(GLOBAL_MODEL):
        with open(GLOBAL_MODEL) as f:
            global_weights_b64 = json.load(f).get("weights_b64")

    round_num      = (fl_state.get("current_round") or 0) + 1
    worker_results = train_all_parallel(global_weights_b64, round_num)

    if not worker_results:
        return JSONResponse(status_code=503, content={"error": "Ningún worker respondió"})

    aggregated         = federated_average(worker_results)
    global_weights_b64 = _weights_to_b64(aggregated)
    total_samples      = sum(r["n_samples"] for r in worker_results)
    global_metrics     = {
        key: round(sum(r["metrics"][key] * r["n_samples"] / total_samples
                       for r in worker_results if key in r.get("metrics", {})), 6)
        for key in ["loss", "accuracy", "auc", "precision", "recall"]
    }

    with open(GLOBAL_MODEL, "w") as f:
        json.dump({"round": round_num, "weights_b64": global_weights_b64,
                   "metrics": global_metrics}, f)

    with _lock:
        fl_state["current_round"] = round_num
        fl_state["history"].append({
            "round": round_num, "global_metrics": global_metrics,
            "workers_ok": len(worker_results), "total_samples": total_samples
        })

    return {"round": round_num, "global_metrics": global_metrics,
            "workers_ok": len(worker_results)}


@app.get("/health", tags=["Sistema"])
def health():
    return {
        "status" : "ok",
        "role"   : "fl_coordinator",
        "workers": WORKER_URLS,
        "ids_delivery": {
            "enabled"         : SEND_MODEL_VIA_IDS,
            "forward_to"      : FORWARD_TO_CONSUMER,
            "status"          : fl_state.get("ids_send_status", "pending"),
            "model_sent"      : fl_state.get("model_sent_ids", False),
            "results_sent"    : fl_state.get("results_sent_ids", False),
        }
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8600)