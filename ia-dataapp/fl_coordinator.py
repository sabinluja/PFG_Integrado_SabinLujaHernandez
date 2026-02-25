"""
fl_coordinator.py — Coordinador Central de Federated Learning
=============================================================
Corre en FastAPI puerto 8600, SOLO en ia-dataapp-1 (instancia central).

Por cada ronda FL:
  1. Envía pesos globales a los 3 workers en paralelo → POST /fl/train
  2. Recoge pesos locales + métricas
  3. Aplica FedAvg (McMahan et al. 2017) — promedio ponderado por n_samples
  4. Guarda modelo global → siguiente ronda

Ref: Luzón et al. (2024) Sec.III-A "Aggregation: FedAvg"
     IEEE/CAA J. Autom. Sinica, vol.11, no.4, pp.824-850.

Endpoints:
  POST /fl/start    → lanza N rondas en hilo separado
  GET  /fl/status   → estado actual
  GET  /fl/results  → historial completo de métricas
  POST /fl/round    → una sola ronda (debug)
  GET  /health      → health check
"""

import os
import json
import time
import logging
import threading
import concurrent.futures
import numpy as np
import requests
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COORDINATOR] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="FL Coordinator",
    description="Coordinador de Federated Learning sobre IDS Connectors",
    version="2.0.0"
)

# ── Configuración ─────────────────────────────────────────────────────────────
WORKER_URLS = [
    os.getenv("WORKER_1_URL", "http://be-dataapp-provider:8500"),
    os.getenv("WORKER_2_URL", "http://ia-dataapp-2:8500"),
    os.getenv("WORKER_3_URL", "http://ia-dataapp-3:8500"),
]

FL_ROUNDS     = int(os.getenv("FL_ROUNDS",     "5"))
ROUND_TIMEOUT = int(os.getenv("ROUND_TIMEOUT", "180"))

DATA_DIR     = "/home/nobody/data"
OUTPUT_DIR   = os.path.join(DATA_DIR, "output")
GLOBAL_MODEL = os.path.join(OUTPUT_DIR, "global_model.json")
RESULTS_FILE = os.path.join(OUTPUT_DIR, "fl_results.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Estado compartido
fl_state = {
    "running"      : False,
    "current_round": 0,
    "total_rounds" : FL_ROUNDS,
    "status"       : "idle",
    "history"      : []
}
_lock = threading.Lock()


# ── Schemas ───────────────────────────────────────────────────────────────────

class StartRequest(BaseModel):
    rounds: Optional[int] = None


# ── FedAvg ────────────────────────────────────────────────────────────────────

def _b64_to_weights(b64_str: str) -> list:
    import base64
    payload = base64.b64decode(b64_str.encode("utf-8"))
    return [np.array(w, dtype=np.float32) for w in json.loads(payload.decode("utf-8"))]


def _weights_to_b64(weights: list) -> str:
    import base64
    payload = json.dumps([w.tolist() for w in weights]).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def federated_average(worker_results: list) -> list:
    """
    Federated Averaging (McMahan et al. 2017).
    Promedio ponderado de pesos por número de muestras locales.
    Ref: Luzón et al. (2024) Sec.III-A "Aggregation"
    """
    total = sum(r["n_samples"] for r in worker_results)
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


# ── Bucle FL principal ────────────────────────────────────────────────────────

def run_fl(n_rounds: int):
    with _lock:
        fl_state.update({"running": True, "status": "running",
                         "current_round": 0, "history": []})

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

        t0 = time.time()
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

        with open(GLOBAL_MODEL, "w") as f:
            json.dump({
                "round"      : round_num,
                "weights_b64": global_weights_b64,
                "metrics"    : global_metrics
            }, f)

        logger.info(
            f"Ronda {round_num} OK en {elapsed}s | "
            f"acc={global_metrics.get('accuracy','?')} | "
            f"auc={global_metrics.get('auc','?')}"
        )

    with _lock:
        fl_state["running"] = False
        fl_state["status"]  = "completed"

    with open(RESULTS_FILE, "w") as f:
        json.dump(fl_state["history"], f, indent=2)

    logger.info(f"✅ FL completado — {n_rounds} rondas.")


# ── Endpoints ─────────────────────────────────────────────────────────────────

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
        if fl_state["history"]:
            return fl_state["history"]

    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            return json.load(f)

    return JSONResponse(status_code=404, content={"error": "Sin resultados todavía"})


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
    return {"status": "ok", "role": "fl_coordinator", "workers": WORKER_URLS}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8600)