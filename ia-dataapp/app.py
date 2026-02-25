"""
app.py — IA DataApp API  (worker de Federated Learning)
========================================================
Cada instancia (ia-dataapp-1/2/3) expone:

  Endpoints sistema:
    GET  /health
    GET  /status

  Endpoints algoritmo (compatibilidad original):
    POST /upload-algorithm
    POST /execute
    GET  /result

  Endpoints Federated Learning:
    POST /fl/train         ← coordinador llama aquí cada ronda
    POST /fl/set-model     ← coordinador empuja modelo global
    GET  /fl/model         ← pesos globales actuales
    GET  /fl/history       ← historial de métricas por ronda
"""

import os
import importlib.util
import logging
import json
import sys
from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

app = FastAPI(
    title="IA DataApp — FL Worker",
    description="Worker de Federated Learning con soporte IDS connectors",
    version="2.0.0"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Instance-%(name)s] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

DATA_DIR       = "/home/nobody/data"
INPUT_DIR      = os.path.join(DATA_DIR, "input")
OUTPUT_DIR     = os.path.join(DATA_DIR, "output")
# Busca algorithm.py primero en el volumen montado (ia-dataapp/), luego en /app (imagen)
_ALGO_MOUNTED = "/app-src/algorithm.py"   # ia-dataapp/algorithm.py montado como volumen
_ALGO_BAKED   = "/app/algorithm.py"       # copiado en el build de la imagen
ALGORITHM_PATH = _ALGO_MOUNTED if os.path.exists(_ALGO_MOUNTED) else _ALGO_BAKED
INSTANCE_ID    = os.getenv("INSTANCE_ID", "1")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(INPUT_DIR,  exist_ok=True)

LOCAL_MODEL_FILE = os.path.join(OUTPUT_DIR, f"local_model_{INSTANCE_ID}.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_algorithm_module():
    """Carga dinámicamente algorithm.py."""
    if not os.path.exists(ALGORITHM_PATH):
        raise FileNotFoundError(f"algorithm.py no encontrado en {ALGORITHM_PATH}")
    spec   = importlib.util.spec_from_file_location("algorithm", ALGORITHM_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["algorithm"] = module
    spec.loader.exec_module(module)
    return module


def get_csv_path() -> str:
    """
    Selecciona el CSV correspondiente a esta instancia.
    Prioridad:
      1. unsw_nb15_worker_<INSTANCE_ID>.csv  (partición específica)
      2. Cualquier CSV disponible en input/   (fallback)
    """
    specific = os.path.join(INPUT_DIR, f"unsw_nb15_worker_{INSTANCE_ID}.csv")
    if os.path.exists(specific):
        return specific

    csv_files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")])
    if not csv_files:
        raise FileNotFoundError(
            f"No hay CSV en {INPUT_DIR}. "
            "Ejecuta prepare_dataset.py primero."
        )
    # Fallback: intentar usar el CSV según índice de instancia
    idx = min(int(INSTANCE_ID) - 1, len(csv_files) - 1)
    return os.path.join(INPUT_DIR, csv_files[idx])


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
        "algorithm_loaded": os.path.exists(ALGORITHM_PATH),
        "csv_available"   : csv_files,
        "csv_selected"    : csv_selected,
        "fl_model_loaded" : os.path.exists(LOCAL_MODEL_FILE),
        "outputs"         : output_files
    }


# ── Endpoints algoritmo (compatibilidad) ─────────────────────────────────────

@app.post("/upload-algorithm", tags=["Algoritmo"])
async def upload_algorithm(algorithm: UploadFile = File(...)):
    """Recibe algorithm.py del Consumer vía IDS y lo guarda en el volumen montado (ia-dataapp/)."""
    try:
        content_bytes = await algorithm.read()
        # Guardar siempre en el volumen montado para que persista y sea visible en el host
        save_path = _ALGO_MOUNTED
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(content_bytes)
        logger.info(f"algorithm.py guardado en {save_path}: {len(content_bytes)} bytes")
        return {"status": "ok", "instance": INSTANCE_ID, "path": save_path, "size_bytes": len(content_bytes)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/execute", tags=["Algoritmo"])
@app.get("/execute",  tags=["Algoritmo"])
def execute():
    """Ejecuta algorithm.py sobre el CSV local. Compatibilidad con flujo original."""
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
    """
    El coordinador FL llama aquí en cada ronda.
    Entrena el modelo local con los pesos globales y devuelve los pesos actualizados.
    Los datos de entrenamiento NUNCA salen de esta instancia.
    """
    logger.info(f"FL ronda {req.round} iniciada")
    try:
        algo      = load_algorithm_module()
        data_path = get_csv_path()
        result    = algo.run(data_path, global_weights_b64=req.global_weights_b64)

        # Guardar métricas de la ronda (sin pesos — privacidad)
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
    """Recibe y persiste el modelo global actualizado por el coordinador."""
    with open(LOCAL_MODEL_FILE, "w") as f:
        json.dump({"round": req.round, "weights_b64": req.weights_b64}, f)
    logger.info(f"Modelo global ronda {req.round} almacenado")
    return {"status": "ok", "instance": INSTANCE_ID, "round": req.round}


@app.get("/fl/model", tags=["Federated Learning"])
def fl_get_model():
    """Devuelve los pesos del modelo global almacenados en esta instancia."""
    if not os.path.exists(LOCAL_MODEL_FILE):
        raise HTTPException(status_code=404, detail="Sin modelo global aún")
    with open(LOCAL_MODEL_FILE) as f:
        return json.load(f)


@app.get("/fl/history", tags=["Federated Learning"])
def fl_history():
    """Historial de métricas FL de esta instancia por ronda."""
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