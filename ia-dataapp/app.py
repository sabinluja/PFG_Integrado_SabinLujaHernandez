import os
import importlib.util
import logging
import json
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(
    title="IA DataApp API",
    description="API para recibir y ejecutar algoritmos del Consumer sobre datos del Provider",
    version="1.0.0"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = "/home/nobody/data"
INPUT_DIR = os.path.join(DATA_DIR, "input")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")
ALGORITHM_PATH = os.path.join(DATA_DIR, "algorithm.py")
INSTANCE_ID = os.getenv("INSTANCE_ID", "1")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)


def load_and_run_algorithm(data_path):
    """Carga dinámicamente el algorithm.py y lo ejecuta."""
    if not os.path.exists(ALGORITHM_PATH):
        raise FileNotFoundError(f"algorithm.py no encontrado en {ALGORITHM_PATH}")

    spec = importlib.util.spec_from_file_location("algorithm", ALGORITHM_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "run"):
        raise AttributeError("algorithm.py debe tener una función run(data_path)")

    return module.run(data_path)


@app.get("/health", summary="Health check", tags=["Sistema"])
def health():
    return {"status": "ok", "instance": INSTANCE_ID}


@app.get("/status", summary="Estado de la instancia", tags=["Sistema"])
def status():
    """Muestra el estado actual: algoritmo cargado, CSV disponible, outputs generados."""
    algorithm_exists = os.path.exists(ALGORITHM_PATH)
    csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    output_files = os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else []

    return {
        "instance": INSTANCE_ID,
        "algorithm_loaded": algorithm_exists,
        "csv_available": csv_files,
        "outputs": output_files
    }


@app.post("/upload-algorithm", summary="Recibe el algorithm.py del Consumer", tags=["Algoritmo"])
async def upload_algorithm(algorithm: UploadFile = File(...)):
    """
    Recibe el algorithm.py enviado por el Consumer vía IDS.
    Al compartir volumen, las 3 instancias lo verán automáticamente.
    """
    try:
        content = await algorithm.read()
        with open(ALGORITHM_PATH, "wb") as f:
            f.write(content)

        logger.info(f"[Instance {INSTANCE_ID}] algorithm.py recibido: {len(content)} bytes")

        return {
            "status": "ok",
            "message": "algorithm.py guardado correctamente",
            "instance": INSTANCE_ID,
            "path": ALGORITHM_PATH,
            "size_bytes": len(content)
        }

    except Exception as e:
        logger.error(f"[Instance {INSTANCE_ID}] Error al recibir algorithm.py: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/execute", summary="Ejecuta el algoritmo sobre el CSV", tags=["Algoritmo"])
@app.get("/execute", summary="Ejecuta el algoritmo sobre el CSV", tags=["Algoritmo"])
def execute():
    """
    Ejecuta el algorithm.py sobre el CSV del Provider.
    El resultado se guarda en /home/nobody/data/output/result_instance_X.json
    """
    try:
        csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
        if not csv_files:
            raise HTTPException(status_code=404, detail="No se encontró ningún CSV en input/")
        data_path = os.path.join(INPUT_DIR, csv_files[0])
        
        logger.info(f"[Instance {INSTANCE_ID}] Ejecutando algoritmo sobre {data_path}")

        result = load_and_run_algorithm(data_path)

        output_file = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        logger.info(f"[Instance {INSTANCE_ID}] Resultado guardado en {output_file}")

        return {
            "status": "ok",
            "instance": INSTANCE_ID,
            "data_used": data_path,
            "result": result,
            "output_file": output_file
        }

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"{str(e)} - Primero envía el algorithm.py via /upload-algorithm")
    except Exception as e:
        logger.error(f"[Instance {INSTANCE_ID}] Error en ejecución: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/result", summary="Devuelve el último resultado", tags=["Algoritmo"])
def get_result():
    """Devuelve el último resultado generado por esta instancia."""
    output_file = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
    if not os.path.exists(output_file):
        raise HTTPException(status_code=404, detail="No hay resultado disponible aún")

    with open(output_file, "r") as f:
        result = json.load(f)

    return {
        "instance": INSTANCE_ID,
        "result": result
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8500)