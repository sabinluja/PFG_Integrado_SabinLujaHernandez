import os
import importlib.util
import logging
import json
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = "/home/nobody/data"
ALGORITHM_PATH = os.path.join(DATA_DIR, "algorithm.py")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")
INSTANCE_ID = os.getenv("INSTANCE_ID", "1")

os.makedirs(OUTPUT_DIR, exist_ok=True)


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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "instance": INSTANCE_ID})


@app.route("/upload-algorithm", methods=["POST"])
def upload_algorithm():
    """
    Recibe el algorithm.py enviado por el Consumer vía IDS.
    El ECC Provider reenvía el payload aquí.
    """
    try:
        # El payload puede venir como fichero multipart o como raw bytes
        if "algorithm" in request.files:
            file = request.files["algorithm"]
            file.save(ALGORITHM_PATH)
            logger.info(f"[Instance {INSTANCE_ID}] algorithm.py recibido via multipart")
        elif request.data:
            with open(ALGORITHM_PATH, "wb") as f:
                f.write(request.data)
            logger.info(f"[Instance {INSTANCE_ID}] algorithm.py recibido via raw bytes")
        else:
            return jsonify({"error": "No se recibió ningún fichero"}), 400

        return jsonify({
            "status": "ok",
            "message": "algorithm.py guardado correctamente",
            "instance": INSTANCE_ID,
            "path": ALGORITHM_PATH
        }), 200

    except Exception as e:
        logger.error(f"[Instance {INSTANCE_ID}] Error al recibir algorithm.py: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/execute", methods=["POST", "GET"])
def execute():
    """
    Ejecuta el algorithm.py sobre el CSV del Provider.
    El resultado se guarda en /home/nobody/data/output/
    """
    try:
        # Buscar el CSV en el directorio de datos
        csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
        if not csv_files:
            return jsonify({"error": "No se encontró ningún CSV en el directorio de datos"}), 404

        data_path = os.path.join(DATA_DIR, csv_files[0])
        logger.info(f"[Instance {INSTANCE_ID}] Ejecutando algoritmo sobre {data_path}")

        result = load_and_run_algorithm(data_path)

        # Guardar resultado en output/
        output_file = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        logger.info(f"[Instance {INSTANCE_ID}] Resultado guardado en {output_file}")

        return jsonify({
            "status": "ok",
            "instance": INSTANCE_ID,
            "data_used": data_path,
            "result": result,
            "output_file": output_file
        }), 200

    except FileNotFoundError as e:
        return jsonify({"error": str(e), "hint": "Primero envía el algorithm.py via /upload-algorithm"}), 404
    except Exception as e:
        logger.error(f"[Instance {INSTANCE_ID}] Error en ejecución: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/result", methods=["GET"])
def get_result():
    """Devuelve el último resultado generado por esta instancia."""
    output_file = os.path.join(OUTPUT_DIR, f"result_instance_{INSTANCE_ID}.json")
    if not os.path.exists(output_file):
        return jsonify({"error": "No hay resultado disponible aún"}), 404

    with open(output_file, "r") as f:
        result = json.load(f)

    return jsonify({
        "instance": INSTANCE_ID,
        "result": result
    }), 200


@app.route("/status", methods=["GET"])
def status():
    """Muestra el estado actual de la instancia."""
    algorithm_exists = os.path.exists(ALGORITHM_PATH)
    csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
    output_files = os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else []

    return jsonify({
        "instance": INSTANCE_ID,
        "algorithm_loaded": algorithm_exists,
        "csv_available": csv_files,
        "outputs": output_files
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8500)