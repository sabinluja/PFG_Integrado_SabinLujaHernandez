# =============================================================================
# Dockerfile.algorithm — Imagen Docker del Algoritmo FL
# =============================================================================
# Esta imagen se construye dinámicamente por el Coordinator y se pushea al
# registry privado (fl-registry:5000). Los workers la descargan via IDS
# ArtifactRequestMessage y extraen algorithm.py + fl_config.json.
#
# Contiene TODAS las dependencias necesarias para ejecutar el entrenamiento:
#   - TensorFlow, NumPy, Pandas (mismas versiones que el DataApp)
#   - algorithm.py (el algoritmo FL)
#   - fl_config.json (hiperparámetros)
#
# NO contiene el DataApp (app.py) ni la lógica IDS.
# =============================================================================

FROM python:3.10-slim

ENV TF_CPP_MIN_LOG_LEVEL=3
ENV PYTHONDONTWRITEBYTECODE=1

# Dependencias del algoritmo — mismas versiones que requirements.txt del DataApp
COPY requirements_algo.txt /algo/requirements_algo.txt
RUN pip install --no-cache-dir -r /algo/requirements_algo.txt

# Algoritmo FL + configuración
COPY algorithm.py   /algo/algorithm.py
COPY fl_config.json /algo/fl_config.json

# Metadata IDS — permite identificar la imagen como artefacto FL
LABEL ids.artifact.type="fl_algorithm"
LABEL ids.artifact.version="1.0"
LABEL ids.description="FL algorithm + config + dependencies for Federated Learning training"

# Directorio de trabajo
WORKDIR /algo
