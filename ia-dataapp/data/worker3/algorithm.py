"""
algorithm.py — FL Worker MÍNIMO para validación de arquitectura IDS
====================================================================
Dataset: UNSW-NB15 (clasificación binaria: tráfico normal vs ataque)
Modelo:  Red neuronal densa mínima (2 capas) con TensorFlow/Keras

Este archivo es intencionalmente simple: su propósito es verificar que
toda la arquitectura IDS (connectors, ECC, coordinador FL, workers)
funciona correctamente de extremo a extremo antes de añadir complejidad.

Flujo por ronda de FL:
  1. Coordinador → POST /fl/train  { global_weights_b64, round }
  2. Worker carga CSV partición local → entrena 3 épocas → devuelve pesos
  3. Coordinador aplica FedAvg → modelo global actualizado
  4. Repetir

Referencia arquitectura:
  Luzón et al. (2024) - "A Tutorial on Federated Learning from Theory
  to Practice" - IEEE/CAA J. Autom. Sinica, vol.11, no.4, pp.824-850.
  → Horizontal FL, client-server, FedAvg, tabular non-IID data (Fig.3, Sec.III-B)
"""

import os
import json
import base64
import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # silencia logs verbose de TF
import tensorflow as tf
from tensorflow import keras

# ── Hiperparámetros ─────────────────────────────────────────────────────────
# Simples a propósito: esto es una prueba de arquitectura, no de rendimiento
EPOCHS        = 3
BATCH_SIZE    = 32
LEARNING_RATE = 0.001
TEST_SPLIT    = 0.2

# Columnas del dataset UNSW-NB15 que usamos (versión preprocesada)
# Fuente: https://research.unsw.edu.au/projects/unsw-nb15-dataset
# Label binario: 0 = tráfico normal, 1 = ataque
LABEL_COL = "label"

# Features numéricas seleccionadas del UNSW-NB15
# (subset de las 49 features originales, las más representativas)
FEATURE_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth",
    "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports"
]


# ── Serialización de pesos ───────────────────────────────────────────────────

def weights_to_b64(weights: list) -> str:
    """Convierte pesos del modelo a string base64 para transmisión HTTP."""
    payload = json.dumps([w.tolist() for w in weights]).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def b64_to_weights(b64_str: str) -> list:
    """Reconstruye pesos desde string base64."""
    payload = base64.b64decode(b64_str.encode("utf-8"))
    return [np.array(w, dtype=np.float32) for w in json.loads(payload.decode("utf-8"))]


# ── Carga y preprocesado del dataset ────────────────────────────────────────

def load_unsw_nb15(data_path: str):
    """
    Carga el CSV del UNSW-NB15 preprocesado y devuelve X_train, y_train, X_val, y_val.

    El CSV puede ser cualquiera de los 4 archivos originales del dataset
    o el archivo combinado (UNSW_NB15_training-set.csv).

    Acepta también CSVs ya filtrados a las columnas relevantes.
    Si falta alguna columna de FEATURE_COLS, se usa lo que haya disponible.
    """
    df = pd.read_csv(data_path, low_memory=False)

    # Normalizar nombre de columna label (el dataset usa 'label' o 'Label')
    df.columns = [c.lower().strip() for c in df.columns]

    if LABEL_COL not in df.columns:
        # Intentar con 'attack_cat' (columna alternativa del UNSW-NB15)
        if "attack_cat" in df.columns:
            df[LABEL_COL] = (df["attack_cat"].str.strip() != "Normal").astype(int)
        else:
            # Última columna numérica como fallback
            num_cols = df.select_dtypes(include="number").columns.tolist()
            df[LABEL_COL] = df[num_cols[-1]].astype(int)

    # Seleccionar features disponibles (intersección con FEATURE_COLS)
    available = [c for c in FEATURE_COLS if c in df.columns]
    if not available:
        # Fallback: todas las columnas numéricas excepto label
        available = [c for c in df.select_dtypes(include="number").columns if c != LABEL_COL]

    df_clean = df[available + [LABEL_COL]].fillna(0)

    # Eliminar infinitos
    df_clean = df_clean.replace([np.inf, -np.inf], 0)

    X = df_clean[available].values.astype(np.float32)
    y = (df_clean[LABEL_COL].values > 0).astype(np.float32)  # binario estricto

    # Normalización min-max por columna
    x_min = X.min(axis=0)
    x_max = X.max(axis=0)
    denom = np.where((x_max - x_min) == 0, 1.0, x_max - x_min)
    X = (X - x_min) / denom

    # Split train / val
    n_val    = max(1, int(len(X) * TEST_SPLIT))
    indices  = np.random.permutation(len(X))
    val_idx  = indices[:n_val]
    train_idx = indices[n_val:]

    return X[train_idx], y[train_idx], X[val_idx], y[val_idx], available


# ── Modelo mínimo ────────────────────────────────────────────────────────────

def build_model(input_dim: int) -> keras.Model:
    """
    Red neuronal densa mínima para clasificación binaria (normal vs ataque).

    Arquitectura deliberadamente simple para la fase de validación:
      Input → Dense(32, relu) → Dense(16, relu) → Dense(1, sigmoid)

    Ref: Luzón et al. (2024) Sec.VII-A — arquitectura densa para HFL tabular.
    """
    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        keras.layers.Dense(32, activation="relu"),
        keras.layers.Dense(16, activation="relu"),
        keras.layers.Dense(1,  activation="sigmoid")
    ], name="fl_minimal_classifier")

    model.compile(
        optimizer=keras.optimizers.Adam(LEARNING_RATE),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.AUC(name="auc"),
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall")
        ]
    )
    return model


# ── Función principal ────────────────────────────────────────────────────────

def run(data_path: str, global_weights_b64: str = None) -> dict:
    """
    Entrena el modelo local una ronda de FL y devuelve pesos + métricas.

    Args:
        data_path          : Ruta al CSV local de esta instancia (partición UNSW-NB15).
        global_weights_b64 : Pesos del modelo global en base64.
                             None en la primera ronda (inicialización aleatoria).
    Returns:
        {
            "weights_b64"  : str,   # pesos locales post-entrenamiento (base64)
            "n_samples"    : int,   # muestras de entrenamiento usadas
            "metrics"      : {      # métricas de validación local
                "loss"      : float,
                "accuracy"  : float,
                "auc"       : float,
                "precision" : float,
                "recall"    : float
            },
            "input_dim"    : int,
            "feature_cols" : list[str],
            "model_name"   : str
        }

    Implementa el paso de entrenamiento local descrito en:
    Luzón et al. (2024) - FL Workflow Step 1 "Local Training" (Fig.2)
    """
    # 1. Cargar y preprocesar datos locales
    X_train, y_train, X_val, y_val, feature_cols = load_unsw_nb15(data_path)
    input_dim = X_train.shape[1]

    # 2. Construir modelo
    model = build_model(input_dim)

    # 3. Inicializar con pesos globales si existen (rondas 2, 3, …)
    #    → Implementa el paso "Local Update" del workflow FL (Fig.2, Step 4)
    if global_weights_b64:
        try:
            global_weights = b64_to_weights(global_weights_b64)
            model.set_weights(global_weights)
        except Exception as e:
            # Si los pesos son incompatibles (cambio de arquitectura), ignorar
            pass

    # 4. Entrenamiento local
    #    Los datos NUNCA salen de esta instancia — privacy-preserving by design
    model.fit(
        X_train, y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=0,
        validation_data=(X_val, y_val)
    )

    # 5. Evaluación local
    eval_res = model.evaluate(X_val, y_val, verbose=0)
    # eval_res = [loss, accuracy, auc, precision, recall]
    metrics = {
        "loss"     : round(float(eval_res[0]), 6),
        "accuracy" : round(float(eval_res[1]), 6),
        "auc"      : round(float(eval_res[2]), 6),
        "precision": round(float(eval_res[3]), 6),
        "recall"   : round(float(eval_res[4]), 6)
    }

    # 6. Serializar pesos locales para enviar al coordinador
    #    Solo los pesos viajan, NUNCA los datos de entrenamiento
    local_weights_b64 = weights_to_b64(model.get_weights())

    return {
        "weights_b64" : local_weights_b64,
        "n_samples"   : int(len(X_train)),
        "metrics"     : metrics,
        "input_dim"   : int(input_dim),
        "feature_cols": list(feature_cols),
        "model_name"  : model.name
    }