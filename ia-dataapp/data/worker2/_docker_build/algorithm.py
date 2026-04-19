"""
algorithm.py — FL Worker para validación de arquitectura IDS
====================================================================
Dataset: UNSW-NB15 (clasificación binaria: tráfico normal vs ataque)
Modelo:  Red neuronal densa mínima (2 capas) con TensorFlow/Keras

Los hiperparámetros (epochs, batch_size, learning_rate, test_split)
se leen de fl_config.json enviado desde Postman en el paso 5.
Si no existe, se usan los valores por defecto definidos en load_config().

Flujo por ronda de FL:
  1. Coordinador → envía pesos globales al worker
  2. Worker carga CSV partición local → entrena N épocas → devuelve pesos
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

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
from tensorflow import keras

# Columnas del dataset UNSW-NB15 que usamos (versión preprocesada)
LABEL_COL = "label"

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

# Ruta por defecto del fichero de configuración
CONFIG_PATH = "/home/nobody/data/fl_config.json"


# ── Configuración ────────────────────────────────────────────────────────────

def load_config(config_path: str = CONFIG_PATH) -> dict:
    """
    Carga fl_config.json si existe y devuelve los parámetros de entrenamiento.
    Si no existe, usa los valores por defecto.

    Parámetros soportados en fl_config.json:
        rounds        (int)   : número de rondas FL — leído por app.py
        round_timeout (int)   : segundos de espera por ronda — leído por app.py
        min_workers   (int)   : mínimo de workers para FedAvg — leído por app.py
        epochs        (int)   : épocas de entrenamiento local
        batch_size    (int)   : tamaño del batch
        learning_rate (float) : tasa de aprendizaje del optimizador Adam
        test_split    (float) : fracción de datos para validación local
    """
    defaults = {
        "rounds"       : 5,
        "round_timeout": 180,
        "min_workers"  : 2,
        "epochs"       : 3,
        "batch_size"   : 32,
        "learning_rate": 0.001,
        "test_split"   : 0.2,
    }
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            defaults.update(cfg)
        except Exception:
            pass
    return defaults


# ── Serialización de pesos ───────────────────────────────────────────────────

def weights_to_b64(weights: list) -> str:
    payload = json.dumps([w.tolist() for w in weights]).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def b64_to_weights(b64_str: str) -> list:
    payload = base64.b64decode(b64_str.encode("utf-8"))
    return [np.array(w, dtype=np.float32) for w in json.loads(payload.decode("utf-8"))]


# ── Carga y preprocesado del dataset ────────────────────────────────────────

def load_unsw_nb15(data_path: str, test_split: float = 0.2):
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]

    if LABEL_COL not in df.columns:
        if "attack_cat" in df.columns:
            df[LABEL_COL] = (df["attack_cat"].str.strip() != "Normal").astype(int)
        else:
            num_cols = df.select_dtypes(include="number").columns.tolist()
            df[LABEL_COL] = df[num_cols[-1]].astype(int)

    available = [c for c in FEATURE_COLS if c in df.columns]
    if not available:
        available = [c for c in df.select_dtypes(include="number").columns if c != LABEL_COL]

    df_clean = df[available + [LABEL_COL]].fillna(0)
    df_clean = df_clean.replace([np.inf, -np.inf], 0)

    X = df_clean[available].values.astype(np.float32)
    y = (df_clean[LABEL_COL].values > 0).astype(np.float32)

    x_min = X.min(axis=0)
    x_max = X.max(axis=0)
    denom = np.where((x_max - x_min) == 0, 1.0, x_max - x_min)
    X = (X - x_min) / denom

    n_val     = max(1, int(len(X) * test_split))
    indices   = np.random.permutation(len(X))
    val_idx   = indices[:n_val]
    train_idx = indices[n_val:]

    return X[train_idx], y[train_idx], X[val_idx], y[val_idx], available


# ── Modelo ────────────────────────────────────────────────────────────────────

def build_model(input_dim: int, learning_rate: float = 0.001) -> keras.Model:
    """
    Red neuronal densa mínima para clasificación binaria (normal vs ataque).
    Arquitectura: Input → Dense(32, relu) → Dense(16, relu) → Dense(1, sigmoid)
    Ref: Luzón et al. (2024) Sec.VII-A
    """
    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        keras.layers.Dense(32, activation="relu"),
        keras.layers.Dense(16, activation="relu"),
        keras.layers.Dense(1,  activation="sigmoid")
    ], name="fl_minimal_classifier")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate),
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

def run(data_path: str, global_weights_b64: str = None,
        config_path: str = CONFIG_PATH) -> dict:
    """
    Entrena el modelo local una ronda de FL y devuelve pesos + métricas.

    Lee los hiperparámetros de fl_config.json (config_path).
    Si no existe, usa los valores por defecto de load_config().

    Args:
        data_path          : Ruta al CSV local (partición UNSW-NB15).
        global_weights_b64 : Pesos globales en base64. None en ronda 1.
        config_path        : Ruta a fl_config.json.

    Returns:
        {
            "weights_b64"  : str,
            "n_samples"    : int,
            "metrics"      : { loss, accuracy, auc, precision, recall },
            "input_dim"    : int,
            "feature_cols" : list[str],
            "model_name"   : str
        }
    """
    cfg = load_config(config_path)
    epochs        = int(cfg["epochs"])
    batch_size    = int(cfg["batch_size"])
    learning_rate = float(cfg["learning_rate"])
    test_split    = float(cfg["test_split"])

    X_train, y_train, X_val, y_val, feature_cols = load_unsw_nb15(data_path, test_split)
    input_dim = X_train.shape[1]

    model = build_model(input_dim, learning_rate)

    if global_weights_b64:
        try:
            model.set_weights(b64_to_weights(global_weights_b64))
        except Exception:
            pass

    model.fit(
        X_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        verbose=0,
        validation_data=(X_val, y_val)
    )

    eval_res = model.evaluate(X_val, y_val, verbose=0)
    metrics = {
        "loss"     : round(float(eval_res[0]), 6),
        "accuracy" : round(float(eval_res[1]), 6),
        "auc"      : round(float(eval_res[2]), 6),
        "precision": round(float(eval_res[3]), 6),
        "recall"   : round(float(eval_res[4]), 6)
    }

    return {
        "weights_b64" : weights_to_b64(model.get_weights()),
        "n_samples"   : int(len(X_train)),
        "metrics"     : metrics,
        "input_dim"   : int(input_dim),
        "feature_cols": list(feature_cols),
        "model_name"  : model.name
    }