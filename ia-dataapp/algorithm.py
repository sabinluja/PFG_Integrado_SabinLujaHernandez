"""
algorithm.py -- FL Worker: Clasificacion Multiclase de Intrusiones de Red
=========================================================================
Dataset: UNSW-NB15 (Moustafa & Slay, 2015)
         10 clases: Normal + 9 tipos de ataque (Fuzzers, Analysis, Backdoor,
         DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms)
Modelo:  Deep Neural Network (DNN) con BatchNormalization y Dropout
Agregacion FL: FedAvg -- McMahan et al. (2017)

Preprocesado:
  - Transformacion logaritmica (log1p) en features con alta asimetria
  - Clipping de outliers al percentil 99
  - StandardScaler (media=0, std=1) por particion local (privacidad FL)
  - Compute class_weight para compensar desbalanceo de clases

Metricas:
  - loss, accuracy, AUC (macro), precision (macro), recall (macro)
  - F1-Score (macro y weighted), Matthews Correlation Coefficient (MCC)
  - Confusion Matrix, Per-class F1, Feature Importance

Los hiperparametros (epochs, batch_size, learning_rate, test_split)
se leen de fl_config.json enviado desde Postman en el paso 5.
Si no existe, se usan los valores por defecto definidos en load_config().

Flujo por ronda de FL:
  1. Coordinador -> envia pesos globales al worker
  2. Worker carga CSV particion local -> entrena N epocas -> devuelve pesos
  3. Coordinador aplica FedAvg -> modelo global actualizado
  4. Repetir

Referencias:
  McMahan et al. (2017) - "Communication-Efficient Learning of Deep Networks
  from Decentralized Data" - AISTATS 2017.
  Luzon et al. (2024) - "A Tutorial on Federated Learning from Theory
  to Practice" - IEEE/CAA J. Autom. Sinica, vol.11, no.4, pp.824-850.
  Moustafa, Nour, and Jill Slay (2015) - "UNSW-NB15: a comprehensive data
  set for network intrusion detection systems" - MilCIS 2015, IEEE.
"""

import os
import json
import base64
import logging

import numpy as np
import pandas as pd

# Reproducibilidad
SEED = 42
np.random.seed(SEED)

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
tf.random.set_seed(SEED)
from tensorflow import keras

from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    f1_score, matthews_corrcoef, confusion_matrix,
    classification_report, precision_score, recall_score
)

log = logging.getLogger(__name__)

# ============================================================================
# Constantes del dataset UNSW-NB15
# ============================================================================

LABEL_COL = "label"
ATTACK_CAT_COL = "attack_cat"

# Las 10 categorias del UNSW-NB15 (Moustafa & Slay, 2015)
ATTACK_CATEGORIES = [
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
    "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms"
]
CAT_TO_IDX = {cat: idx for idx, cat in enumerate(ATTACK_CATEGORIES)}

# 37 features numericas del dataset
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

# Features con alta asimetria que se benefician de log1p
LOG_TRANSFORM_COLS = [
    "sbytes", "dbytes", "sload", "dload", "rate",
    "response_body_len", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit",
    "stcpb", "dtcpb"
]

# Ruta por defecto del fichero de configuracion
CONFIG_PATH = "/home/nobody/data/fl_config.json"


# ============================================================================
# Configuracion
# ============================================================================

def load_config(config_path: str = CONFIG_PATH) -> dict:
    """
    Carga fl_config.json si existe y devuelve los parametros de entrenamiento.

    Parametros soportados:
        rounds            (int)   : numero de rondas FL (leido por app.py)
        round_timeout     (int)   : segundos de espera por ronda (leido por app.py)
        min_workers       (int)   : minimo de workers para FedAvg (leido por app.py)
        epochs            (int)   : epocas maximas de entrenamiento local
        batch_size        (int)   : tamano del batch
        learning_rate     (float) : tasa de aprendizaje del optimizador Adam
        test_split        (float) : fraccion de datos para validacion local
        early_stopping_patience (int) : epocas sin mejora antes de parar
    """
    defaults = {
        "rounds"        : 5,
        "round_timeout" : 300,
        "min_workers"   : 2,
        "epochs"        : 10,
        "batch_size"    : 64,
        "learning_rate" : 0.001,
        "test_split"    : 0.2,
        "early_stopping_patience": 3,
    }
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            defaults.update(cfg)
        except Exception:
            pass
    return defaults


# ============================================================================
# Serializacion de pesos
# ============================================================================

def weights_to_b64(weights: list) -> str:
    payload = json.dumps([w.tolist() for w in weights]).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def b64_to_weights(b64_str: str) -> list:
    payload = base64.b64decode(b64_str.encode("utf-8"))
    return [np.array(w, dtype=np.float32) for w in json.loads(payload.decode("utf-8"))]


# ============================================================================
# Carga y preprocesado del dataset
# ============================================================================

def load_unsw_nb15(data_path: str, test_split: float = 0.2):
    """
    Carga y preprocesa una particion local del UNSW-NB15.

    Pipeline:
      1. Detectar modo (multiclase si attack_cat existe, binario si no)
      2. Seleccionar features numericas disponibles
      3. Imputar valores faltantes e infinitos
      4. Transformacion logaritmica (log1p) en features asimetricas
      5. Clip de outliers al percentil 99
      6. StandardScaler (media=0, std=1) -- calculado localmente
      7. Stratified split train/val

    Returns:
        X_train, y_train, X_val, y_val, feature_cols, num_classes, class_names
    """
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]

    # --- Detectar modo: multiclase o binario ---
    if ATTACK_CAT_COL in df.columns:
        # Multiclase: 10 categorias
        df[ATTACK_CAT_COL] = df[ATTACK_CAT_COL].fillna("Normal").astype(str).str.strip()
        df.loc[df[ATTACK_CAT_COL] == "", ATTACK_CAT_COL] = "Normal"

        # Mapear a indices enteros
        y_series = df[ATTACK_CAT_COL].map(CAT_TO_IDX)
        # Categorias desconocidas -> Normal (0)
        y_series = y_series.fillna(0).astype(int)
        num_classes = len(ATTACK_CATEGORIES)
        class_names = list(ATTACK_CATEGORIES)
        mode = "multiclass"
        log.info(f"[algorithm] Modo MULTICLASE detectado ({num_classes} clases)")
    else:
        # Fallback binario
        if LABEL_COL not in df.columns:
            if "attack_cat" in df.columns:
                df[LABEL_COL] = (df["attack_cat"].str.strip() != "Normal").astype(int)
            else:
                num_cols = df.select_dtypes(include="number").columns.tolist()
                df[LABEL_COL] = df[num_cols[-1]].astype(int)
        y_series = (df[LABEL_COL].values > 0).astype(int)
        y_series = pd.Series(y_series)
        num_classes = 2
        class_names = ["Normal", "Attack"]
        mode = "binary"
        log.info("[algorithm] Modo BINARIO (fallback -- attack_cat no encontrado)")

    # --- Seleccionar features ---
    available = [c for c in FEATURE_COLS if c in df.columns]
    if not available:
        available = [c for c in df.select_dtypes(include="number").columns
                     if c != LABEL_COL and c != "id"]

    log.info(f"[algorithm] Features: {len(available)} de {len(FEATURE_COLS)} disponibles")

    # --- Imputacion ---
    X_df = df[available].copy()
    X_df = X_df.fillna(0)
    X_df = X_df.replace([np.inf, -np.inf], 0)

    # --- Log1p transform en features asimetricas ---
    log_cols = [c for c in LOG_TRANSFORM_COLS if c in X_df.columns]
    for col in log_cols:
        X_df[col] = np.log1p(X_df[col].clip(lower=0))

    # --- Clip de outliers al percentil 99 ---
    for col in X_df.columns:
        p99 = X_df[col].quantile(0.99)
        if p99 > 0:
            X_df[col] = X_df[col].clip(upper=p99)

    # --- StandardScaler (local por worker -- privacidad FL) ---
    scaler = StandardScaler()
    X = scaler.fit_transform(X_df.values).astype(np.float32)
    # Reemplazar NaN post-scaling (columnas con std=0)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    y = y_series.values.astype(np.int32)

    # --- Stratified split ---
    n_val = max(1, int(len(X) * test_split))
    indices = np.random.permutation(len(X))

    # Intentar stratified split
    try:
        from sklearn.model_selection import train_test_split
        train_idx, val_idx = train_test_split(
            np.arange(len(X)), test_size=test_split,
            stratify=y, random_state=SEED
        )
    except Exception:
        # Fallback a random split si stratify falla (clase con 1 muestra)
        val_idx = indices[:n_val]
        train_idx = indices[n_val:]

    return (X[train_idx], y[train_idx],
            X[val_idx], y[val_idx],
            available, num_classes, class_names)


# ============================================================================
# Modelo
# ============================================================================

def build_model(input_dim: int, num_classes: int,
                learning_rate: float = 0.001) -> keras.Model:
    """
    Deep Neural Network para clasificacion de intrusiones de red.

    Arquitectura:
        Input(N) -> Dense(256, relu) -> BatchNorm -> Dropout(0.3)
                 -> Dense(128, relu) -> BatchNorm -> Dropout(0.2)
                 -> Dense(64, relu)  -> BatchNorm -> Dropout(0.1)
                 -> Dense(32, relu)
                 -> Dense(num_classes, softmax)

    Para clasificacion binaria (num_classes=2): softmax con 2 salidas.
    Para multiclase (num_classes=10): softmax con 10 salidas.

    Regularizacion:
      - BatchNormalization: estabiliza el entrenamiento entre rondas FL
      - Dropout decreciente (0.3 -> 0.2 -> 0.1): previene overfitting
        en particiones pequenas de datos non-IID

    Ref: Luzon et al. (2024) Sec.VII-A, McMahan et al. (2017) Sec.3
    """
    inputs = keras.layers.Input(shape=(input_dim,), name="input_features")

    x = keras.layers.Dense(256, activation="relu", name="dense_1")(inputs)
    x = keras.layers.BatchNormalization(name="bn_1")(x)
    x = keras.layers.Dropout(0.3, name="dropout_1")(x)

    x = keras.layers.Dense(128, activation="relu", name="dense_2")(x)
    x = keras.layers.BatchNormalization(name="bn_2")(x)
    x = keras.layers.Dropout(0.2, name="dropout_2")(x)

    x = keras.layers.Dense(64, activation="relu", name="dense_3")(x)
    x = keras.layers.BatchNormalization(name="bn_3")(x)
    x = keras.layers.Dropout(0.1, name="dropout_3")(x)

    x = keras.layers.Dense(32, activation="relu", name="dense_4")(x)

    outputs = keras.layers.Dense(
        num_classes, activation="softmax", name="output"
    )(x)

    model = keras.Model(
        inputs=inputs, outputs=outputs,
        name="fl_ids_multiclass_dnn"
    )

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model


# ============================================================================
# Metricas completas
# ============================================================================

def compute_full_metrics(model, X_val, y_val, class_names):
    """
    Calcula metricas completas nivel PFG:
      - loss, accuracy (Keras)
      - AUC macro (one-vs-rest)
      - Precision, Recall, F1 (macro y weighted)
      - Matthews Correlation Coefficient (MCC)
      - Confusion Matrix
      - Per-class F1
      - Feature Importance (L1 norm de la primera capa densa)
    """
    # Keras loss + accuracy
    eval_res = model.evaluate(X_val, y_val, verbose=0)
    loss_val = float(eval_res[0])
    acc_val = float(eval_res[1])

    # Predicciones
    y_prob = model.predict(X_val, verbose=0)
    y_pred = np.argmax(y_prob, axis=1)

    # Clases presentes en la particion
    present_labels = sorted(set(y_val.tolist()) | set(y_pred.tolist()))

    # AUC macro (one-vs-rest)
    try:
        from sklearn.metrics import roc_auc_score
        if len(present_labels) > 2:
            auc_val = roc_auc_score(
                y_val, y_prob, multi_class="ovr",
                average="macro", labels=list(range(len(class_names)))
            )
        else:
            auc_val = roc_auc_score(y_val, y_prob[:, 1] if y_prob.shape[1] > 1 else y_prob[:, 0])
        auc_val = float(auc_val)
    except Exception:
        auc_val = 0.0

    # Precision, Recall, F1
    prec_macro = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_val, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))

    # MCC
    mcc_val = float(matthews_corrcoef(y_val, y_pred))

    # Confusion Matrix
    cm = confusion_matrix(y_val, y_pred, labels=list(range(len(class_names))))
    cm_list = cm.tolist()

    # Per-class report
    report = classification_report(
        y_val, y_pred, labels=list(range(len(class_names))),
        target_names=class_names, output_dict=True, zero_division=0
    )
    per_class_f1 = {}
    for cls_name in class_names:
        if cls_name in report:
            per_class_f1[cls_name] = round(report[cls_name]["f1-score"], 4)

    # Feature Importance (L1 norm de pesos de la primera capa densa)
    feature_importance = {}
    try:
        first_dense = None
        for layer in model.layers:
            if isinstance(layer, keras.layers.Dense):
                first_dense = layer
                break
        if first_dense is not None:
            w = first_dense.get_weights()[0]  # shape: (input_dim, 256)
            importance = np.mean(np.abs(w), axis=1)
            # Normalizar a [0, 1]
            imp_max = importance.max()
            if imp_max > 0:
                importance = importance / imp_max
            feature_importance = {
                f"feature_{i}": round(float(v), 4)
                for i, v in enumerate(importance)
            }
    except Exception:
        pass

    metrics = {
        "loss"      : round(loss_val, 6),
        "accuracy"  : round(acc_val, 6),
        "auc"       : round(auc_val, 6),
        "precision" : round(prec_macro, 6),
        "recall"    : round(rec_macro, 6),
        "f1_macro"  : round(f1_macro, 6),
        "f1_weighted": round(f1_weighted, 6),
        "mcc"       : round(mcc_val, 6),
        "num_classes": len(class_names),
        "classification_mode": "multiclass" if len(class_names) > 2 else "binary",
    }

    return metrics, cm_list, per_class_f1, feature_importance


# ============================================================================
# Funcion principal
# ============================================================================

def run(data_path: str, global_weights_b64: str = None,
        config_path: str = CONFIG_PATH) -> dict:
    """
    Entrena el modelo local una ronda de FL y devuelve pesos + metricas.

    Lee los hiperparametros de fl_config.json (config_path).
    Si no existe, usa los valores por defecto de load_config().

    Args:
        data_path          : Ruta al CSV local (particion UNSW-NB15).
        global_weights_b64 : Pesos globales en base64. None en ronda 1.
        config_path        : Ruta a fl_config.json.

    Returns:
        {
            "weights_b64"          : str,
            "n_samples"            : int,
            "metrics"              : dict (loss, accuracy, auc, precision,
                                          recall, f1_macro, f1_weighted, mcc),
            "input_dim"            : int,
            "feature_cols"         : list[str],
            "model_name"           : str,
            "num_classes"          : int,
            "classification_mode"  : str,
            "feature_importance"   : dict,
            "confusion_matrix"     : list[list[int]],
            "per_class_report"     : dict
        }
    """
    cfg = load_config(config_path)
    epochs        = int(cfg["epochs"])
    batch_size    = int(cfg["batch_size"])
    learning_rate = float(cfg["learning_rate"])
    test_split    = float(cfg["test_split"])
    es_patience   = int(cfg.get("early_stopping_patience", 3))

    # --- Cargar y preprocesar datos ---
    X_train, y_train, X_val, y_val, feature_cols, num_classes, class_names = \
        load_unsw_nb15(data_path, test_split)
    input_dim = X_train.shape[1]

    log.info(
        f"[algorithm] Dataset: {len(X_train)} train, {len(X_val)} val, "
        f"{input_dim} features, {num_classes} clases"
    )

    # --- Class weights para compensar desbalanceo ---
    try:
        cw_values = compute_class_weight(
            "balanced", classes=np.arange(num_classes), y=y_train
        )
        class_weight_dict = {i: float(w) for i, w in enumerate(cw_values)}
        log.info(f"[algorithm] Class weights: { {class_names[i]: round(w, 2) for i, w in class_weight_dict.items() if i < len(class_names)} }")
    except Exception:
        class_weight_dict = None

    # --- Construir modelo ---
    model = build_model(input_dim, num_classes, learning_rate)

    # --- Cargar pesos globales si no es la primera ronda ---
    if global_weights_b64:
        try:
            model.set_weights(b64_to_weights(global_weights_b64))
            log.info("[algorithm] Pesos globales cargados correctamente")
        except Exception as e:
            log.warning(f"[algorithm] No se pudieron cargar pesos globales: {e}")

    # --- Callbacks ---
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=es_patience,
            restore_best_weights=True,
            verbose=0
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=max(1, es_patience - 1),
            min_lr=1e-6,
            verbose=0
        ),
    ]

    # --- Entrenar ---
    model.fit(
        X_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        verbose=0,
        validation_data=(X_val, y_val),
        class_weight=class_weight_dict,
        callbacks=callbacks,
    )

    # --- Metricas completas ---
    metrics, cm, per_class_f1, feature_importance = \
        compute_full_metrics(model, X_val, y_val, class_names)

    log.info(
        f"[algorithm] Resultados: "
        f"acc={metrics['accuracy']:.4f} "
        f"auc={metrics['auc']:.4f} "
        f"f1_macro={metrics['f1_macro']:.4f} "
        f"mcc={metrics['mcc']:.4f}"
    )

    # Nombrar features en feature_importance con nombres reales
    if feature_importance and len(feature_cols) == len(feature_importance):
        feature_importance = {
            feature_cols[i]: v
            for i, (_, v) in enumerate(sorted(feature_importance.items()))
        }

    return {
        "weights_b64"         : weights_to_b64(model.get_weights()),
        "n_samples"           : int(len(X_train)),
        "metrics"             : metrics,
        "input_dim"           : int(input_dim),
        "feature_cols"        : list(feature_cols),
        "model_name"          : model.name,
        "num_classes"         : num_classes,
        "classification_mode" : metrics.get("classification_mode", "multiclass"),
        "feature_importance"  : feature_importance,
        "confusion_matrix"    : cm,
        "per_class_report"    : per_class_f1,
    }