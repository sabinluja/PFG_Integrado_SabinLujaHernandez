"""
algorithm.py -- FL Worker: Clasificacion Multiclase de Intrusiones de Red
=========================================================================
Dataset: UNSW-NB15 (Moustafa & Slay, 2015)
         10 clases: Normal + 9 tipos de ataque
Modelo:  DNN con BatchNorm, Dropout, Focal Loss y SMOTE
Agregacion FL: FedAvg -- McMahan et al. (2017)

Mejoras v2:
  - Focal Loss (Lin et al., 2017) para clases desbalanceadas
  - SMOTE oversampling en clases minoritarias
  - Label Smoothing (0.1)
  - Cosine Decay LR schedule
  - Red mas ancha (512->256->128->64->10)

Referencias:
  McMahan et al. (2017) - Communication-Efficient Learning - AISTATS 2017
  Lin et al. (2017) - Focal Loss for Dense Object Detection - ICCV 2017
  Chawla et al. (2002) - SMOTE - JAIR 2002
  Moustafa & Slay (2015) - UNSW-NB15 - MilCIS 2015
"""

import os, json, base64, logging
import numpy as np
import pandas as pd

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
# Constantes UNSW-NB15
# ============================================================================
LABEL_COL = "label"
ATTACK_CAT_COL = "attack_cat"
ATTACK_CATEGORIES = [
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
    "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms"
]
CAT_TO_IDX = {cat: idx for idx, cat in enumerate(ATTACK_CATEGORIES)}

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
LOG_TRANSFORM_COLS = [
    "sbytes", "dbytes", "sload", "dload", "rate",
    "response_body_len", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "stcpb", "dtcpb"
]
CONFIG_PATH = "/home/nobody/data/fl_config.json"


# ============================================================================
# Focal Loss (Lin et al., 2017)
# ============================================================================
class SparseFocalLoss(keras.losses.Loss):
    """
    Focal Loss para clasificacion multiclase con etiquetas enteras.
    FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    gamma=2 down-weights easy examples, focusing on hard minority classes.
    """
    def __init__(self, gamma=2.0, class_weights=None, label_smoothing=0.1,
                 num_classes=10, **kwargs):
        super().__init__(**kwargs)
        self.gamma = gamma
        self.label_smoothing = label_smoothing
        self.num_classes = num_classes
        if class_weights is not None:
            self.alpha = tf.constant(class_weights, dtype=tf.float32)
        else:
            self.alpha = None

    def call(self, y_true, y_pred):
        y_true = tf.cast(tf.reshape(y_true, [-1]), tf.int32)
        y_pred = tf.clip_by_value(y_pred, 1e-7, 1.0 - 1e-7)

        # Label smoothing
        onehot = tf.one_hot(y_true, self.num_classes)
        if self.label_smoothing > 0:
            onehot = onehot * (1 - self.label_smoothing) + \
                     self.label_smoothing / self.num_classes

        # Focal modulation
        pt = tf.reduce_sum(y_pred * onehot, axis=-1)
        focal_weight = tf.pow(1.0 - pt, self.gamma)

        ce = -tf.reduce_sum(onehot * tf.math.log(y_pred), axis=-1)

        # Per-class alpha weighting
        if self.alpha is not None:
            alpha_t = tf.gather(self.alpha, y_true)
            loss = alpha_t * focal_weight * ce
        else:
            loss = focal_weight * ce

        return tf.reduce_mean(loss)


# ============================================================================
# Config, serialization
# ============================================================================
def load_config(config_path=CONFIG_PATH):
    defaults = {
        "rounds": 10, "round_timeout": 300, "min_workers": 2,
        "epochs": 30, "batch_size": 128, "learning_rate": 0.002,
        "test_split": 0.2, "early_stopping_patience": 5,
    }
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path) as f:
                defaults.update(json.load(f))
        except Exception:
            pass
    return defaults

def weights_to_b64(weights):
    return base64.b64encode(
        json.dumps([w.tolist() for w in weights]).encode()
    ).decode()

def b64_to_weights(b64_str):
    return [np.array(w, dtype=np.float32)
            for w in json.loads(base64.b64decode(b64_str))]


# ============================================================================
# Dataset loading + SMOTE
# ============================================================================
def _apply_smote(X, y, num_classes):
    """SMOTE oversampling para clases con < 500 muestras."""
    try:
        from imblearn.over_sampling import SMOTE
        class_counts = np.bincount(y, minlength=num_classes)
        minority = [i for i, c in enumerate(class_counts) if 0 < c < 500]
        if not minority:
            return X, y
        # Target: al menos 500 muestras o 2x lo que tienen
        strategy = {}
        for cls_idx in minority:
            strategy[cls_idx] = min(500, max(class_counts[cls_idx] * 3, 200))
        # Solo oversamplear clases que existen
        strategy = {k: v for k, v in strategy.items() if class_counts[k] > 0}
        if not strategy:
            return X, y
        sm = SMOTE(sampling_strategy=strategy, random_state=SEED, k_neighbors=min(3, min(class_counts[c] for c in strategy) - 1))
        X_res, y_res = sm.fit_resample(X, y)
        log.info(f"[algorithm] SMOTE: {len(X)} -> {len(X_res)} muestras "
                 f"(clases oversampled: {list(strategy.keys())})")
        return X_res, y_res
    except Exception as e:
        log.warning(f"[algorithm] SMOTE no disponible, continuando sin oversample: {e}")
        return X, y


def load_unsw_nb15(data_path, test_split=0.2):
    """Carga y preprocesa particion local UNSW-NB15."""
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]

    if ATTACK_CAT_COL in df.columns:
        df[ATTACK_CAT_COL] = df[ATTACK_CAT_COL].fillna("Normal").str.strip()
        df.loc[df[ATTACK_CAT_COL] == "", ATTACK_CAT_COL] = "Normal"
        y_series = df[ATTACK_CAT_COL].map(CAT_TO_IDX).fillna(0).astype(int)
        num_classes = len(ATTACK_CATEGORIES)
        class_names = list(ATTACK_CATEGORIES)
        log.info(f"[algorithm] Modo MULTICLASE detectado ({num_classes} clases)")
    else:
        if LABEL_COL not in df.columns:
            num_cols = df.select_dtypes(include="number").columns.tolist()
            df[LABEL_COL] = df[num_cols[-1]].astype(int)
        y_series = pd.Series((df[LABEL_COL].values > 0).astype(int))
        num_classes, class_names = 2, ["Normal", "Attack"]
        log.info("[algorithm] Modo BINARIO (fallback)")

    available = [c for c in FEATURE_COLS if c in df.columns]
    if not available:
        available = [c for c in df.select_dtypes(include="number").columns
                     if c not in (LABEL_COL, "id")]
    log.info(f"[algorithm] Features: {len(available)} de {len(FEATURE_COLS)}")

    X_df = df[available].fillna(0).replace([np.inf, -np.inf], 0)
    for col in [c for c in LOG_TRANSFORM_COLS if c in X_df.columns]:
        X_df[col] = np.log1p(X_df[col].clip(lower=0))
    for col in X_df.columns:
        p99 = X_df[col].quantile(0.99)
        if p99 > 0:
            X_df[col] = X_df[col].clip(upper=p99)

    scaler = StandardScaler()
    X = np.nan_to_num(scaler.fit_transform(X_df.values).astype(np.float32))
    y = y_series.values.astype(np.int32)

    try:
        from sklearn.model_selection import train_test_split
        train_idx, val_idx = train_test_split(
            np.arange(len(X)), test_size=test_split,
            stratify=y, random_state=SEED)
    except Exception:
        n_val = max(1, int(len(X) * test_split))
        idx = np.random.permutation(len(X))
        val_idx, train_idx = idx[:n_val], idx[n_val:]

    X_train, y_train = X[train_idx], y[train_idx]

    # SMOTE en train solamente
    X_train, y_train = _apply_smote(X_train, y_train, num_classes)

    return (X_train, y_train, X[val_idx], y[val_idx],
            available, num_classes, class_names)


# ============================================================================
# Modelo v2: red mas ancha con Focal Loss
# ============================================================================
def build_model(input_dim, num_classes, learning_rate=0.002,
                class_weights=None, total_steps=100):
    """
    DNN v2: 512->256->128->64->num_classes
    Con Focal Loss, Label Smoothing, y Cosine Decay LR.
    """
    inputs = keras.layers.Input(shape=(input_dim,), name="input_features")

    x = keras.layers.Dense(512, activation="relu", name="dense_1",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(inputs)
    x = keras.layers.BatchNormalization(name="bn_1")(x)
    x = keras.layers.Dropout(0.4, name="dropout_1")(x)

    x = keras.layers.Dense(256, activation="relu", name="dense_2",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(x)
    x = keras.layers.BatchNormalization(name="bn_2")(x)
    x = keras.layers.Dropout(0.3, name="dropout_2")(x)

    x = keras.layers.Dense(128, activation="relu", name="dense_3",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(x)
    x = keras.layers.BatchNormalization(name="bn_3")(x)
    x = keras.layers.Dropout(0.2, name="dropout_3")(x)

    x = keras.layers.Dense(64, activation="relu", name="dense_4")(x)

    outputs = keras.layers.Dense(
        num_classes, activation="softmax", name="output"
    )(x)

    model = keras.Model(inputs=inputs, outputs=outputs,
                        name="fl_ids_multiclass_dnn_v2")

    # Cosine Decay LR
    lr_schedule = keras.optimizers.schedules.CosineDecay(
        initial_learning_rate=learning_rate,
        decay_steps=total_steps,
        alpha=1e-5
    )

    # Focal Loss con class weights
    loss_fn = SparseFocalLoss(
        gamma=2.0,
        class_weights=class_weights,
        label_smoothing=0.1,
        num_classes=num_classes
    )

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr_schedule),
        loss=loss_fn,
        metrics=["accuracy"]
    )
    return model


# ============================================================================
# Metricas completas
# ============================================================================
def compute_full_metrics(model, X_val, y_val, class_names):
    """Metricas completas: loss, acc, AUC, F1, MCC, CM, per-class F1."""
    eval_res = model.evaluate(X_val, y_val, verbose=0)
    loss_val, acc_val = float(eval_res[0]), float(eval_res[1])

    y_prob = model.predict(X_val, verbose=0)
    y_pred = np.argmax(y_prob, axis=1)

    try:
        from sklearn.metrics import roc_auc_score
        auc_val = float(roc_auc_score(
            y_val, y_prob, multi_class="ovr", average="macro",
            labels=list(range(len(class_names)))
        )) if len(set(y_val)) > 2 else float(roc_auc_score(
            y_val, y_prob[:, 1] if y_prob.shape[1] > 1 else y_prob[:, 0]))
    except Exception:
        auc_val = 0.0

    prec = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
    rec = float(recall_score(y_val, y_pred, average="macro", zero_division=0))
    f1_m = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
    f1_w = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))
    mcc = float(matthews_corrcoef(y_val, y_pred))

    cm = confusion_matrix(y_val, y_pred, labels=list(range(len(class_names))))

    report = classification_report(
        y_val, y_pred, labels=list(range(len(class_names))),
        target_names=class_names, output_dict=True, zero_division=0)
    per_class_f1 = {c: round(report[c]["f1-score"], 4)
                    for c in class_names if c in report}

    # Feature importance (L1 norm primera capa)
    feat_imp = {}
    try:
        for layer in model.layers:
            if isinstance(layer, keras.layers.Dense):
                w = layer.get_weights()[0]
                imp = np.mean(np.abs(w), axis=1)
                mx = imp.max()
                if mx > 0:
                    imp = imp / mx
                feat_imp = {f"feature_{i}": round(float(v), 4)
                            for i, v in enumerate(imp)}
                break
    except Exception:
        pass

    metrics = {
        "loss": round(loss_val, 6), "accuracy": round(acc_val, 6),
        "auc": round(auc_val, 6), "precision": round(prec, 6),
        "recall": round(rec, 6), "f1_macro": round(f1_m, 6),
        "f1_weighted": round(f1_w, 6), "mcc": round(mcc, 6),
        "num_classes": len(class_names),
        "classification_mode": "multiclass" if len(class_names) > 2 else "binary",
    }
    return metrics, cm.tolist(), per_class_f1, feat_imp


# ============================================================================
# Funcion principal
# ============================================================================
def run(data_path, global_weights_b64=None, config_path=CONFIG_PATH):
    cfg = load_config(config_path)
    epochs = int(cfg["epochs"])
    batch_size = int(cfg["batch_size"])
    learning_rate = float(cfg["learning_rate"])
    test_split = float(cfg["test_split"])
    es_patience = int(cfg.get("early_stopping_patience", 5))

    X_train, y_train, X_val, y_val, feature_cols, num_classes, class_names = \
        load_unsw_nb15(data_path, test_split)
    input_dim = X_train.shape[1]
    log.info(f"[algorithm] Dataset: {len(X_train)} train, {len(X_val)} val, "
             f"{input_dim} features, {num_classes} clases")

    # Class weights para Focal Loss alpha
    try:
        cw = compute_class_weight("balanced", classes=np.arange(num_classes), y=y_train)
        cw_list = [float(w) for w in cw]
        cw_dict = {i: cw_list[i] for i in range(num_classes)}
        log.info(f"[algorithm] Class weights: "
                 f"{ {class_names[i]: round(w, 2) for i, w in cw_dict.items()} }")
    except Exception:
        cw_list = None
        cw_dict = None

    total_steps = (len(X_train) // batch_size + 1) * epochs
    model = build_model(input_dim, num_classes, learning_rate,
                        class_weights=cw_list, total_steps=total_steps)

    if global_weights_b64:
        try:
            model.set_weights(b64_to_weights(global_weights_b64))
            log.info("[algorithm] Pesos globales cargados correctamente")
        except Exception as e:
            log.warning(f"[algorithm] No se pudieron cargar pesos globales: {e}")

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=es_patience,
            restore_best_weights=True, verbose=0),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5,
            patience=max(1, es_patience - 1), min_lr=1e-6, verbose=0),
    ]

    model.fit(X_train, y_train, epochs=epochs, batch_size=batch_size,
              verbose=0, validation_data=(X_val, y_val),
              class_weight=cw_dict, callbacks=callbacks)

    metrics, cm, per_class_f1, feat_imp = \
        compute_full_metrics(model, X_val, y_val, class_names)

    log.info(f"[algorithm] Resultados: acc={metrics['accuracy']:.4f} "
             f"auc={metrics['auc']:.4f} f1_macro={metrics['f1_macro']:.4f} "
             f"mcc={metrics['mcc']:.4f}")

    if feat_imp and len(feature_cols) == len(feat_imp):
        feat_imp = {feature_cols[i]: v
                    for i, (_, v) in enumerate(sorted(feat_imp.items()))}

    return {
        "weights_b64": weights_to_b64(model.get_weights()),
        "n_samples": int(len(X_train)),
        "metrics": metrics,
        "input_dim": int(input_dim),
        "feature_cols": list(feature_cols),
        "model_name": model.name,
        "num_classes": num_classes,
        "classification_mode": metrics.get("classification_mode", "multiclass"),
        "feature_importance": feat_imp,
        "confusion_matrix": cm,
        "per_class_report": per_class_f1,
        "class_names": class_names,
    }