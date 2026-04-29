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

import os, json, base64, logging, hashlib
import numpy as np
import pandas as pd

SEED = 42
np.random.seed(SEED)

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
tf.random.set_seed(SEED)
from tensorflow import keras

from sklearn.preprocessing import StandardScaler
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
CATEGORICAL_HASH_COLS = {
    "proto": 16,
    "state": 8,
    "service": 16,
}
CONFIG_PATH = "/home/nobody/data/fl_config.json"
ULTRA_RARE_CLASS_COUNT = 8
RARE_CLASS_COUNT = 40
MINORITY_TARGET_RATIO = 0.2
MINORITY_TARGET_FLOOR = 32
MINORITY_TARGET_CAP = 400


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


class FedProxModel(keras.Model):
    """Modelo Keras con termino proximal FedProx en el entrenamiento local."""
    def __init__(self, *args, prox_mu=0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.prox_mu = float(prox_mu or 0.0)
        self._prox_reference = None

    def set_prox_reference(self, weights):
        if not weights:
            self._prox_reference = None
            return
        self._prox_reference = [tf.constant(w, dtype=tf.float32) for w in weights]

    def train_step(self, data):
        x, y, sample_weight = keras.utils.unpack_x_y_sample_weight(data)
        with tf.GradientTape() as tape:
            y_pred = self(x, training=True)
            loss = self.compiled_loss(
                y, y_pred,
                sample_weight=sample_weight,
                regularization_losses=self.losses
            )
            if self.prox_mu > 0 and self._prox_reference is not None:
                prox_terms = []
                for w, ref in zip(self.trainable_weights, self._prox_reference):
                    if tuple(w.shape) == tuple(ref.shape):
                        prox_terms.append(tf.reduce_sum(tf.square(w - ref)))
                if prox_terms:
                    loss = loss + 0.5 * self.prox_mu * tf.add_n(prox_terms)

        gradients = tape.gradient(loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(gradients, self.trainable_weights))
        self.compiled_metrics.update_state(y, y_pred, sample_weight=sample_weight)

        results = {m.name: m.result() for m in self.metrics}
        results["loss"] = loss
        return results


# ============================================================================
# Config, serialization
# ============================================================================
def load_config(config_path=CONFIG_PATH):
    defaults = {
        "rounds": 25,
        "round_timeout": 180,
        "min_workers": 2,
        "epochs": 5,
        "batch_size": 128,
        "learning_rate": 0.001,
        "test_split": 0.2,
        "early_stopping_patience": 2,
        "focal_gamma": 1.25,
        "label_smoothing": 0.02,
        "fedprox_mu": 0.005,
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
def _minority_target_size(class_count, majority_count):
    target = max(
        MINORITY_TARGET_FLOOR,
        int(np.ceil(majority_count * MINORITY_TARGET_RATIO)),
        int(class_count * 3),
    )
    return min(MINORITY_TARGET_CAP, target)


def _apply_smote(X, y, num_classes):
    """Oversampling hibrido para reforzar clases muy raras y minoritarias."""
    try:
        from imblearn.over_sampling import RandomOverSampler, SMOTE
        class_counts = np.bincount(y, minlength=num_classes)
        present_counts = class_counts[class_counts > 0]
        if present_counts.size == 0:
            return X, y
        majority_count = int(present_counts.max())

        ros_strategy = {}
        for cls_idx, count in enumerate(class_counts):
            if count <= 0 or count >= majority_count:
                continue
            if count <= 5:
                ros_strategy[cls_idx] = max(6, _minority_target_size(count, majority_count) // 2)

        X_res, y_res = X, y
        if ros_strategy:
            ros = RandomOverSampler(sampling_strategy=ros_strategy, random_state=SEED)
            X_res, y_res = ros.fit_resample(X_res, y_res)
            log.info(
                f"[algorithm] RandomOverSampler: {len(X)} -> {len(X_res)} muestras "
                f"(clases reforzadas: {list(ros_strategy.keys())})"
            )

        class_counts = np.bincount(y_res, minlength=num_classes)
        smote_strategy = {}
        for cls_idx, count in enumerate(class_counts):
            if count < 6:
                continue
            target = _minority_target_size(count, majority_count)
            if count < target:
                smote_strategy[cls_idx] = target

        if not smote_strategy:
            return X_res, y_res

        min_smote_count = min(class_counts[c] for c in smote_strategy)
        sm = SMOTE(
            sampling_strategy=smote_strategy,
            random_state=SEED,
            k_neighbors=max(1, min(5, min_smote_count - 1))
        )
        X_bal, y_bal = sm.fit_resample(X_res, y_res)
        log.info(
            f"[algorithm] SMOTE: {len(X_res)} -> {len(X_bal)} muestras "
            f"(clases oversampled: {list(smote_strategy.keys())})"
        )
        return X_bal, y_bal
    except Exception as e:
        log.warning(f"[algorithm] SMOTE no disponible, continuando sin oversample: {e}")
        return X, y


def _stable_bucket(value, n_buckets):
    token = str(value).strip().lower().encode("utf-8")
    digest = hashlib.md5(token).hexdigest()
    return int(digest, 16) % n_buckets


def _build_hashed_categorical_features(df):
    matrices = []
    feature_names = []
    present_cols = []
    for col, n_buckets in CATEGORICAL_HASH_COLS.items():
        if col not in df.columns:
            continue
        raw_values = df[col].fillna("unknown").astype(str).str.strip().str.lower()
        if raw_values.empty:
            continue
        present_cols.append(col)
        bucket_idx = raw_values.map(lambda v: _stable_bucket(v or "unknown", n_buckets)).to_numpy(dtype=np.int32)
        one_hot = np.zeros((len(raw_values), n_buckets), dtype=np.float32)
        one_hot[np.arange(len(raw_values)), bucket_idx] = 1.0
        matrices.append(one_hot)
        feature_names.extend([f"{col}_hash_{i}" for i in range(n_buckets)])
    if present_cols:
        log.info(f"[algorithm] Features categoricas hash activas: {present_cols}")
    else:
        log.info("[algorithm] CSV sin proto/state/service -- continuando solo con features numericas")
    return matrices, feature_names


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
    log.info(f"[algorithm] Features numericas: {len(available)} de {len(FEATURE_COLS)}")

    X_df = df[available].fillna(0).replace([np.inf, -np.inf], 0)
    for col in [c for c in LOG_TRANSFORM_COLS if c in X_df.columns]:
        X_df[col] = np.log1p(X_df[col].clip(lower=0))
    for col in X_df.columns:
        p99 = X_df[col].quantile(0.99)
        if p99 > 0:
            X_df[col] = X_df[col].clip(upper=p99)

    scaler = StandardScaler()
    X_num = np.nan_to_num(scaler.fit_transform(X_df.values).astype(np.float32))
    cat_matrices, cat_feature_names = _build_hashed_categorical_features(df)
    if cat_matrices:
        X = np.hstack([X_num] + cat_matrices).astype(np.float32)
        feature_cols = available + cat_feature_names
    else:
        X = X_num
        feature_cols = list(available)
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
    train_class_counts = np.bincount(y_train, minlength=num_classes).astype(np.int32)

    # SMOTE en train solamente
    X_train, y_train = _apply_smote(X_train, y_train, num_classes)

    return (X_train, y_train, X[val_idx], y[val_idx],
            feature_cols, num_classes, class_names, train_class_counts)


def compute_training_class_weights(train_class_counts, class_names):
    """
    Pesos de clase basados en la distribucion original del train
    antes del oversampling, con boost extra para clases muy raras.
    """
    counts = np.asarray(train_class_counts, dtype=np.float32)
    total = float(counts.sum())
    present_mask = counts > 0
    if total <= 0 or not np.any(present_mask):
        return None, None

    num_present = float(np.sum(present_mask))
    balanced = np.ones_like(counts, dtype=np.float32)
    balanced[present_mask] = total / (num_present * counts[present_mask])

    beta = 0.999
    effective = np.ones_like(counts, dtype=np.float32)
    effective[present_mask] = (1.0 - beta) / (1.0 - np.power(beta, counts[present_mask]))

    combined = np.ones_like(counts, dtype=np.float32)
    combined[present_mask] = np.sqrt(balanced[present_mask] * effective[present_mask])

    rarity_boost = np.ones_like(counts, dtype=np.float32)
    rarity_boost[(counts > 0) & (counts <= ULTRA_RARE_CLASS_COUNT)] = 1.8
    rarity_boost[(counts > ULTRA_RARE_CLASS_COUNT) & (counts <= RARE_CLASS_COUNT)] = 1.35
    combined *= rarity_boost
    combined[present_mask] = np.clip(combined[present_mask], 0.5, 8.0)

    cw_list = [float(v) for v in combined]
    cw_dict = {i: cw_list[i] for i in range(len(cw_list))}
    counts_log = {class_names[i]: int(counts[i]) for i in range(len(class_names)) if counts[i] > 0}
    weights_log = {class_names[i]: round(cw_list[i], 3) for i in range(len(class_names)) if counts[i] > 0}
    log.info(f"[algorithm] Train class counts (pre-resample): {counts_log}")
    log.info(f"[algorithm] Loss class weights (pre-resample): {weights_log}")
    return cw_list, cw_dict


# ============================================================================
# Modelo v2: red mas ancha con Focal Loss
# ============================================================================
def build_model(input_dim, num_classes, learning_rate=0.0015,
                class_weights=None, total_steps=100,
                focal_gamma=1.5, label_smoothing=0.05,
                prox_mu=0.0):
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

    model = FedProxModel(
        inputs=inputs, outputs=outputs,
        name="fl_ids_multiclass_dnn_v3",
        prox_mu=prox_mu
    )

    # Cosine Decay LR
    lr_schedule = keras.optimizers.schedules.CosineDecay(
        initial_learning_rate=learning_rate,
        decay_steps=total_steps,
        alpha=1e-5
    )

    # Focal Loss con class weights
    loss_fn = SparseFocalLoss(
        gamma=focal_gamma,
        class_weights=class_weights,
        label_smoothing=label_smoothing,
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


class ValidationMacroF1Callback(keras.callbacks.Callback):
    """Calcula macro-F1 por epoca para seleccionar mejor las clases minoritarias."""
    def __init__(self, X_val, y_val, class_names):
        super().__init__()
        self.X_val = X_val
        self.y_val = y_val
        self.class_names = class_names

    def on_epoch_end(self, epoch, logs=None):
        logs = logs if logs is not None else {}
        y_prob = self.model.predict(self.X_val, verbose=0)
        y_pred = np.argmax(y_prob, axis=1)
        val_f1_macro = float(f1_score(self.y_val, y_pred, average="macro", zero_division=0))

        present_labels = sorted(set(int(v) for v in self.y_val.tolist()))
        minority_labels = [i for i in present_labels if np.sum(self.y_val == i) <= RARE_CLASS_COUNT]
        minority_f1 = 0.0
        if minority_labels:
            report = classification_report(
                self.y_val,
                y_pred,
                labels=present_labels,
                target_names=[self.class_names[i] for i in present_labels],
                output_dict=True,
                zero_division=0,
            )
            values = [
                float(report[self.class_names[i]]["f1-score"])
                for i in minority_labels
                if self.class_names[i] in report
            ]
            if values:
                minority_f1 = float(np.mean(values))

        logs["val_f1_macro"] = val_f1_macro
        logs["val_minority_f1"] = minority_f1
        log.info(
            f"[algorithm] epoch {epoch + 1}: "
            f"val_f1_macro={val_f1_macro:.4f} val_minority_f1={minority_f1:.4f}"
        )


# ============================================================================
# Funcion principal
# ============================================================================
def run(data_path, global_weights_b64=None, config_path=CONFIG_PATH):
    cfg = load_config(config_path)
    epochs = int(cfg["epochs"])
    batch_size = int(cfg["batch_size"])
    learning_rate = float(cfg["learning_rate"])
    test_split = float(cfg["test_split"])
    es_patience = int(cfg.get("early_stopping_patience", 3))
    focal_gamma = float(cfg.get("focal_gamma", 1.25))
    label_smoothing = float(cfg.get("label_smoothing", 0.02))
    fedprox_mu = float(cfg.get("fedprox_mu", 0.005))

    X_train, y_train, X_val, y_val, feature_cols, num_classes, class_names, train_class_counts = \
        load_unsw_nb15(data_path, test_split)
    input_dim = X_train.shape[1]
    log.info(f"[algorithm] Dataset: {len(X_train)} train, {len(X_val)} val, "
             f"{input_dim} features, {num_classes} clases")

    cw_list, _ = compute_training_class_weights(train_class_counts, class_names)

    total_steps = (len(X_train) // batch_size + 1) * epochs
    model = build_model(input_dim, num_classes, learning_rate,
                        class_weights=cw_list,
                        total_steps=total_steps,
                        focal_gamma=focal_gamma,
                        label_smoothing=label_smoothing,
                        prox_mu=fedprox_mu)

    if global_weights_b64:
        try:
            incoming_weights = b64_to_weights(global_weights_b64)
            model.set_weights(incoming_weights)
            model.set_prox_reference(incoming_weights)
            log.info("[algorithm] Pesos globales cargados correctamente")
        except Exception as e:
            log.warning(f"[algorithm] No se pudieron cargar pesos globales: {e}")
            model.set_prox_reference(model.get_weights())
    else:
        model.set_prox_reference(model.get_weights())

    callbacks = [
        ValidationMacroF1Callback(X_val, y_val, class_names),
        keras.callbacks.EarlyStopping(
            monitor="val_f1_macro", patience=es_patience, mode="max",
            restore_best_weights=True, verbose=0),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_f1_macro", factor=0.5, mode="max",
            patience=max(1, es_patience - 1), min_lr=1e-6, verbose=0),
    ]

    model.fit(X_train, y_train, epochs=epochs, batch_size=batch_size,
              verbose=0, validation_data=(X_val, y_val),
              callbacks=callbacks)

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
