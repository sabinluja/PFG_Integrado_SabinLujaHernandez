"""
algorithm.py -- FL Worker: Clasificacion Multiclase de Intrusiones de Red
=========================================================================
Dataset: UNSW-NB15 (Moustafa & Slay, 2015)
         5 clases: agrupacion semantica para reducir confusiones entre ataques
Modelo:  DNN con BatchNorm, Dropout, Focal Loss y oversampling hibrido
Agregacion FL: FedAvg -- McMahan et al. (2017)

Mejoras v4:
  - Agrupacion a 5 clases con semantica mas coherente
  - Focal Loss (Lin et al., 2017) para clases desbalanceadas
  - Oversampling hibrido por clase (SMOTE + RandomOverSampler)
  - Label Smoothing mas conservador
  - Features numericas estandarizadas
  - Proto/service/state reintroducidas via one-hot limitado
  - Feature selection supervisada sobre el bloque numerico
  - Refuerzo dirigido a ExploitAccess, Disruption y ReconAttack

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
from sklearn.feature_selection import SelectKBest, VarianceThreshold, mutual_info_classif
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
ATTACK_GROUP_COL = "attack_group"
ATTACK_CATEGORIES = [
    "Benign",
    "GenericAttack",
    "ExploitAccess",
    "Disruption",
    "ReconAttack",
]
ATTACK_GROUP_MAP = {
    "normal": "Benign",
    "benign": "Benign",
    "generic": "GenericAttack",
    "genericattack": "GenericAttack",
    "exploitaccess": "ExploitAccess",
    "exploits": "ExploitAccess",
    "analysis": "ExploitAccess",
    "backdoor": "ExploitAccess",
    "shellcode": "ExploitAccess",
    "worms": "ExploitAccess",
    "fuzzers": "Disruption",
    "fuzzdos": "Disruption",
    "disruption": "Disruption",
    "dos": "Disruption",
    "reconnaissance": "ReconAttack",
    "reconattack": "ReconAttack",
    # Compatibilidad con agrupados heredados.
    "probe": "ReconAttack",
    "malware": "ReconAttack",
    "otherattack": "ReconAttack",
    "groupedattacks": "ReconAttack",
}
CAT_TO_IDX = {cat: idx for idx, cat in enumerate(ATTACK_CATEGORIES)}

FEATURE_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload", "sloss", "dloss",
    "sttl", "dttl",
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
# Fallback estable si no se pudo calcular una mascara automatica compartida.
SELECTED_NUMERIC_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "sload", "dload", "sloss", "dloss", "sttl",
    "dttl", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "tcprtt", "smean", "dmean", "response_body_len",
    "ct_state_ttl", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports", "ct_srv_src",
]
CATEGORICAL_COLS = ["proto", "service", "state"]
CATEGORICAL_VOCABS = {
    "proto": ["tcp", "udp", "unas", "arp", "ospf", "sctp", "any", "gre", "rsvp", "ipv6", "sep", "sun-nd"],
    "service": ["-", "dns", "http", "smtp", "ftp", "ftp-data", "pop3", "ssh", "ssl", "snmp", "dhcp", "radius"],
    "state": ["fin", "int", "con", "req", "acc", "rst", "clo"],
}
LOG_TRANSFORM_COLS = [
    "sbytes", "dbytes", "sload", "dload", "rate",
    "response_body_len", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "stcpb", "dtcpb"
]
CONFIG_PATH = "/home/nobody/data/fl_config.json"
MINORITY_TARGET_RATIO = 0.2
MINORITY_TARGET_FLOOR = 32
TAIL_CLASS_FRACTION = 0.4
CLASS_TARGET_RATIOS = {
    "Benign": 0.0,
    "GenericAttack": 0.0,
    "ExploitAccess": 0.20,
    "Disruption": 0.28,
    "ReconAttack": 0.18,
}
CLASS_TARGET_GROWTH_RATIOS = {
    "ExploitAccess": 0.16,
    "Disruption": 0.38,
    "ReconAttack": 0.32,
}
CLASS_FOCUS_BOOST = {
    "ExploitAccess": 1.08,
    "Disruption": 1.22,
    "ReconAttack": 1.26,
}
CLASS_WEIGHT_FLOORS = {
    "Benign": 0.85,
    "GenericAttack": 0.95,
    "ExploitAccess": 1.05,
    "Disruption": 1.30,
    "ReconAttack": 1.38,
}
CLASS_WEIGHT_CEILINGS = {
    "Benign": 0.95,
    "GenericAttack": 1.05,
    "ExploitAccess": 1.24,
    "Disruption": 1.48,
    "ReconAttack": 1.58,
}
FOCUS_CLASSES = ("ExploitAccess", "Disruption", "ReconAttack")
ROS_ONLY_CLASSES = {"Disruption", "ReconAttack"}
SMOTE_CLASSES = {"ExploitAccess"}
MIN_SMOTE_COUNT = 24


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
        "rounds": 18,
        "round_timeout": 180,
        "min_workers": 3,
        "epochs": 18,
        "batch_size": 128,
        "learning_rate": 0.001,
        "test_split": 0.2,
        "early_stopping_patience": 3,
        "focal_gamma": 1.5,
        "label_smoothing": 0.005,
        "fedprox_mu": 0.001,
        "categorical_encoding_enabled": True,
        "selected_numeric_features": [],
        "feature_selection_strategy": "global_fixed_shared",
        "feature_selection_enabled": True,
        "feature_selection_keep_ratio": 0.75,
        "feature_selection_min_features": 30,
        "feature_selection_max_features": 30,
        "feature_selection_variance_threshold": 1e-8,
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
def _target_size_for_class(class_name, class_count, majority_count):
    ratio = float(CLASS_TARGET_RATIOS.get(class_name, MINORITY_TARGET_RATIO))
    if ratio <= 0:
        return int(class_count)

    growth_ratio = float(CLASS_TARGET_GROWTH_RATIOS.get(class_name, 0.15))
    target = max(
        MINORITY_TARGET_FLOOR,
        int(np.ceil(majority_count * ratio)),
        int(np.ceil(class_count * (1.0 + growth_ratio))),
    )
    return int(target)


def _mutual_info_scores(X, y):
    return mutual_info_classif(X, y, random_state=SEED)


def _sanitize_feature_value(value):
    value = str(value).strip().lower()
    value = "".join(ch if ch.isalnum() else "_" for ch in value)
    value = "_".join(part for part in value.split("_") if part)
    return value or "other"


def _encode_categorical_columns(train_df, val_df, categorical_cols, cfg):
    if not cfg.get("categorical_encoding_enabled", True):
        return (
            np.empty((len(train_df), 0), dtype=np.float32),
            np.empty((len(val_df), 0), dtype=np.float32),
            [],
        )

    train_blocks, val_blocks, feature_names = [], [], []
    kept_logs = {}
    for col in categorical_cols:
        if col not in CATEGORICAL_VOCABS:
            continue
        kept_values = list(CATEGORICAL_VOCABS[col])
        categories = kept_values + ["__other__"]

        train_series = train_df[col].fillna("__other__").astype(str).str.strip().str.lower().replace("", "__other__")
        val_series = val_df[col].fillna("__other__").astype(str).str.strip().str.lower().replace("", "__other__")
        train_mapped = train_series.where(train_series.isin(kept_values), "__other__")
        val_mapped = val_series.where(val_series.isin(kept_values), "__other__")

        train_cat = pd.Categorical(train_mapped, categories=categories)
        val_cat = pd.Categorical(val_mapped, categories=categories)
        train_dummies = pd.get_dummies(train_cat, prefix=col, prefix_sep="__", dtype=np.float32)
        val_dummies = pd.get_dummies(val_cat, prefix=col, prefix_sep="__", dtype=np.float32)

        train_blocks.append(train_dummies.to_numpy(dtype=np.float32))
        val_blocks.append(val_dummies.to_numpy(dtype=np.float32))
        feature_names.extend([f"{col}__{_sanitize_feature_value(category)}" for category in categories])
        kept_logs[col] = kept_values

    if kept_logs:
        log.info(f"[algorithm] Categoricas activas (one-hot limitado + other): {kept_logs}")

    return (
        np.concatenate(train_blocks, axis=1) if train_blocks else np.empty((len(train_df), 0), dtype=np.float32),
        np.concatenate(val_blocks, axis=1) if val_blocks else np.empty((len(val_df), 0), dtype=np.float32),
        feature_names,
    )


def _apply_smote(X, y, num_classes):
    """Oversampling hibrido: SMOTE para clases coherentes y ROS para clases mas heterogeneas."""
    try:
        from imblearn.over_sampling import RandomOverSampler, SMOTE
        class_counts = np.bincount(y, minlength=num_classes)
        present_counts = class_counts[class_counts > 0]
        if present_counts.size == 0:
            return X, y
        majority_count = int(present_counts.max())

        ros_strategy = {}
        smote_strategy = {}
        target_debug = {}
        for cls_idx, count in enumerate(class_counts):
            if count <= 0 or count >= majority_count:
                continue
            class_name = ATTACK_CATEGORIES[cls_idx]
            target = _target_size_for_class(class_name, count, majority_count)
            target_debug[class_name] = {
                "current": int(count),
                "target": int(target),
                "method": "smote" if class_name in SMOTE_CLASSES else "ros",
            }
            if target <= count:
                continue
            if class_name in ROS_ONLY_CLASSES or count < MIN_SMOTE_COUNT:
                ros_strategy[cls_idx] = target
            elif class_name in SMOTE_CLASSES:
                smote_strategy[cls_idx] = target
            else:
                ros_strategy[cls_idx] = target

        if target_debug:
            log.info(f"[algorithm] Oversampling targets: {target_debug}")

        X_res, y_res = X, y
        if ros_strategy:
            ros = RandomOverSampler(sampling_strategy=ros_strategy, random_state=SEED)
            X_res, y_res = ros.fit_resample(X_res, y_res)
            log.info(
                f"[algorithm] RandomOverSampler: {len(X)} -> {len(X_res)} muestras "
                f"(clases reforzadas: {list(ros_strategy.keys())})"
            )

        class_counts = np.bincount(y_res, minlength=num_classes)
        smote_strategy = {
            cls_idx: target
            for cls_idx, target in smote_strategy.items()
            if class_counts[cls_idx] >= 6 and class_counts[cls_idx] < target
        }

        X_bal, y_bal = X_res, y_res
        if not ros_strategy and not smote_strategy:
            log.info("[algorithm] Oversampling no aplicado: ninguna clase minoritaria necesita refuerzo")
        if smote_strategy:
            min_smote_count = min(class_counts[c] for c in smote_strategy)
            sm = SMOTE(
                sampling_strategy=smote_strategy,
                random_state=SEED,
                k_neighbors=max(3, min(7, min_smote_count - 1)),
            )
            X_bal, y_bal = sm.fit_resample(X_bal, y_bal)
            log.info(
                f"[algorithm] SMOTE: {len(X_res)} -> {len(X_bal)} muestras "
                f"(clases oversampled: {list(smote_strategy.keys())})"
            )
        return X_bal, y_bal
    except Exception as e:
        log.warning(f"[algorithm] SMOTE no disponible, continuando sin oversample: {e}")
        return X, y


def _select_features(X_train, y_train, X_val, feature_cols, cfg):
    if not cfg.get("feature_selection_enabled", True):
        log.info("[algorithm] Feature selection desactivada por configuracion")
        return X_train, X_val, feature_cols

    if len(feature_cols) <= 1:
        return X_train, X_val, feature_cols

    try:
        variance_threshold = float(cfg.get("feature_selection_variance_threshold", 1e-8))
        vt = VarianceThreshold(threshold=variance_threshold)
        X_train_vt = vt.fit_transform(X_train)
        X_val_vt = vt.transform(X_val)
        vt_indices = vt.get_support(indices=True)
        vt_feature_cols = [feature_cols[idx] for idx in vt_indices]
        removed_low_variance = [feature_cols[idx] for idx in range(len(feature_cols)) if idx not in set(vt_indices)]
        if removed_low_variance:
            log.info(f"[algorithm] Features eliminadas por baja varianza: {removed_low_variance}")

        candidate_count = len(vt_feature_cols)
        if candidate_count <= 1:
            return X_train_vt, X_val_vt, vt_feature_cols

        keep_ratio = float(cfg.get("feature_selection_keep_ratio", 0.75))
        min_features = int(cfg.get("feature_selection_min_features", 30))
        max_features = int(cfg.get("feature_selection_max_features", 30))
        target_k = max(min_features, int(np.ceil(candidate_count * keep_ratio)))
        if max_features > 0:
            target_k = min(target_k, max_features)
        target_k = max(1, min(candidate_count, target_k))

        if target_k >= candidate_count:
            log.info(
                f"[algorithm] Feature selection: conservando {candidate_count}/{candidate_count} "
                "features tras el filtro de varianza"
            )
            return X_train_vt, X_val_vt, vt_feature_cols

        selector = SelectKBest(score_func=_mutual_info_scores, k=target_k)
        X_train_sel = selector.fit_transform(X_train_vt, y_train)
        X_val_sel = selector.transform(X_val_vt)
        selected_indices = selector.get_support(indices=True)
        selected_feature_cols = [vt_feature_cols[idx] for idx in selected_indices]
        scores = selector.scores_ if selector.scores_ is not None else np.zeros(candidate_count, dtype=np.float32)
        top_scores = sorted(
            [(vt_feature_cols[idx], float(scores[idx])) for idx in selected_indices],
            key=lambda item: item[1],
            reverse=True,
        )
        log.info(
            f"[algorithm] Feature selection: {len(feature_cols)} -> {len(selected_feature_cols)} "
            f"features (mutual_info, keep_ratio={keep_ratio})"
        )
        log.info(f"[algorithm] Features seleccionadas: {selected_feature_cols}")
        log.info(f"[algorithm] Top mutual_info: {[(name, round(score, 4)) for name, score in top_scores[:10]]}")
        return X_train_sel, X_val_sel, selected_feature_cols
    except Exception as e:
        log.warning(f"[algorithm] Feature selection no disponible, continuando sin seleccion: {e}")
        return X_train, X_val, feature_cols


def select_global_numeric_features(reference_csv_path, cfg=None):
    """
    Calcula una mascara global de variables numericas desde el training-set comun.
    Esta seleccion se hace una vez en el coordinator y luego se reparte a todos.
    """
    cfg = cfg or {}
    test_split = float(cfg.get("test_split", 0.2))

    df = pd.read_csv(reference_csv_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]

    if ATTACK_CAT_COL in df.columns:
        df[ATTACK_CAT_COL] = df[ATTACK_CAT_COL].fillna("Normal").astype(str).str.strip()
        df.loc[df[ATTACK_CAT_COL] == "", ATTACK_CAT_COL] = "Normal"
        grouped_attack = df[ATTACK_CAT_COL].map(_group_attack_category)
        y_series = grouped_attack.map(CAT_TO_IDX).fillna(0).astype(int)
    elif ATTACK_GROUP_COL in df.columns:
        grouped_attack = (
            df[ATTACK_GROUP_COL]
            .fillna("Benign")
            .astype(str)
            .str.strip()
            .map(_group_attack_category)
        )
        y_series = grouped_attack.map(CAT_TO_IDX).fillna(0).astype(int)
    else:
        if LABEL_COL not in df.columns:
            raise ValueError("No se puede calcular feature selection global sin etiquetas")
        y_series = pd.Series((df[LABEL_COL].values > 0).astype(int))

    available = [c for c in FEATURE_COLS if c in df.columns]
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

    X_train = X[train_idx]
    y_train = y[train_idx]
    X_val = X[val_idx]
    _, _, selected_feature_cols = _select_features(X_train, y_train, X_val, list(available), cfg)
    selected_feature_cols = [col for col in available if col in selected_feature_cols]
    log.info(
        f"[algorithm] Feature selection global desde referencia: "
        f"{len(available)} -> {len(selected_feature_cols)} numericas"
    )
    log.info(f"[algorithm] Variables numericas globales seleccionadas: {selected_feature_cols}")
    return selected_feature_cols


def _group_attack_category(value):
    raw = str(value).strip()
    if not raw:
        return "Benign"
    return ATTACK_GROUP_MAP.get(raw.lower(), "Benign")


def _select_tail_labels(y_values, present_labels):
    if not present_labels:
        return []
    class_counts = {
        int(label): int(np.sum(y_values == label))
        for label in present_labels
    }
    ordered = sorted(present_labels, key=lambda label: (class_counts[int(label)], int(label)))
    tail_k = max(1, int(np.ceil(len(ordered) * TAIL_CLASS_FRACTION)))
    cutoff = class_counts[int(ordered[min(tail_k - 1, len(ordered) - 1)])]
    return [int(label) for label in ordered if class_counts[int(label)] <= cutoff]


def load_unsw_nb15(data_path, test_split=0.2, cfg=None):
    """Carga y preprocesa particion local UNSW-NB15."""
    cfg = cfg or {}
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]

    if ATTACK_CAT_COL in df.columns:
        df[ATTACK_CAT_COL] = df[ATTACK_CAT_COL].fillna("Normal").astype(str).str.strip()
        df.loc[df[ATTACK_CAT_COL] == "", ATTACK_CAT_COL] = "Normal"
        grouped_attack = df[ATTACK_CAT_COL].map(_group_attack_category)
        df[ATTACK_GROUP_COL] = grouped_attack
        y_series = grouped_attack.map(CAT_TO_IDX).fillna(0).astype(int)
        num_classes = len(ATTACK_CATEGORIES)
        class_names = list(ATTACK_CATEGORIES)
        grouped_counts = grouped_attack.value_counts().to_dict()
        log.info(f"[algorithm] Modo MULTICLASE AGRUPADO detectado desde attack_cat ({num_classes} clases)")
        log.info(f"[algorithm] Grupos de ataque activos: {grouped_counts}")
    elif ATTACK_GROUP_COL in df.columns:
        df[ATTACK_GROUP_COL] = (
            df[ATTACK_GROUP_COL]
            .fillna("Benign")
            .astype(str)
            .str.strip()
            .map(_group_attack_category)
        )
        y_series = df[ATTACK_GROUP_COL].map(CAT_TO_IDX).fillna(0).astype(int)
        num_classes = len(ATTACK_CATEGORIES)
        class_names = list(ATTACK_CATEGORIES)
        grouped_counts = df[ATTACK_GROUP_COL].value_counts().to_dict()
        log.info(f"[algorithm] Modo MULTICLASE AGRUPADO detectado desde attack_group ({num_classes} clases)")
        log.info(f"[algorithm] Grupos de ataque activos: {grouped_counts}")
    else:
        if LABEL_COL not in df.columns:
            num_cols = df.select_dtypes(include="number").columns.tolist()
            df[LABEL_COL] = df[num_cols[-1]].astype(int)
        y_series = pd.Series((df[LABEL_COL].values > 0).astype(int))
        num_classes, class_names = 2, ["Normal", "Attack"]
        log.info("[algorithm] Modo BINARIO (fallback)")

    shared_numeric_features = cfg.get("selected_numeric_features") or SELECTED_NUMERIC_FEATURES
    available = [c for c in shared_numeric_features if c in df.columns]
    missing_selected = [c for c in shared_numeric_features if c not in df.columns]
    if missing_selected:
        log.warning(f"[algorithm] Variables numericas globales no encontradas: {missing_selected}")
    if not available:
        available = [c for c in df.select_dtypes(include="number").columns
                     if c not in (LABEL_COL, "id")]
    source_label = "runtime compartido" if cfg.get("selected_numeric_features") else "fallback compartido"
    log.info(
        f"[algorithm] Feature selection global ({source_label}): {len(available)} numericas "
        f"compartidas entre todos los workers"
    )
    log.info(f"[algorithm] Variables numericas seleccionadas: {available}")

    X_df = df[available].fillna(0).replace([np.inf, -np.inf], 0)
    for col in [c for c in LOG_TRANSFORM_COLS if c in X_df.columns]:
        X_df[col] = np.log1p(X_df[col].clip(lower=0))
    for col in X_df.columns:
        p99 = X_df[col].quantile(0.99)
        if p99 > 0:
            X_df[col] = X_df[col].clip(upper=p99)

    scaler = StandardScaler()
    X = np.nan_to_num(scaler.fit_transform(X_df.values).astype(np.float32))
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

    X_train_num, X_val_num = X[train_idx], X[val_idx]
    y_train, y_val = y[train_idx], y[val_idx]
    train_class_counts = np.bincount(y_train, minlength=num_classes).astype(np.int32)

    categorical_cols = [col for col in CATEGORICAL_COLS if col in df.columns]
    X_train_cat = np.empty((len(train_idx), 0), dtype=np.float32)
    X_val_cat = np.empty((len(val_idx), 0), dtype=np.float32)
    categorical_feature_cols = []
    if categorical_cols:
        X_train_cat, X_val_cat, categorical_feature_cols = _encode_categorical_columns(
            df.iloc[train_idx][categorical_cols],
            df.iloc[val_idx][categorical_cols],
            categorical_cols,
            cfg,
        )
        log.info(
            f"[algorithm] Columnas categoricas incorporadas al modelo: {categorical_cols} "
            f"({len(categorical_feature_cols)} features one-hot)"
        )
    else:
        log.info("[algorithm] No hay columnas categoricas adicionales disponibles para el modelo")

    X_train = X_train_num
    X_val = X_val_num
    if X_train_cat.shape[1] > 0:
        X_train = np.concatenate([X_train_num, X_train_cat], axis=1).astype(np.float32)
        X_val = np.concatenate([X_val_num, X_val_cat], axis=1).astype(np.float32)
        feature_cols = feature_cols + categorical_feature_cols

    # SMOTE en train solamente
    X_train, y_train = _apply_smote(X_train, y_train, num_classes)

    return (X_train, y_train, X_val, y_val,
            feature_cols, num_classes, class_names, train_class_counts)


def compute_training_class_weights(train_class_counts, class_names):
    """
    Pesos de clase basados en la distribucion original del train
    antes del oversampling. Se priorizan solo las clases realmente
    conflictivas para no sobre-optimizar Benign o GenericAttack.
    """
    counts = np.asarray(train_class_counts, dtype=np.float32)
    total = float(counts.sum())
    present_mask = counts > 0
    if total <= 0 or not np.any(present_mask):
        return None, None

    num_present = float(np.sum(present_mask))
    combined = np.ones_like(counts, dtype=np.float32)
    combined[present_mask] = total / (num_present * counts[present_mask])

    focus_boost = np.ones_like(counts, dtype=np.float32)
    for idx, class_name in enumerate(class_names):
        focus_boost[idx] = float(CLASS_FOCUS_BOOST.get(class_name, 1.0))
    combined *= focus_boost

    if np.any(present_mask):
        combined[present_mask] = combined[present_mask] / np.mean(combined[present_mask])

    for idx, class_name in enumerate(class_names):
        if not present_mask[idx]:
            continue
        floor = float(CLASS_WEIGHT_FLOORS.get(class_name, 0.9))
        ceiling = float(CLASS_WEIGHT_CEILINGS.get(class_name, 1.6))
        combined[idx] = float(np.clip(combined[idx], floor, ceiling))

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
def build_model(input_dim, num_classes, learning_rate=0.001,
                class_weights=None, total_steps=100,
                focal_gamma=1.5, label_smoothing=0.005,
                prox_mu=0.0):
    """
    DNN v2: 512->256->128->64->num_classes
    Con Focal Loss, Label Smoothing y FedProx.
    """
    inputs = keras.layers.Input(shape=(input_dim,), name="input_features")

    x = keras.layers.Dense(512, activation="relu", name="dense_1",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(inputs)
    x = keras.layers.BatchNormalization(name="bn_1")(x)
    x = keras.layers.Dropout(0.32, name="dropout_1")(x)

    x = keras.layers.Dense(256, activation="relu", name="dense_2",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(x)
    x = keras.layers.BatchNormalization(name="bn_2")(x)
    x = keras.layers.Dropout(0.24, name="dropout_2")(x)

    x = keras.layers.Dense(128, activation="relu", name="dense_3",
                           kernel_regularizer=keras.regularizers.l2(1e-4))(x)
    x = keras.layers.BatchNormalization(name="bn_3")(x)
    x = keras.layers.Dropout(0.16, name="dropout_3")(x)

    x = keras.layers.Dense(64, activation="relu", name="dense_4")(x)

    outputs = keras.layers.Dense(
        num_classes, activation="softmax", name="output"
    )(x)

    model = FedProxModel(
        inputs=inputs, outputs=outputs,
        name="fl_ids_multiclass_dnn_v4",
        prox_mu=prox_mu
    )

    # Focal Loss con class weights
    loss_fn = SparseFocalLoss(
        gamma=focal_gamma,
        class_weights=class_weights,
        label_smoothing=label_smoothing,
        num_classes=num_classes
    )

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
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
    focus_values = [
        float(report[class_name]["f1-score"])
        for class_name in FOCUS_CLASSES
        if class_name in report
    ]
    focus_f1 = float(np.mean(focus_values)) if focus_values else 0.0

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
        "focus_f1": round(focus_f1, 6),
        "f1_weighted": round(f1_w, 6), "mcc": round(mcc, 6),
        "num_classes": len(class_names),
        "classification_mode": "multiclass" if len(class_names) > 2 else "binary",
    }
    return metrics, cm.tolist(), per_class_f1, feat_imp


class ValidationMacroF1Callback(keras.callbacks.Callback):
    """Calcula macro-F1 por epoca y mantiene visible el rendimiento de la cola."""
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
        minority_labels = _select_tail_labels(self.y_val, present_labels)
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
        tail_names = [self.class_names[i] for i in minority_labels]
        focus_report = classification_report(
            self.y_val,
            y_pred,
            labels=present_labels,
            target_names=[self.class_names[i] for i in present_labels],
            output_dict=True,
            zero_division=0,
        )
        focus_values = [
            float(focus_report[class_name]["f1-score"])
            for class_name in FOCUS_CLASSES
            if class_name in focus_report
        ]
        focus_f1 = float(np.mean(focus_values)) if focus_values else 0.0
        logs["val_f1_macro"] = val_f1_macro
        logs["val_minority_f1"] = minority_f1
        logs["val_focus_f1"] = focus_f1
        log.info(
            f"[algorithm] epoch {epoch + 1}: "
            f"val_f1_macro={val_f1_macro:.4f} "
            f"val_minority_f1={minority_f1:.4f} "
            f"val_focus_f1={focus_f1:.4f} "
            f"tail_classes={tail_names}"
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
    label_smoothing = float(cfg.get("label_smoothing", 0.005))
    fedprox_mu = float(cfg.get("fedprox_mu", 0.005))

    X_train, y_train, X_val, y_val, feature_cols, num_classes, class_names, train_class_counts = \
        load_unsw_nb15(data_path, test_split, cfg)
    input_dim = X_train.shape[1]
    log.info(f"[algorithm] Dataset: {len(X_train)} train, {len(X_val)} val, "
             f"{input_dim} features, {num_classes} clases")

    cw_list, _ = compute_training_class_weights(train_class_counts, class_names)

    model = build_model(input_dim, num_classes, learning_rate,
                        class_weights=cw_list,
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
