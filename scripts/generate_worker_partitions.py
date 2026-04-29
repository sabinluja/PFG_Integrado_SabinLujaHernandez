"""
generate_worker_partitions.py
Recalcula attack_group para UNSW-NB15 con un esquema semantico de 5 clases y genera
particiones heterogeneas para 3 workers de FL.

Nuevo esquema multiclase:
  - Benign
  - GenericAttack
  - ExploitAccess   (Exploits + Analysis + Backdoor + Shellcode + Worms)
  - Disruption      (Fuzzers + DoS)
  - ReconAttack     (Reconnaissance)

Ademas de las features numericas, se conservan proto/state/service y sttl/dttl
para que el algoritmo pueda explotar mas senales del dataset.
"""
import pandas as pd
import numpy as np
import os

SEED = 42
np.random.seed(SEED)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RAW_DIR = os.path.join(PROJECT_DIR, "ia-dataapp", "data", "raw")
RAW_TRAIN_CSV = os.path.join(RAW_DIR, "UNSW_NB15_training-set.csv")
RAW_TEST_CSV = os.path.join(RAW_DIR, "UNSW_NB15_testing-set.csv")

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
CATEGORICAL_COLS = ["proto", "service", "state"]
KEEP_COLS = FEATURE_COLS + CATEGORICAL_COLS + ["attack_cat", "label", "attack_group"]
RAW_ATTACK_CATEGORIES = [
    "Normal", "Generic", "Exploits", "Fuzzers", "DoS",
    "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"
]
ATTACK_GROUPS = [
    "Benign", "GenericAttack", "ExploitAccess", "Disruption", "ReconAttack"
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
    # Compatibilidad por si el CSV ya venia agrupado.
    "probe": "ReconAttack",
    "malware": "ReconAttack",
    "otherattack": "ReconAttack",
    "groupedattacks": "ReconAttack",
}

# Reparto heterogeneo
WORKER_FRACTIONS = {1: 0.50, 2: 0.30, 3: 0.20}
WORKER_LABELS = {1: "Grande (50%)", 2: "Mediano (30%)", 3: "Pequeno (20%)"}


def _group_attack(value):
    raw = str(value).strip()
    if not raw:
        return "Benign"
    return ATTACK_GROUP_MAP.get(raw.lower(), "Benign")


def _prepare_unsw_dataframe(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]
    if "attack_cat" not in df.columns:
        raise ValueError(f"El CSV {csv_path} no contiene 'attack_cat'.")
    df["attack_cat"] = df["attack_cat"].fillna("Normal").astype(str).str.strip()
    df.loc[df["attack_cat"] == "", "attack_cat"] = "Normal"
    df["attack_group"] = df["attack_cat"].map(_group_attack)
    return df


def _print_distribution(df, label_col, labels, title):
    print(f"\n{title}:")
    counts = df[label_col].value_counts().reindex(labels, fill_value=0)
    total = max(len(df), 1)
    for label in labels:
        count = int(counts[label])
        pct = count / total * 100
        print(f"  {label:<20} {count:>7} ({pct:5.1f}%)")


def _rewrite_raw_csv(csv_path):
    df = _prepare_unsw_dataframe(csv_path)
    df.to_csv(csv_path, index=False)
    print(f"\nActualizado attack_group en {csv_path}")
    _print_distribution(df, "attack_group", ATTACK_GROUPS, "Distribucion agrupada (5 clases)")
    return df


def main():
    print(f"Leyendo y normalizando {RAW_TRAIN_CSV}...")
    df = _rewrite_raw_csv(RAW_TRAIN_CSV)
    print(f"  Total train: {len(df)} filas, {len(df.columns)} columnas")

    if os.path.exists(RAW_TEST_CSV):
        _rewrite_raw_csv(RAW_TEST_CSV)

    _print_distribution(df, "attack_cat", RAW_ATTACK_CATEGORIES, "Distribucion de clases original")
    _print_distribution(df, "attack_group", ATTACK_GROUPS, "Distribucion agrupada para el entrenamiento")

    available = [c for c in KEEP_COLS if c in df.columns]
    missing = [c for c in KEEP_COLS if c not in df.columns]
    if missing:
        print(f"\nWARNING: Columnas no encontradas: {missing}")
    df = df[available]

    print(f"\nGenerando particiones heterogeneas (seed={SEED})...")
    for wid in [1, 2, 3]:
        print(f"  Worker-{wid}: {WORKER_FRACTIONS[wid]:.0%} ({WORKER_LABELS[wid]})")

    worker_dfs = {1: [], 2: [], 3: []}
    for cat in sorted(df["attack_cat"].unique()):
        cat_df = df[df["attack_cat"] == cat].sample(frac=1, random_state=SEED).reset_index(drop=True)
        n = len(cat_df)
        n1 = int(n * WORKER_FRACTIONS[1])
        n2 = int(n * WORKER_FRACTIONS[2])
        worker_dfs[1].append(cat_df.iloc[:n1])
        worker_dfs[2].append(cat_df.iloc[n1:n1+n2])
        worker_dfs[3].append(cat_df.iloc[n1+n2:])

    for wid in [1, 2, 3]:
        worker_dfs[wid] = pd.concat(worker_dfs[wid], ignore_index=True).sample(
            frac=1, random_state=SEED+wid
        ).reset_index(drop=True)

    for wid in [1, 2, 3]:
        out_dir = os.path.join(PROJECT_DIR, "ia-dataapp", "data", f"worker{wid}", "input")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"unsw_nb15_worker_{wid}.csv")
        worker_dfs[wid].to_csv(out_path, index=False)

        print(f"\n  Worker-{wid}: {len(worker_dfs[wid])} filas -> {out_path}")
        _print_distribution(
            worker_dfs[wid],
            "attack_group",
            ATTACK_GROUPS,
            f"Distribucion agrupada worker-{wid}"
        )

    print("\nParticiones generadas correctamente.")
    print(f"  Columnas: {list(worker_dfs[1].columns)}")
    print(
        "  Features de entrada: "
        f"{len([c for c in worker_dfs[1].columns if c not in ['attack_cat', 'label', 'attack_group']])}"
    )


if __name__ == "__main__":
    main()
