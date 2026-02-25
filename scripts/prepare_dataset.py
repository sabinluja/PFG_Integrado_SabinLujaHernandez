"""
prepare_dataset.py
==================
Prepara UNSW-NB15 para 3 workers de Federated Learning.
Requiere que ya exista:

    ia-dataapp/data/raw/UNSW_NB15_training-set.csv

Ejecutar:
    python3 prepare_dataset.py
"""

import os
import pandas as pd
import numpy as np

# ── Configuración ─────────────────────────────────────────────
OUTPUT_DIR = os.path.join("ia-dataapp", "data", "input")
RAW_DIR    = os.path.join("ia-dataapp", "data", "raw")
CSV_FILE   = "UNSW_NB15_training-set.csv"

N_WORKERS  = 3
RANDOM_SEED = 42

SELECTED_FEATURES = [
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
    "is_sm_ips_ports", "label"
]


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.lower().strip() for c in df.columns]

    # Crear label si no existe
    if "label" not in df.columns:
        if "attack_cat" in df.columns:
            df["label"] = (df["attack_cat"].str.strip() != "Normal").astype(int)
        else:
            raise ValueError("No se encontró columna 'label'")

    df["label"] = df["label"].astype(int)

    cols_available = [c for c in SELECTED_FEATURES if c in df.columns]
    df = df[cols_available].copy()

    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    for col in df.columns:
        if df[col].dtype == object:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    print(f"Dataset limpio: {len(df)} filas")
    print(f"Balance: {df['label'].value_counts().to_dict()}")

    return df


def partition_non_iid(df: pd.DataFrame, n_workers: int = 3):
    normal = df[df["label"] == 0]
    attacks = df[df["label"] == 1]

    normal = normal.sample(frac=1, random_state=RANDOM_SEED)
    attacks = attacks.sample(frac=1, random_state=RANDOM_SEED)

    n_each = len(normal) // n_workers
    normal_parts = [
        normal.iloc[i * n_each:(i + 1) * n_each]
        for i in range(n_workers)
    ]

    proportions = [0.50, 0.30, 0.20]
    n_atk = len(attacks)
    boundaries = [0] + [int(sum(proportions[:i+1]) * n_atk) for i in range(n_workers)]
    attack_parts = [
        attacks.iloc[boundaries[i]:boundaries[i+1]]
        for i in range(n_workers)
    ]

    partitions = []
    for i in range(n_workers):
        part = pd.concat([normal_parts[i], attack_parts[i]])
        part = part.sample(frac=1, random_state=RANDOM_SEED + i).reset_index(drop=True)
        partitions.append(part)

    return partitions


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    csv_path = os.path.join(RAW_DIR, CSV_FILE)

    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"No se encontró {csv_path}\n"
            "Coloca UNSW_NB15_training-set.csv en ia-dataapp/data/raw/"
        )

    print("Cargando dataset...")
    df = pd.read_csv(csv_path, low_memory=False)
    df = clean_dataset(df)

    print("Particionando NON-IID...")
    partitions = partition_non_iid(df, N_WORKERS)

    for i, part in enumerate(partitions, start=1):
        out_path = os.path.join(OUTPUT_DIR, f"unsw_nb15_worker_{i}.csv")
        part.to_csv(out_path, index=False)
        balance = part["label"].value_counts().to_dict()
        print(f"Worker {i}: {len(part)} muestras | {balance}")

    print("\n✅ Dataset listo. Ejecuta:")
    print("   docker-compose up --build")


if __name__ == "__main__":
    main()