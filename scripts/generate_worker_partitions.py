"""
generate_worker_partitions.py
Genera particiones estratificadas del UNSW-NB15 training set para 3 workers de FL.
Incluye attack_cat para clasificacion multiclase.

Reparto HETEROGENEO (realista):
  Worker-1: 50% (organizacion grande, e.g. hospital central)
  Worker-2: 30% (organizacion mediana)
  Worker-3: 20% (organizacion pequena, e.g. clinica rural)

Cada worker ve los MISMOS tipos de ataque pero en distinta cantidad.
Esto simula un escenario real de Federated Learning con data heterogeneity.
"""
import pandas as pd
import numpy as np
import os

SEED = 42
np.random.seed(SEED)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RAW_CSV = os.path.join(PROJECT_DIR, "ia-dataapp", "data", "raw", "UNSW_NB15_training-set.csv")

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

KEEP_COLS = FEATURE_COLS + ["attack_cat", "label"]

ATTACK_CATEGORIES = [
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
    "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms"
]

# Reparto heterogeneo
WORKER_FRACTIONS = {1: 0.50, 2: 0.30, 3: 0.20}
WORKER_LABELS = {1: "Grande (50%)", 2: "Mediano (30%)", 3: "Pequeno (20%)"}


def main():
    print(f"Leyendo {RAW_CSV}...")
    df = pd.read_csv(RAW_CSV, low_memory=False)
    df.columns = [c.lower().strip() for c in df.columns]
    print(f"  Total: {len(df)} filas, {len(df.columns)} columnas")

    if "attack_cat" not in df.columns:
        raise ValueError("El CSV raw no contiene 'attack_cat'.")

    df["attack_cat"] = df["attack_cat"].fillna("Normal").astype(str).str.strip()
    df.loc[df["attack_cat"] == "", "attack_cat"] = "Normal"

    print("\nDistribucion de clases en el dataset completo:")
    class_counts = df["attack_cat"].value_counts().reindex(ATTACK_CATEGORIES, fill_value=0)
    for cat in ATTACK_CATEGORIES:
        count = class_counts[cat]
        pct = count / len(df) * 100
        print(f"  {cat:<20} {count:>7} ({pct:5.1f}%)")

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
        w_counts = worker_dfs[wid]["attack_cat"].value_counts().reindex(ATTACK_CATEGORIES, fill_value=0)
        for cat in ATTACK_CATEGORIES:
            count = w_counts[cat]
            pct = count / len(worker_dfs[wid]) * 100
            print(f"    {cat:<20} {count:>6} ({pct:5.1f}%)")

    print("\nParticiones generadas correctamente.")
    print(f"  Columnas: {list(worker_dfs[1].columns)}")
    print(f"  Features numericas: {len([c for c in worker_dfs[1].columns if c not in ['attack_cat', 'label']])}")


if __name__ == "__main__":
    main()
