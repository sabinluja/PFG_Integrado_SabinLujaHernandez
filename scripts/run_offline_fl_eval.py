"""
run_offline_fl_eval.py
Simula el entrenamiento federado de UNSW-NB15 en local, sin pasar por IDS/ECC,
y evalua el modelo global agregado en el conjunto de validacion combinado.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import numpy as np


PROJECT_DIR = Path(__file__).resolve().parents[1]
ALGO_PATH = PROJECT_DIR / "ia-dataapp" / "algorithm.py"
CONFIG_PATH = PROJECT_DIR / "ia-dataapp" / "fl_config.json"
OUTPUT_DIR = PROJECT_DIR / "ia-dataapp" / "data" / "worker2" / "output"
WORKER_PATHS = [
    PROJECT_DIR / "ia-dataapp" / "data" / "worker1" / "input" / "unsw_nb15_worker_1.csv",
    PROJECT_DIR / "ia-dataapp" / "data" / "worker2" / "input" / "unsw_nb15_worker_2.csv",
    PROJECT_DIR / "ia-dataapp" / "data" / "worker3" / "input" / "unsw_nb15_worker_3.csv",
]


def load_algorithm():
    spec = importlib.util.spec_from_file_location("algorithm_offline", ALGO_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fedavg(algo, results):
    total = sum(r["n_samples"] for r in results)
    aggregated = None
    for result in results:
        weights = algo.b64_to_weights(result["weights_b64"])
        scale = result["n_samples"] / total
        if aggregated is None:
            aggregated = [layer * scale for layer in weights]
        else:
            for idx, layer in enumerate(weights):
                aggregated[idx] += layer * scale
    return algo.weights_to_b64(aggregated)


def evaluate_global_model(algo, global_weights_b64, cfg):
    X_vals = []
    y_vals = []
    class_names = None
    input_dim = None
    num_classes = None

    for csv_path in WORKER_PATHS:
        _, _, X_val, y_val, _, local_num_classes, local_class_names, _ = algo.load_unsw_nb15(
            str(csv_path),
            float(cfg["test_split"]),
        )
        X_vals.append(X_val)
        y_vals.append(y_val)
        class_names = local_class_names
        input_dim = int(X_val.shape[1])
        num_classes = int(local_num_classes)

    X_eval = np.vstack(X_vals)
    y_eval = np.concatenate(y_vals)

    model = algo.build_model(
        input_dim=input_dim,
        num_classes=num_classes,
        learning_rate=float(cfg["learning_rate"]),
        class_weights=None,
        total_steps=1,
        focal_gamma=float(cfg.get("focal_gamma", 1.25)),
        label_smoothing=float(cfg.get("label_smoothing", 0.02)),
        prox_mu=float(cfg.get("fedprox_mu", 0.005)),
    )
    model.set_weights(algo.b64_to_weights(global_weights_b64))
    metrics, cm, per_class_report, _ = algo.compute_full_metrics(model, X_eval, y_eval, class_names)
    return {
        "metrics": metrics,
        "confusion_matrix": cm,
        "per_class_report": per_class_report,
        "class_names": class_names,
        "val_samples": int(len(y_eval)),
    }


def main():
    algo = load_algorithm()
    cfg = algo.load_config(str(CONFIG_PATH))
    rounds = int(cfg["rounds"])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    global_weights_b64 = None
    history = []
    best_round = None
    best_payload = None
    best_f1 = -1.0
    best_acc = -1.0

    print(f"Offline FL sobre {len(WORKER_PATHS)} workers, {rounds} rondas")
    for round_num in range(1, rounds + 1):
        round_start = time.time()
        local_results = []
        for worker_idx, csv_path in enumerate(WORKER_PATHS, start=1):
            print(f"  Ronda {round_num} -> worker{worker_idx}: {csv_path.name}")
            result = algo.run(
                str(csv_path),
                global_weights_b64=global_weights_b64,
                config_path=str(CONFIG_PATH),
            )
            local_results.append(result)

        global_weights_b64 = fedavg(algo, local_results)
        global_eval = evaluate_global_model(algo, global_weights_b64, cfg)

        metrics = global_eval["metrics"]
        elapsed = round(time.time() - round_start, 2)
        total_samples = sum(result["n_samples"] for result in local_results)
        history.append(
            {
                "round": round_num,
                "workers_ok": len(local_results),
                "total_samples": total_samples,
                "elapsed_seconds": elapsed,
                "global_metrics": metrics,
            }
        )
        print(
            "    "
            f"acc={metrics['accuracy']:.4f} "
            f"auc={metrics['auc']:.4f} "
            f"f1_macro={metrics['f1_macro']:.4f} "
            f"mcc={metrics['mcc']:.4f} "
            f"tail={global_eval['per_class_report'].get('OtherAttack', 0.0):.4f}"
        )

        current_f1 = float(metrics.get("f1_macro", 0.0))
        current_acc = float(metrics.get("accuracy", 0.0))
        if current_f1 > best_f1 or (current_f1 == best_f1 and current_acc > best_acc):
            best_f1 = current_f1
            best_acc = current_acc
            best_round = round_num
            best_payload = {
                "round": round_num,
                "weights_b64": global_weights_b64,
                "metrics": metrics,
                "per_class_report": global_eval["per_class_report"],
                "confusion_matrix": global_eval["confusion_matrix"],
                "class_names": global_eval["class_names"],
                "num_classes": len(global_eval["class_names"]),
                "val_samples": global_eval["val_samples"],
            }

    results_path = OUTPUT_DIR / "offline_fl_results_5class.json"
    model_path = OUTPUT_DIR / "offline_global_model_5class.json"
    summary_path = OUTPUT_DIR / "offline_fl_summary_5class.json"

    results_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    model_path.write_text(json.dumps(best_payload, indent=2), encoding="utf-8")
    summary_path.write_text(
        json.dumps(
            {
                "config_path": str(CONFIG_PATH),
                "worker_paths": [str(path) for path in WORKER_PATHS],
                "best_round": best_round,
                "best_metrics": best_payload["metrics"] if best_payload else {},
                "class_names": best_payload["class_names"] if best_payload else [],
                "per_class_report": best_payload["per_class_report"] if best_payload else {},
                "history_path": str(results_path),
                "model_path": str(model_path),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nMejor ronda:")
    print(summary_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
