#!/usr/bin/env python3
"""
pfg_fl_grid_search.py -- Grid search practico sobre el flujo FL existente
==========================================================================
python scripts/pfg_fl_grid_search.py --coordinator 2 --objective f1_macro --rounds 10,12 --epochs 10, 15, 20 --learning-rates 0.0005,0.001,0.0015 --batch-sizes 128 --patience 3 --focal-gammas 1.5 --label-smoothing 0.05 --fedprox-mus 0.0

Objetivo:
  - Probar varias combinaciones de hiperparametros FL
  - Reutilizar el despliegue actual (DataApps + ECC + Broker)
  - Guardar un resumen ordenado por la metrica objetivo

Importante:
  Este runner esta pensado para usar la distribucion del algoritmo/config
  via IDS base64 (FL_ALGO_VIA_DOCKER=false). En modo Docker-image el
  algoritmo y la config quedan "horneados" en la imagen y no se pueden
  variar por trial de forma ligera.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import socket
import sys
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import HTTPError, RequestException


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
IA_DIR = ROOT / "ia-dataapp"
BASE_CONFIG_PATH = IA_DIR / "fl_config.json"
ALGO_SOURCE_PATH = IA_DIR / "algorithm.py"
OUTPUT_ROOT = SCRIPT_DIR / "grid_search_results"
ENV_PATH = ROOT / ".env"


SESSION = requests.Session()
SESSION.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def info(msg: str):
    print(f"[INFO] {msg}")


def warn(msg: str):
    print(f"[WARN] {msg}")


def die(msg: str, code: int = 1):
    print(f"[ERR ] {msg}")
    sys.exit(code)


def parse_args():
    ap = argparse.ArgumentParser(description="Grid search del entrenamiento federado")
    ap.add_argument("--coordinator", type=int, default=2, help="Worker coordinador")
    ap.add_argument("--timeout", type=int, default=240, help="Timeout HTTP por peticion")
    ap.add_argument("--poll-seconds", type=int, default=10, help="Intervalo de polling /fl/status")
    ap.add_argument("--trial-timeout", type=int, default=5400, help="Timeout maximo por trial")
    ap.add_argument("--objective", default="f1_macro",
                    choices=["accuracy", "auc", "precision", "recall", "f1_macro", "f1_weighted", "mcc", "loss"],
                    help="Metrica usada para ordenar el grid search")
    ap.add_argument("--workers", default="1,2,3,4",
                    help="Lista de workers a resetear por trial")
    ap.add_argument("--rounds", default="5,10,15", help="Lista CSV de rounds")
    ap.add_argument("--epochs", default="10,15,20", help="Lista CSV de epochs locales")
    ap.add_argument("--learning-rates", default="0.0005,0.001,0.002", help="Lista CSV de learning rates")
    ap.add_argument("--batch-sizes", default="128", help="Lista CSV de batch sizes")
    ap.add_argument("--patience", default="3", help="Lista CSV de early stopping patience")
    ap.add_argument("--focal-gammas", default="1.5", help="Lista CSV de focal gamma")
    ap.add_argument("--label-smoothing", default="0.05", help="Lista CSV de label smoothing")
    ap.add_argument("--fedprox-mus", default="0.0, 0.05", help="Lista CSV de FedProx mu")
    ap.add_argument("--min-workers", type=int, default=2, help="min_workers para cada trial")
    ap.add_argument("--limit", type=int, default=0, help="Limitar numero de trials (0 = todos)")
    return ap.parse_args()


def parse_list(raw: str, caster):
    return [caster(x.strip()) for x in raw.split(",") if x.strip()]


def coordinator_url(cid: int) -> str:
    return f"https://localhost:{5000 + cid}"


def load_env_flags() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_PATH.exists():
        return values
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


def http_get(url: str, timeout: int):
    r = SESSION.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def http_post(url: str, body: dict, timeout: int):
    r = SESSION.post(url, json=body, timeout=timeout)
    r.raise_for_status()
    return r.json()


def is_transient_http_error(exc: Exception) -> bool:
    if isinstance(exc, (RequestsConnectionError, requests.Timeout)):
        return True
    if isinstance(exc, RequestException):
        msg = str(exc).lower()
        transient_tokens = (
            "remote end closed connection",
            "remotedisconnected",
            "connection aborted",
            "max retries exceeded",
            "temporarily unavailable",
            "temporary failure in name resolution",
            "failed to resolve",
            "connection reset",
            "502",
            "503",
            "504",
        )
        return any(token in msg for token in transient_tokens)
    if isinstance(exc, (ConnectionResetError, socket.gaierror, TimeoutError)):
        return True
    return False


def wait_for_idle(base_url: str, timeout: int, max_wait: int = 60, stable_reads: int = 2):
    start = time.time()
    stable = 0
    last_error = None
    while time.time() - start <= max_wait:
        try:
            status = http_get(f"{base_url}/fl/status", timeout)
            if status.get("status") == "idle" and int(status.get("current_round", 0) or 0) == 0:
                stable += 1
                if stable >= stable_reads:
                    return status
            else:
                stable = 0
            last_error = None
        except Exception as exc:
            last_error = exc
            stable = 0
        time.sleep(2)
    raise TimeoutError(f"No se alcanzo estado idle estable en {max_wait}s ({last_error})")


def wait_for_coordinator_role(base_url: str, timeout: int, max_wait: int = 30):
    start = time.time()
    last = None
    while time.time() - start <= max_wait:
        try:
            status = http_get(f"{base_url}/status", timeout)
            last = status
            if status.get("role") == "coordinator" and status.get("algorithm_loaded"):
                return status
        except Exception as exc:
            last = {"error": str(exc)}
        time.sleep(2)
    raise TimeoutError(f"El coordinator no quedo listo tras /fl/fetch-algorithm ({last})")


def post_with_retry(url: str, body: dict, timeout: int, retries: int = 3, delay: int = 3):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return http_post(url, body, timeout)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries or not is_transient_http_error(exc):
                raise
            warn(f"retry POST {url} intento {attempt}/{retries} tras error transitorio: {exc}")
            time.sleep(delay * attempt)
    raise last_exc


def get_with_retry(url: str, timeout: int, retries: int = 3, delay: int = 2):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return http_get(url, timeout)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries or not is_transient_http_error(exc):
                raise
            warn(f"retry GET {url} intento {attempt}/{retries} tras error transitorio: {exc}")
            time.sleep(delay * attempt)
    raise last_exc


def reset_workers(worker_ids: list[int], timeout: int):
    for wid in worker_ids:
        url = f"https://localhost:{5000 + wid}/system/reset"
        try:
            http_post(url, {}, timeout)
            info(f"worker-{wid} reseteado")
        except Exception as exc:
            warn(f"no se pudo resetear worker-{wid}: {exc}")


def ensure_local_algorithm_and_config(coord_id: int, trial_cfg: dict):
    worker_dir = IA_DIR / "data" / f"worker{coord_id}"
    worker_dir.mkdir(parents=True, exist_ok=True)

    algo_target = worker_dir / "algorithm.py"
    cfg_target = worker_dir / "fl_config.json"

    algo_target.write_text(ALGO_SOURCE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    cfg_target.write_text(json.dumps(trial_cfg, indent=2), encoding="utf-8")

    return algo_target, cfg_target


def run_trial(
    trial_id: int,
    cfg: dict,
    coord_id: int,
    worker_ids: list[int],
    timeout: int,
    poll_seconds: int,
    trial_timeout: int,
    output_dir: Path,
):
    base_url = coordinator_url(coord_id)
    trial_name = f"trial_{trial_id:02d}"
    info(f"{trial_name}: rounds={cfg['rounds']} epochs={cfg['epochs']} lr={cfg['learning_rate']} "
         f"batch={cfg['batch_size']} patience={cfg['early_stopping_patience']} "
         f"gamma={cfg['focal_gamma']} ls={cfg['label_smoothing']} prox={cfg.get('fedprox_mu', 0.0)}")

    reset_workers(worker_ids, timeout)
    wait_for_idle(base_url, timeout, max_wait=90)

    fetch = post_with_retry(f"{base_url}/fl/fetch-algorithm", {}, timeout, retries=3, delay=3)
    info(f"{trial_name}: coordinator listo, modo={fetch.get('delivery_mode', '?')}")

    algo_target, cfg_target = ensure_local_algorithm_and_config(coord_id, cfg)
    info(f"{trial_name}: algorithm sincronizado en {algo_target}")
    info(f"{trial_name}: config sincronizada en {cfg_target}")
    wait_for_coordinator_role(base_url, timeout, max_wait=30)

    discover = post_with_retry(f"{base_url}/broker/discover", {}, timeout, retries=3, delay=3)
    compatible = discover.get("compatible_workers", [])
    info(f"{trial_name}: compatibles detectados={len(compatible)}")

    if not compatible:
        raise RuntimeError(f"{trial_name}: /broker/discover no encontro workers compatibles")

    negotiate = post_with_retry(f"{base_url}/fl/negotiate", {}, timeout, retries=3, delay=3)
    accepted = negotiate.get("accepted", [])
    rejected = negotiate.get("rejected", [])
    info(f"{trial_name}: aceptados={len(accepted)} rechazados={len(rejected)}")

    if not accepted:
        return {
            "trial_id": trial_id,
            "config": cfg,
            "status": "failed",
            "error": "No hay workers aceptados tras /fl/negotiate",
            "accepted_workers": 0,
            "rejected_workers": len(rejected),
        }

    start_resp = post_with_retry(f"{base_url}/fl/start", {}, timeout, retries=3, delay=3)
    info(f"{trial_name}: entrenamiento arrancado")

    started_at = time.time()
    last_status = {}
    transient_status_errors = 0
    while True:
        time.sleep(poll_seconds)
        try:
            last_status = get_with_retry(f"{base_url}/fl/status", timeout, retries=2, delay=2)
            transient_status_errors = 0
        except Exception as exc:
            if not is_transient_http_error(exc):
                raise
            transient_status_errors += 1
            warn(f"{trial_name}: error transitorio consultando /fl/status ({transient_status_errors}): {exc}")
            if transient_status_errors >= 6:
                raise RuntimeError(f"{trial_name}: demasiados fallos transitorios en /fl/status: {exc}")
            continue
        status = last_status.get("status", "unknown")
        current_round = last_status.get("current_round", 0)
        total_rounds = last_status.get("total_rounds", cfg["rounds"])
        info(f"{trial_name}: estado={status} ronda={current_round}/{total_rounds}")

        if status == "completed":
            # Confirmar que el coordinador ha terminado de persistir historial.
            time.sleep(3)
            break
        if status == "failed":
            break
        if time.time() - started_at > trial_timeout:
            raise TimeoutError(f"{trial_name}: timeout esperando completion")

    results = get_with_retry(f"{base_url}/fl/results", timeout, retries=3, delay=2)
    results_path = output_dir / f"{trial_name}_results.json"
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if not isinstance(results, list) or not results:
        return {
            "trial_id": trial_id,
            "config": cfg,
            "status": last_status.get("status", "unknown"),
            "error": "Sin historial de resultados",
            "accepted_workers": len(accepted),
            "rejected_workers": len(rejected),
        }

    return {
        "trial_id": trial_id,
        "config": cfg,
        "status": last_status.get("status", "completed"),
        "accepted_workers": len(accepted),
        "rejected_workers": len(rejected),
        "history": results,
        "results_file": str(results_path),
        "start_response": start_resp,
    }


def summarize_trial(trial: dict, objective: str) -> dict:
    summary = {
        "trial_id": trial["trial_id"],
        "status": trial.get("status", "unknown"),
        "accepted_workers": trial.get("accepted_workers", 0),
        "rejected_workers": trial.get("rejected_workers", 0),
        "config": trial.get("config", {}),
    }
    history = trial.get("history") or []
    if not history:
        summary["objective_value"] = float("-inf")
        summary["error"] = trial.get("error", "Sin historial")
        return summary

    best_obj_row = max(history, key=lambda r: r.get("global_metrics", {}).get(objective, float("-inf")))
    best_acc_row = max(history, key=lambda r: r.get("global_metrics", {}).get("accuracy", float("-inf")))
    last_row = history[-1]

    summary.update({
        "objective": objective,
        "objective_value": best_obj_row.get("global_metrics", {}).get(objective, float("-inf")),
        "best_objective_round": best_obj_row.get("round"),
        "best_objective_metrics": best_obj_row.get("global_metrics", {}),
        "best_accuracy_round": best_acc_row.get("round"),
        "best_accuracy_metrics": best_acc_row.get("global_metrics", {}),
        "last_round": last_row.get("round"),
        "last_metrics": last_row.get("global_metrics", {}),
        "elapsed_last_round": last_row.get("elapsed_seconds"),
        "results_file": trial.get("results_file"),
    })
    return summary


def build_trial_configs(args) -> list[dict]:
    base_cfg = json.loads(BASE_CONFIG_PATH.read_text(encoding="utf-8"))
    rounds = parse_list(args.rounds, int)
    epochs = parse_list(args.epochs, int)
    learning_rates = parse_list(args.learning_rates, float)
    batch_sizes = parse_list(args.batch_sizes, int)
    patience = parse_list(args.patience, int)
    focal_gammas = parse_list(args.focal_gammas, float)
    label_smoothing = parse_list(args.label_smoothing, float)
    fedprox_mus = parse_list(args.fedprox_mus, float)

    configs = []
    for combo in itertools.product(
        rounds,
        epochs,
        learning_rates,
        batch_sizes,
        patience,
        focal_gammas,
        label_smoothing,
        fedprox_mus,
    ):
        cfg = deepcopy(base_cfg)
        (
            cfg["rounds"],
            cfg["epochs"],
            cfg["learning_rate"],
            cfg["batch_size"],
            cfg["early_stopping_patience"],
            cfg["focal_gamma"],
            cfg["label_smoothing"],
            cfg["fedprox_mu"],
        ) = combo
        cfg["round_timeout"] = max(int(base_cfg.get("round_timeout", 360)), 360)
        cfg["min_workers"] = int(args.min_workers)
        configs.append(cfg)

    if args.limit and args.limit > 0:
        configs = configs[:args.limit]
    return configs


def write_summary_csv(rows: list[dict], path: Path):
    fieldnames = [
        "rank",
        "trial_id",
        "status",
        "objective",
        "objective_value",
        "best_objective_round",
        "best_accuracy_round",
        "accepted_workers",
        "rejected_workers",
        "rounds",
        "epochs",
        "learning_rate",
        "batch_size",
        "early_stopping_patience",
        "focal_gamma",
        "label_smoothing",
        "fedprox_mu",
        "last_accuracy",
        "last_auc",
        "last_f1_macro",
        "last_mcc",
        "results_file",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for idx, row in enumerate(rows, start=1):
            cfg = row.get("config", {})
            last = row.get("last_metrics", {})
            writer.writerow({
                "rank": idx,
                "trial_id": row.get("trial_id"),
                "status": row.get("status"),
                "objective": row.get("objective"),
                "objective_value": row.get("objective_value"),
                "best_objective_round": row.get("best_objective_round"),
                "best_accuracy_round": row.get("best_accuracy_round"),
                "accepted_workers": row.get("accepted_workers"),
                "rejected_workers": row.get("rejected_workers"),
                "rounds": cfg.get("rounds"),
                "epochs": cfg.get("epochs"),
                "learning_rate": cfg.get("learning_rate"),
                "batch_size": cfg.get("batch_size"),
                "early_stopping_patience": cfg.get("early_stopping_patience"),
                "focal_gamma": cfg.get("focal_gamma"),
                "label_smoothing": cfg.get("label_smoothing"),
                "fedprox_mu": cfg.get("fedprox_mu"),
                "last_accuracy": last.get("accuracy"),
                "last_auc": last.get("auc"),
                "last_f1_macro": last.get("f1_macro"),
                "last_mcc": last.get("mcc"),
                "results_file": row.get("results_file"),
            })


def main():
    args = parse_args()
    env_flags = load_env_flags()
    if env_flags.get("FL_ALGO_VIA_DOCKER", "").lower() == "true":
        die(
            "FL_ALGO_VIA_DOCKER=true en .env. Para este grid search debes ponerlo a false y reiniciar "
            "los DataApps, porque en modo Docker la imagen del algoritmo se hornea antes de cada trial."
        )

    worker_ids = parse_list(args.workers, int)
    if args.coordinator not in worker_ids:
        worker_ids.append(args.coordinator)
        worker_ids.sort()

    trial_configs = build_trial_configs(args)
    if not trial_configs:
        die("No hay combinaciones de hiperparametros para ejecutar.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_ROOT / f"grid_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    info(f"Grid search con {len(trial_configs)} trial(s)")
    info(f"Resultados en: {run_dir}")

    raw_trials = []
    for idx, cfg in enumerate(trial_configs, start=1):
        try:
            raw = run_trial(
                trial_id=idx,
                cfg=cfg,
                coord_id=args.coordinator,
                worker_ids=worker_ids,
                timeout=args.timeout,
                poll_seconds=args.poll_seconds,
                trial_timeout=args.trial_timeout,
                output_dir=run_dir,
            )
        except Exception as exc:
            raw = {
                "trial_id": idx,
                "config": cfg,
                "status": "failed",
                "error": str(exc),
                "accepted_workers": 0,
                "rejected_workers": 0,
            }
            warn(f"trial_{idx:02d} fallo: {exc}")
        raw_trials.append(raw)
        # Asegurar que el coordinador vuelve a un estado limpio antes del siguiente trial.
        try:
            reset_workers(worker_ids, args.timeout)
            wait_for_idle(coordinator_url(args.coordinator), args.timeout, max_wait=90)
        except Exception as cleanup_exc:
            warn(f"post-trial cleanup tras trial_{idx:02d} incompleto: {cleanup_exc}")

    summaries = [summarize_trial(t, args.objective) for t in raw_trials]
    ranked = sorted(
        summaries,
        key=lambda r: (
            r.get("status") == "completed",
            r.get("objective_value", float("-inf")),
            r.get("best_accuracy_metrics", {}).get("accuracy", float("-inf")),
        ),
        reverse=True,
    )

    (run_dir / "trial_summaries.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    (run_dir / "trial_ranked.json").write_text(json.dumps(ranked, indent=2), encoding="utf-8")
    write_summary_csv(ranked, run_dir / "trial_ranked.csv")

    print()
    print("=" * 92)
    print("GRID SEARCH -- RANKING FINAL")
    print("=" * 92)
    print(f"{'Rank':>4} {'Trial':>5} {'Status':>10} {'Obj':>10} {'Valor':>10} {'Rounds':>6} {'Epochs':>6} {'LR':>8} {'Pat':>4}")
    print("-" * 92)
    for rank, row in enumerate(ranked, start=1):
        cfg = row.get("config", {})
        print(
            f"{rank:>4} {row.get('trial_id', '?'):>5} {row.get('status', '?'):>10} "
            f"{args.objective:>10} {row.get('objective_value', float('-inf')):>10.6f} "
            f"{cfg.get('rounds', '?'):>6} {cfg.get('epochs', '?'):>6} "
            f"{cfg.get('learning_rate', '?'):>8} {cfg.get('early_stopping_patience', '?'):>4}"
        )

    if ranked:
        best = ranked[0]
        print()
        print("Mejor configuracion encontrada:")
        print(json.dumps(best, indent=2))
        (run_dir / "best_config.json").write_text(json.dumps(best, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
