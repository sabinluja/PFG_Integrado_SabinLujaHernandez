"""
baseline_train.py -- Local worker baselines for MLflow comparison
=================================================================

This MLflow Project trains local No-FL baselines without sharing data between
workers. In the default mode it creates three independent MLflow runs:

  - worker-1 trains only with unsw_nb15_worker_1.csv
  - worker-2 trains only with unsw_nb15_worker_2.csv
  - worker-3 trains only with unsw_nb15_worker_3.csv

It uses the same DNN algorithm as the IDS federated pipeline: same preprocessing,
feature selection, categorical encoding, oversampling, model and metrics.
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pandas as pd

os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "10")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "3")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_BACKOFF_FACTOR", "1")
os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

import mlflow  # type: ignore

sys.path.insert(0, "/app")
import algorithm  # type: ignore  # noqa: E402

log = logging.getLogger("local_worker_baseline")


@dataclass
class DatasetJob:
    label: str
    worker_id: str
    source_path: str
    dataframe: pd.DataFrame


def parse_args():
    p = argparse.ArgumentParser(
        description="Train local No-FL worker baselines for MLflow comparison.",
    )
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--batch-size", type=int, default=128)
    p.add_argument("--learning-rate", type=float, default=0.001)
    p.add_argument("--focal-gamma", type=float, default=1.5)
    p.add_argument("--label-smoothing", type=float, default=0.005)
    p.add_argument("--test-split", type=float, default=0.2)
    p.add_argument("--patience", type=int, default=3)
    p.add_argument(
        "--data-mode",
        choices=["workers", "raw"],
        default="workers",
        help=(
            "workers: train the selected worker datasets independently. "
            "raw: train one local baseline with the UNSW-NB15 raw files."
        ),
    )
    p.add_argument("--worker-ids", default="1,2,3")
    p.add_argument(
        "--dataset-pattern",
        default="unsw_nb15_worker_{worker}.csv",
        help="CSV filename inside workerX/input/. Use {worker} for the worker id.",
    )
    p.add_argument("--data-dir", default="/data")
    p.add_argument("--output-dir", default="/outputs")
    p.add_argument("--experiment-name", default="PFG_Local_Worker_Baseline")
    return p.parse_args()


def parse_worker_ids(worker_ids: str) -> list[int]:
    return [int(item.strip()) for item in worker_ids.split(",") if item.strip()]


def load_worker_jobs(args) -> list[DatasetJob]:
    jobs: list[DatasetJob] = []
    for idx in parse_worker_ids(args.worker_ids):
        filename = args.dataset_pattern.format(worker=idx, worker_id=idx)
        path = os.path.join(args.data_dir, f"worker{idx}/input/{filename}")
        if not os.path.exists(path):
            log.warning("  MISSING worker-%s dataset: %s", idx, path)
            continue
        df = pd.read_csv(path, low_memory=False)
        jobs.append(
            DatasetJob(
                label=f"worker-{idx}",
                worker_id=str(idx),
                source_path=path,
                dataframe=df,
            )
        )
        log.info("  OK worker-%s dataset loaded: %s (%s rows)", idx, os.path.basename(path), f"{len(df):,}")

    if not jobs:
        raise FileNotFoundError(f"No worker CSV files found under {args.data_dir}/worker*/input/")
    expected_workers = len(parse_worker_ids(args.worker_ids))
    if len(jobs) != expected_workers:
        raise FileNotFoundError(
            f"Expected {expected_workers} worker CSV files for the local baseline, found {len(jobs)}."
        )
    return jobs


def load_raw_job(data_dir: str) -> DatasetJob:
    candidates = [
        os.path.join(data_dir, "raw/UNSW_NB15_training-set.csv"),
        os.path.join(data_dir, "raw/UNSW_NB15_testing-set.csv"),
    ]
    frames = []
    existing_paths = []
    for path in candidates:
        if os.path.exists(path):
            df = pd.read_csv(path, low_memory=False)
            frames.append(df)
            existing_paths.append(path)
            log.info("  OK raw dataset loaded: %s (%s rows)", os.path.basename(path), f"{len(df):,}")

    if not frames:
        raise FileNotFoundError(f"No raw UNSW-NB15 CSV files found under {data_dir}/raw/")

    combined = pd.concat(frames, ignore_index=True)
    log.info("  OK raw local dataset prepared: %s rows", f"{len(combined):,}")
    return DatasetJob(
        label="raw-local",
        worker_id="raw",
        source_path=";".join(existing_paths),
        dataframe=combined,
    )


def build_training_config(args) -> dict:
    return {
        "rounds": args.epochs,
        "round_timeout": 360,
        "min_workers": 1,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "test_split": args.test_split,
        "early_stopping_patience": args.patience,
        "focal_gamma": args.focal_gamma,
        "label_smoothing": args.label_smoothing,
        "fedprox_mu": 0.0,
        "categorical_encoding_enabled": True,
        "feature_selection_strategy": "runtime_dataset_shared",
        "feature_selection_enabled": True,
        "feature_selection_keep_ratio": 0.75,
        "feature_selection_min_features": 30,
        "feature_selection_max_features": 30,
        "feature_selection_variance_threshold": 1e-8,
        "selected_numeric_features": [],
    }


def _normalized_df(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(c).lower().strip() for c in out.columns]
    return out


def _label_series_for_selection(df: pd.DataFrame) -> pd.Series:
    if algorithm.ATTACK_CAT_COL in df.columns:
        attack = df[algorithm.ATTACK_CAT_COL].fillna("Normal").astype(str).str.strip()
        attack.loc[attack == ""] = "Normal"
        grouped = attack.map(algorithm._group_attack_category)
        return grouped.map(algorithm.CAT_TO_IDX).fillna(0).astype(int)
    if algorithm.ATTACK_GROUP_COL in df.columns:
        grouped = (
            df[algorithm.ATTACK_GROUP_COL]
            .fillna("Benign")
            .astype(str)
            .str.strip()
            .map(algorithm._group_attack_category)
        )
        return grouped.map(algorithm.CAT_TO_IDX).fillna(0).astype(int)
    if algorithm.LABEL_COL in df.columns:
        return pd.Series((df[algorithm.LABEL_COL].values > 0).astype(int))

    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    if not numeric_cols:
        raise ValueError("Feature selection needs a label/attack_cat column or at least one numeric target fallback.")
    log.warning(
        "  No label/attack_cat column found; using last numeric column '%s' as binary label fallback.",
        numeric_cols[-1],
    )
    return pd.Series((df[numeric_cols[-1]].values > 0).astype(int))


def select_runtime_numeric_features(jobs: list[DatasetJob], cfg: dict) -> list[str]:
    normalized_frames = [_normalized_df(job.dataframe) for job in jobs]
    label_like = {algorithm.LABEL_COL, algorithm.ATTACK_CAT_COL, algorithm.ATTACK_GROUP_COL, "id"}

    common_numeric = None
    for df in normalized_frames:
        numeric_cols = {
            col for col in df.select_dtypes(include="number").columns.tolist()
            if col not in label_like
        }
        common_numeric = numeric_cols if common_numeric is None else common_numeric & numeric_cols

    candidates = sorted(common_numeric or [])
    if not candidates:
        raise ValueError("No common numeric feature columns were found for the selected baseline dataset(s).")

    reference_df = pd.concat(normalized_frames, ignore_index=True, sort=False)
    y_series = _label_series_for_selection(reference_df)
    X_df = reference_df[candidates].fillna(0).replace([np.inf, -np.inf], 0)
    for col in [c for c in algorithm.LOG_TRANSFORM_COLS if c in X_df.columns]:
        X_df[col] = np.log1p(X_df[col].clip(lower=0))
    for col in X_df.columns:
        p99 = X_df[col].quantile(0.99)
        if p99 > 0:
            X_df[col] = X_df[col].clip(upper=p99)

    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X = np.nan_to_num(scaler.fit_transform(X_df.values).astype(np.float32))
    y = y_series.values.astype(np.int32)
    try:
        train_idx, val_idx = train_test_split(
            np.arange(len(X)),
            test_size=float(cfg.get("test_split", 0.2)),
            stratify=y,
            random_state=42,
        )
    except Exception:
        n_val = max(1, int(len(X) * float(cfg.get("test_split", 0.2))))
        idx = np.random.permutation(len(X))
        val_idx, train_idx = idx[:n_val], idx[n_val:]

    _, _, selected = algorithm._select_features(
        X[train_idx],
        y[train_idx],
        X[val_idx],
        candidates,
        cfg,
    )
    selected = [col for col in candidates if col in selected]
    if not selected:
        selected = candidates[: int(cfg.get("feature_selection_max_features", 30))]

    log.info(
        "  Runtime feature selection: %s candidate numeric columns -> %s selected",
        len(candidates),
        len(selected),
    )
    log.info("  Selected numeric features: %s", selected)
    return selected


def _setup_plotting():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.rcParams.update(
            {
                "figure.facecolor": "#ffffff",
                "axes.facecolor": "#ffffff",
                "axes.edgecolor": "#d0d7de",
                "axes.labelcolor": "#24292f",
                "axes.titleweight": "bold",
                "axes.titlesize": 13,
                "axes.labelsize": 10,
                "xtick.color": "#57606a",
                "ytick.color": "#57606a",
                "font.size": 9,
                "legend.frameon": False,
                "grid.color": "#d8dee4",
                "grid.linewidth": 0.8,
                "savefig.facecolor": "#ffffff",
            }
        )
        return plt
    except Exception as exc:
        log.warning("Plots are not available: %s", exc)
        return None


def _metric_color(value: float) -> str:
    if value >= 0.8:
        return "#2da44e"
    if value >= 0.5:
        return "#bf8700"
    return "#cf222e"


def _style_axes(ax, grid_axis: str = "y"):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#d0d7de")
    ax.spines["bottom"].set_color("#d0d7de")
    ax.grid(axis=grid_axis, alpha=0.65)
    ax.set_axisbelow(True)


def _add_bar_labels(ax, bars, fmt: str = "{:.3f}", horizontal: bool = False):
    for bar in bars:
        if horizontal:
            value = bar.get_width()
            x = min(value + 0.015, ax.get_xlim()[1] * 0.98)
            ax.text(
                x,
                bar.get_y() + bar.get_height() / 2,
                fmt.format(value),
                va="center",
                ha="left",
                fontsize=8,
                color="#57606a",
            )
        else:
            value = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.015,
                fmt.format(value),
                va="bottom",
                ha="center",
                fontsize=8,
                color="#57606a",
            )


def _save_and_log(fig, path: str, plt):
    fig.savefig(path, dpi=180, bbox_inches="tight", facecolor="#ffffff")
    mlflow.log_artifact(path)
    plt.close(fig)


def plot_and_log(result: dict, artifacts_dir: str, label: str, file_prefix: str):
    plt = _setup_plotting()
    if plt is None:
        return

    metrics = result.get("metrics", {}) or {}
    training_history = result.get("training_history", {}) or {}
    per_class = result.get("per_class_report", {}) or {}
    cm = result.get("confusion_matrix", []) or []
    class_names = result.get("class_names", []) or []
    feat_imp = result.get("feature_importance", {}) or {}

    if training_history:
        max_len = max(
            (len(v) for v in training_history.values() if isinstance(v, list)),
            default=0,
        )
        if max_len:
            epochs = list(range(1, max_len + 1))
            fig, ax = plt.subplots(figsize=(10.5, 5.2))
            curves = [
                ("val_f1_macro", "Validation F1 macro", "#0969da"),
                ("val_focus_f1", "Validation focus F1", "#8250df"),
                ("val_minority_f1", "Validation minority F1", "#bf8700"),
                ("accuracy", "Training accuracy", "#2da44e"),
            ]
            for key, curve_label, color in curves:
                values = training_history.get(key, [])
                if values:
                    ax.plot(
                        epochs[: len(values)],
                        values,
                        marker="o",
                        markersize=4,
                        linewidth=2.0,
                        color=color,
                        label=curve_label,
                    )
            ax.set_xlabel("Local epoch")
            ax.set_ylabel("Metric value")
            ax.set_ylim(0, 1.05)
            ax.set_title(f"{label} local training evolution (No-FL)", pad=14)
            ax.legend(ncol=2)
            _style_axes(ax, grid_axis="y")
            path = os.path.join(artifacts_dir, f"{file_prefix}_training_evolution.png")
            _save_and_log(fig, path, plt)
            log.info("      [PLOT] Training evolution          saved")

            loss_values = training_history.get("loss", [])
            val_loss_values = training_history.get("val_loss", [])
            if loss_values or val_loss_values:
                fig, ax = plt.subplots(figsize=(10.5, 4.9))
                if loss_values:
                    ax.plot(
                        epochs[: len(loss_values)],
                        loss_values,
                        marker="o",
                        linewidth=2.0,
                        color="#cf222e",
                        label="Training loss",
                    )
                if val_loss_values:
                    ax.plot(
                        epochs[: len(val_loss_values)],
                        val_loss_values,
                        marker="o",
                        linewidth=2.0,
                        color="#0969da",
                        label="Validation loss",
                    )
                ax.set_xlabel("Local epoch")
                ax.set_ylabel("Loss")
                ax.set_title(f"{label} local loss evolution (No-FL)", pad=14)
                ax.legend()
                _style_axes(ax, grid_axis="y")
                path = os.path.join(artifacts_dir, f"{file_prefix}_loss_evolution.png")
                _save_and_log(fig, path, plt)
                log.info("      [PLOT] Loss evolution              saved")

    metric_keys = ["accuracy", "auc", "precision", "recall", "f1_macro", "focus_f1", "f1_weighted", "mcc"]
    labels = [key for key in metric_keys if isinstance(metrics.get(key), (int, float))]
    values = [float(metrics[key]) for key in labels]
    if values:
        fig, ax = plt.subplots(figsize=(10.5, 4.9))
        bars = ax.bar(labels, values, color=[_metric_color(v) for v in values])
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Metric value")
        ax.set_title(f"{label} summary metrics (No-FL)", pad=14)
        ax.tick_params(axis="x", rotation=25)
        _style_axes(ax, grid_axis="y")
        _add_bar_labels(ax, bars)
        path = os.path.join(artifacts_dir, f"{file_prefix}_summary_metrics.png")
        _save_and_log(fig, path, plt)
        log.info("      [PLOT] Summary metrics             saved")

    class_items = [
        (str(k), float(v))
        for k, v in per_class.items()
        if isinstance(v, (int, float)) and np.isfinite(float(v))
    ]
    if class_items:
        class_items.sort(key=lambda x: x[1])
        fig, ax = plt.subplots(figsize=(9.5, max(3.8, len(class_items) * 0.52)))
        bars = ax.barh(
            [k for k, _ in class_items],
            [v for _, v in class_items],
            color=[_metric_color(v) for _, v in class_items],
        )
        ax.set_xlim(0, 1.0)
        ax.set_xlabel("F1-score")
        ax.set_title(f"{label} F1-score by class", pad=14)
        ax.axvline(0.8, color="#2da44e", linewidth=1, linestyle="--", alpha=0.5)
        _style_axes(ax, grid_axis="x")
        _add_bar_labels(ax, bars, horizontal=True)
        path = os.path.join(artifacts_dir, f"{file_prefix}_f1_per_class.png")
        _save_and_log(fig, path, plt)
        log.info("      [PLOT] F1 per class                saved")

    if cm:
        matrix = np.array(cm, dtype=float)
        if matrix.ndim == 2 and matrix.size > 0:
            n = min(matrix.shape[0], matrix.shape[1], len(class_names) if class_names else matrix.shape[0])
            matrix = matrix[:n, :n]
            c_labels = [str(c) for c in (class_names[:n] if class_names else range(n))]
            row_totals = matrix.sum(axis=1, keepdims=True)
            matrix_pct = np.divide(matrix, row_totals, out=np.zeros_like(matrix), where=row_totals != 0)
            fig, ax = plt.subplots(figsize=(max(7, n * 1.35), max(5.6, n * 1.08)))
            im = ax.imshow(matrix_pct, cmap="Blues", vmin=0, vmax=1)
            ax.set_title(f"{label} normalized confusion matrix", pad=14)
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            ax.set_xticks(range(n), labels=c_labels, rotation=35, ha="right")
            ax.set_yticks(range(n), labels=c_labels)
            for i in range(n):
                for j in range(n):
                    color = "white" if matrix_pct[i, j] > 0.5 else "#24292f"
                    ax.text(
                        j,
                        i,
                        f"{matrix_pct[i, j] * 100:.0f}%\n({int(matrix[i, j])})",
                        ha="center",
                        va="center",
                        color=color,
                        fontsize=8,
                    )
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            path = os.path.join(artifacts_dir, f"{file_prefix}_confusion_matrix.png")
            _save_and_log(fig, path, plt)
            log.info("      [PLOT] Confusion matrix            saved")

    feature_items = [
        (str(k), float(v))
        for k, v in feat_imp.items()
        if isinstance(v, (int, float)) and np.isfinite(float(v))
    ]
    if feature_items:
        feature_items = sorted(feature_items, key=lambda x: x[1], reverse=True)[:15]
        feature_items.sort(key=lambda x: x[1])
        fig, ax = plt.subplots(figsize=(9.5, max(4.2, len(feature_items) * 0.42)))
        bars = ax.barh([k for k, _ in feature_items], [v for _, v in feature_items], color="#0969da")
        ax.set_xlabel("Relative importance")
        ax.set_title(f"{label} top input features", pad=14)
        _style_axes(ax, grid_axis="x")
        _add_bar_labels(ax, bars, fmt="{:.2f}", horizontal=True)
        path = os.path.join(artifacts_dir, f"{file_prefix}_feature_importance.png")
        _save_and_log(fig, path, plt)
        log.info("      [PLOT] Feature importance          saved")

    if class_names and cm:
        matrix = np.array(cm, dtype=float)
        n = min(len(class_names), matrix.shape[0])
        class_totals = matrix[:n].sum(axis=1)
        if class_totals.sum() > 0:
            fig, ax = plt.subplots(figsize=(8, 5.5))
            colors = ["#0969da", "#2da44e", "#bf8700", "#8250df", "#cf222e"]
            ax.pie(
                class_totals,
                labels=class_names[:n],
                autopct="%1.1f%%",
                colors=colors[:n],
                startangle=90,
                textprops={"fontsize": 9},
            )
            ax.set_title(f"{label} validation class distribution", pad=14)
            path = os.path.join(artifacts_dir, f"{file_prefix}_class_distribution.png")
            _save_and_log(fig, path, plt)
            log.info("      [PLOT] Class distribution          saved")


def safe_metric_name(raw: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._/-" else "_" for ch in str(raw))[:250]


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, np.ndarray):
        return json_safe(value.tolist())
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def write_temp_json(payload: dict) -> str:
    tmp_fd, path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(json_safe(payload), f, indent=2)
    return path


def write_temp_csv(df: pd.DataFrame) -> str:
    tmp_fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(tmp_fd)
    df.to_csv(path, index=False)
    return path


def log_training_history(training_history: dict):
    max_len = max(
        (len(v) for v in training_history.values() if isinstance(v, list)),
        default=0,
    )
    for epoch_idx in range(max_len):
        step = epoch_idx + 1
        mlflow.log_metric("local_epoch", step, step=step)
        for key, values in training_history.items():
            if not isinstance(values, list) or epoch_idx >= len(values):
                continue
            value = values[epoch_idx]
            if isinstance(value, (int, float, np.integer, np.floating)) and np.isfinite(float(value)):
                mlflow.log_metric(safe_metric_name(f"epoch.{key}"), float(value), step=step)


def log_result_metrics(result: dict, elapsed: float):
    metrics = result.get("metrics", {}) or {}
    per_class = result.get("per_class_report", {}) or {}

    for key, value in metrics.items():
        if isinstance(value, (int, float, np.integer, np.floating)) and np.isfinite(float(value)):
            mlflow.log_metric(safe_metric_name(key), float(value))

    for class_name, f1_value in per_class.items():
        if isinstance(f1_value, (int, float, np.integer, np.floating)) and np.isfinite(float(f1_value)):
            mlflow.log_metric(safe_metric_name(f"class_f1.{class_name}"), float(f1_value))

    mlflow.log_metric("training_time_seconds", elapsed)
    mlflow.log_metric("total_samples", result.get("n_samples", 0))
    mlflow.log_metric("input_dim", result.get("input_dim", 0))


def train_one_job(job: DatasetJob, cfg: dict, args, tracking_uri: str) -> dict:
    label = job.label.title()
    file_prefix = job.label.replace("-", "_")
    start_dt = datetime.now()
    started_at = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    started_stamp = start_dt.strftime("%H%M%S")
    run_name = (
        f"{label} | Local No-FL baseline | {started_at} | "
        f"{args.epochs} epochs"
    )
    dataset_csv_path = write_temp_csv(job.dataframe)
    config_path = write_temp_json(cfg)
    start_time = time.time()

    log.info("")
    log.info("-" * 80)
    log.info("LOCAL BASELINE: %s", label)
    log.info("  Dataset file:   %s", os.path.basename(job.source_path))
    log.info("  Dataset rows:   %s", f"{len(job.dataframe):,}")
    log.info("  Started at:     %s", started_at)
    log.info("  Local epochs:   %s", args.epochs)
    log.info("  MLflow run:     %s", run_name)
    log.info("-" * 80)

    try:
        with mlflow.start_run(
            run_name=run_name,
            nested=True,
            tags={
                "training.mode": "local_worker_baseline",
                "training.pipeline": "same_pipeline_as_fl_algorithm",
                "training.data_mode": args.data_mode,
                "comparison.group": "FL_vs_LocalWorkers",
                "worker.id": job.worker_id,
                "worker.label": job.label,
                "run.started_at": started_at,
                "model.architecture": "DNN_512-256-128-64",
                "model.loss": "SparseFocalLoss",
                "dataset": "UNSW-NB15",
            },
        ):
            mlflow.log_params(
                {
                    "mode": "local_worker_baseline",
                    "pipeline": "same_pipeline_as_fl_algorithm",
                    "data_mode": args.data_mode,
                    "worker_id": job.worker_id,
                    "worker_label": job.label,
                    "started_at": started_at,
                    "dataset_file": os.path.basename(job.source_path),
                    "dataset_rows": len(job.dataframe),
                    "epochs": args.epochs,
                    "batch_size": args.batch_size,
                    "learning_rate": args.learning_rate,
                    "focal_gamma": args.focal_gamma,
                    "label_smoothing": args.label_smoothing,
                    "test_split": args.test_split,
                    "early_stopping_patience": args.patience,
                    "fedprox_mu": 0.0,
                    "federated": "false",
                    "num_workers": 1,
                    "round_definition": "one local baseline training run",
                    "feature_selection_strategy": cfg.get("feature_selection_strategy"),
                    "feature_selection_enabled": cfg.get("feature_selection_enabled"),
                    "categorical_encoding_enabled": cfg.get("categorical_encoding_enabled"),
                }
            )

            result = algorithm.run(
                data_path=dataset_csv_path,
                global_weights_b64=None,
                config_path=config_path,
            )
            elapsed = time.time() - start_time
            metrics = result.get("metrics", {}) or {}
            per_class = result.get("per_class_report", {}) or {}
            training_history = result.get("training_history", {}) or {}

            log_training_history(training_history)
            log_result_metrics(result, elapsed)

            run_id = mlflow.active_run().info.run_id
            artifacts_dir = os.path.join(
                args.output_dir,
                f"{job.label.replace('-', '_')}_Baseline_{started_stamp}",
            )
            os.makedirs(artifacts_dir, exist_ok=True)
            log.info("")
            log.info("  Artifact export")
            log.info("  ------------------------------------------------------------------------------")
            log.info("    Output directory              %s", artifacts_dir)

            results_payload = {
                "mode": "local_worker_baseline",
                "pipeline": "same_pipeline_as_fl_algorithm",
                "worker_id": job.worker_id,
                "worker_label": job.label,
                "started_at": started_at,
                "source_path": job.source_path,
                "config": cfg,
                "metrics": metrics,
                "per_class_report": per_class,
                "confusion_matrix": result.get("confusion_matrix", []),
                "feature_cols": result.get("feature_cols", []),
                "training_history": training_history,
                "class_names": result.get("class_names", []),
                "n_samples": result.get("n_samples", 0),
                "input_dim": result.get("input_dim", 0),
                "model_name": result.get("model_name", ""),
                "num_classes": result.get("num_classes", 0),
                "classification_mode": result.get("classification_mode", ""),
                "training_time_seconds": round(elapsed, 2),
            }

            results_path = os.path.join(artifacts_dir, f"{file_prefix}_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump(json_safe(results_payload), f, indent=2, ensure_ascii=False)
            mlflow.log_artifact(results_path)

            cfg_artifact_path = os.path.join(artifacts_dir, "training_config.json")
            with open(cfg_artifact_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            mlflow.log_artifact(cfg_artifact_path)

            log.info("    Plot generation               STARTED")
            plot_and_log(result, artifacts_dir, label, file_prefix)
            log.info("    Plot generation               COMPLETED")

            log.info("")
            log.info("  Baseline evaluation summary -- %s", label)
            log.info("  ------------------------------------------------------------------------------")
            log.info("    Metric                         Value")
            log.info("    Accuracy                       %.4f", metrics.get("accuracy", 0))
            log.info("    AUC                            %.4f", metrics.get("auc", 0))
            log.info("    Precision macro                %.4f", metrics.get("precision", 0))
            log.info("    Recall macro                   %.4f", metrics.get("recall", 0))
            log.info("    F1 macro                       %.4f", metrics.get("f1_macro", 0))
            log.info("    Focus F1                       %.4f", metrics.get("focus_f1", 0))
            log.info("    F1 weighted                    %.4f", metrics.get("f1_weighted", 0))
            log.info("    Matthews corrcoef              %.4f", metrics.get("mcc", 0))
            log.info("    Loss                           %.6f", metrics.get("loss", 0))
            log.info("  ------------------------------------------------------------------------------")
            log.info("    Training samples               %s", f"{result.get('n_samples', 0):,}")
            log.info("    Model input features           %s", result.get("input_dim", 0))
            log.info("    Output classes                 %s", result.get("num_classes", 0))
            log.info("    Training time                  %.1fs", elapsed)
            if per_class:
                log.info("")
                log.info("    Per-class F1 score")
                log.info("    Class                          F1-score   Bar")
                for cls, f1_value in sorted(per_class.items(), key=lambda x: x[1], reverse=True):
                    bar = "#" * int(float(f1_value) * 30)
                    log.info("    %-30s %.4f     %s", cls, float(f1_value), bar)
            log.info("  ------------------------------------------------------------------------------")
            log.info("  MLflow registration             OK  %s", tracking_uri.replace("mlflow:5000", "localhost:5005"))

            return results_payload
    finally:
        for path in (dataset_csv_path, config_path):
            try:
                os.unlink(path)
            except OSError:
                pass


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  [local-baseline]  %(levelname)-8s  %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    log.info("=" * 80)
    log.info("  LOCAL WORKER BASELINES (No-FL) -- MLflow comparison with FL")
    log.info("=" * 80)
    log.info("  Data mode:      %s", args.data_mode)
    log.info("  Local epochs:   %s", args.epochs)
    log.info("  Batch size:     %s", args.batch_size)
    log.info("  Learning rate:  %s", args.learning_rate)
    log.info("  Focal gamma:    %s", args.focal_gamma)
    log.info("  Label smooth:   %s", args.label_smoothing)
    log.info("  Test split:     %s", args.test_split)
    log.info("  Patience:       %s", args.patience)
    log.info("=" * 80)

    log.info("[PHASE 1] Loading local baseline datasets...")
    jobs = load_worker_jobs(args) if args.data_mode == "workers" else [load_raw_job(args.data_dir)]

    log.info("[PHASE 2] Preparing shared training configuration...")
    cfg = build_training_config(args)
    cfg["selected_numeric_features"] = select_runtime_numeric_features(jobs, cfg)
    log.info("  Feature selection: %s", cfg["feature_selection_strategy"])
    log.info("  FedProx: disabled (mu=0.0)")

    tracking_uri = os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000")
    experiment_name = os.getenv("MLFLOW_EXPERIMENT_NAME", args.experiment_name)
    mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(experiment_name)
    log.info("[PHASE 3] MLflow tracking: %s / %s", tracking_uri, experiment_name)

    log.info("[PHASE 4] Training %s independent local baseline(s)...", len(jobs))
    summaries = []
    for job in jobs:
        summaries.append(train_one_job(job, cfg, args, tracking_uri))

    log.info("")
    log.info("=" * 80)
    log.info("  LOCAL BASELINE RUNS COMPLETED")
    log.info("=" * 80)
    for item in summaries:
        metrics = item.get("metrics", {}) or {}
        log.info(
            "  %-8s  rows=%-8s  acc=%.4f  f1_macro=%.4f  focus_f1=%.4f",
            item.get("worker_label", "unknown"),
            f"{item.get('n_samples', 0):,}",
            metrics.get("accuracy", 0),
            metrics.get("f1_macro", 0),
            metrics.get("focus_f1", 0),
        )
    log.info("=" * 80)
    log.info("  Compare these local worker runs with the federated run in MLflow.")


if __name__ == "__main__":
    main()
