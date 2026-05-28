# Local No-FL Baseline Training (mlflow-baseline)

This directory contains the pipeline to train local machine learning models in isolation (**No-FL Baseline**) on each worker's dataset partition. The results are tracked using **MLflow** for comparative evaluation against the Federated Learning pipeline.

---

## Purpose of the Baseline

In a Federated Learning project, it is essential to evaluate the "Federation Gain". This module answers: *How does a model trained locally on a single worker's isolated partition compare to a model trained collaboratively via Federated Learning?*

* **Independent Runs**: Trains separate models for Worker 1 ($50\%$ data), Worker 2 ($30\%$ data), and Worker 3 ($20\%$ data).
* **Parity of Algorithm**: Uses the exact same preprocessing, custom Sparse Focal Loss layer, SMOTE class balancing, and DNN architecture as the main federated algorithm (`ia-dataapp/algorithm.py`).
* **MLflow Observability**: Logs all parameters, metrics per epoch, and evaluation artifacts to the shared MLflow server to allow direct comparison side-by-side with the federated trials.

---

## Core Files

* [baseline_train.py](baseline_train.py): The training execution script. It loads the dataset partitions, configures hyperparameters, runs the training loop, computes metrics, generates evaluation charts, and publishes runs to MLflow.
* [MLproject](MLproject): MLflow Project definition mapping entry points, parameters, and shell commands.

---

## Parameters & Arguments

You can customize baseline runs using the following arguments defined in `MLproject`:

| Parameter | Default | Description |
|:---|:---:|:---|
| `--epochs` | `18` | Total training epochs for the model. |
| `--batch-size` | `128` | Batch size for gradient updates. |
| `--learning-rate`| `0.001` | Learning rate for the Adam optimizer. |
| `--focal-gamma` | `1.5` | Focal loss gamma focusing parameter. |
| `--label-smoothing`| `0.005`| Label smoothing epsilon. |
| `--data-mode` | `workers` | `workers` (train partitions) or `raw` (train full UNSW-NB15 dataset). |
| `--worker-ids` | `1,2,3` | Gaps separated list of worker IDs to run baselines for. |
| `--data-dir` | `/data` | Path to the directory containing dataset partitions. |

---

## Logged MLflow Artifacts

For each run, the baseline script generates and logs visual evaluation plots:
* **Training & Loss Evolution**: Charts showing macro F1-score, focus F1-score, and loss curves per epoch.
* **Summary Metrics**: Bar chart comparing accuracy, AUC, precision, recall, MCC, and F1 macro.
* **F1 per Class**: Performance comparison across the 5 categorized attack groups.
* **Confusion Matrix**: Normalized confusion matrix showing absolute samples and percentages.
* **Feature Importance**: Top 15 network features based on relative importance metrics.

---

## Running the Baseline

### Option 1: Docker Compose (Recommended)
You can trigger the baseline run inside the docker-compose stack:
```bash
docker compose run --rm mlflow-baseline
```

### Option 2: Local Python Execution
To run locally outside Docker (requires python dependencies installed):
```bash
python mlflow-baseline/baseline_train.py \
  --epochs 20 \
  --learning-rate 0.0015 \
  --worker-ids 1,2,3 \
  --data-dir ia-dataapp/data \
  --output-dir mlflow-baseline/outputs
```
