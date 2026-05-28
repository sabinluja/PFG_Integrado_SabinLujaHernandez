# Utility & Experiments Scripts (scripts)

This directory contains standalone Python utility scripts to prepare dataset partitions and execute hyperparameter optimization (Grid Search) across the Federated Learning Docker stack.

---

## Script Descriptions

### 1. Dataset Partitioning (`generate_worker_partitions.py`)
This script prepares the machine learning datasets for the Federated Learning nodes. It processes the raw [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) CSV files and partitions them heterogeneously.

* **5-Class Semantic Grouping**: Re-categorizes the original 10 attack classes into 5 unified profiles:
  * `Benign`: Normal network traffic.
  * `GenericAttack`: Generic exploit signatures.
  * `ExploitAccess`: Complex intrusions (Exploits, Analysis, Backdoor, Shellcode, Worms).
  * `Disruption`: Traffic flood and state disruption attacks (Fuzzers, DoS).
  * `ReconAttack`: Reconnaissance activity (Probes, Port scans).
* **Heterogeneous Worker Distribution**: Splits the training dataset unevenly among the 3 active participants (simulating nodes of different sizes):
  * **Worker 1**: $50\%$ of the data (Large partition).
  * **Worker 2**: $30\%$ of the data (Medium partition).
  * **Worker 3**: $20\%$ of the data (Small partition).
  * *Note: Worker 4 is excluded from partitioning as it rejects participation due to lack of a valid data contract.*
* **Outputs**: Writes partitioned files to `ia-dataapp/data/worker{wid}/input/unsw_nb15_worker_{wid}.csv`.

#### Usage
```bash
python scripts/generate_worker_partitions.py
```

---

## Hyperparameter Grid Search (`pfg_fl_grid_search.py`)
Automates the execution of multiple Federated Learning runs to discover the best hyperparameter combinations. It leverages the live Docker containers and coordinates training via REST API triggers.

* **Configurable Sweep**: Sweeps across custom parameters including:
  * Number of global rounds (`--rounds`)
  * Local epochs per round (`--epochs`)
  * Local Optimizer Learning rates (`--learning-rates`)
  * Local batch sizes (`--batch-sizes`)
  * FedProx regularization coefficient $\mu$ (`--fedprox-mus`)
  * Focal Loss gamma parameter (`--focal-gammas`)
* **Auto-Evaluation**: Ranks combinations based on a target metric (accuracy, macro F1-score, loss, MCC) and saves JSON reports and a sorted CSV (`trial_ranked.csv`).
* *Note: Requires `FL_ALGO_VIA_DOCKER=false` in the `.env` configuration to allow on-the-fly algorithm configuration updates.*

#### Usage
```bash
python scripts/pfg_fl_grid_search.py \
  --coordinator 2 \
  --objective f1_macro \
  --rounds 5,10 \
  --epochs 10,15 \
  --learning-rates 0.0005,0.001 \
  --fedprox-mus 0.0,0.01
```
---

## Requirements

To run these scripts on your host machine, install the necessary libraries:
```bash
pip install pandas numpy scikit-learn requests urllib3
```
