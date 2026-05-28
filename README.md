<h1 align="center">Federated Learning over International Data Spaces<br/>for Network Intrusion Detection</h1>

<p align="center">
  <strong>Final Degree Project - Computer Science · Data Science and Artificial Intelligence</strong><br/>
  <em>Sabin Luja Hernandez</em>
</p>

---

## Overview

This project implements a **privacy-preserving Federated Learning (FL) pipeline** for network intrusion detection, built entirely on top of the **International Data Spaces (IDS)** reference architecture. Data never leaves its owner - only model weights travel between participants through authenticated, contract-governed IDS channels.

The system deploys **4 IDS connector nodes** (workers), each holding a local partition of the [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) dataset. A coordinator orchestrates multi-class classification (5 attack categories) using **FedAvg / FedProx** aggregation over a DNN with Focal Loss, while a full IDS infrastructure handles identity, discovery, contract negotiation, and auditability.

### Key Contributions

- **End-to-end IDS integration**: DAPS authentication, Broker discovery, contract negotiation, and Clearing House audit logging - all fully operational, not mocked.
- **Data sovereignty by design**: Worker 4 legitimately rejects FL participation via contract negotiation, and is provably denied access to the trained model.
- **AI-assisted dataset recommendation**: Local LLM (LLaMA 3.2 via Ollama) recommends compatible datasets during the discovery phase.
- **MLOps observability**: Full experiment tracking with MLflow - per-round metrics, confusion matrices, feature importance charts, and federated vs. local baseline comparison.
- **Docker-native algorithm distribution**: The FL algorithm is packaged as an immutable Docker image and distributed through a private registry via IDS artifact messages.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Docker Compose Stack                              │
│                                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│    │  Worker 1   │    │  Worker 2   │    │  Worker 3   │    │  Worker 4   │    │
│    │  ECC + DA   │    │  ECC + DA   │    │  ECC + DA   │    │  ECC + DA   │    │
│    │   (data)    │    │  (coord.)   │    │   (data)    │    │ (rejected)  │    │
│    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    │
│           │                  │                  │                  │           │
│           └──────────────────┼──────────────────┴──────────────────┘           │
│                              │   IDS Network                                   │
│               ┌──────────────┴─────────┬────────────────────────┐              │
│               │                        │                        │              │
│               ▼                        ▼                        ▼              │
│      ┌────────────────┐       ┌────────────────┐       ┌────────────────┐      │
│      │      DAPS      │       │     Broker     │       │ Clearing House │      │
│      │    (Omejdn)    │       │    (Fuseki)    │       │ (FastAPI+Mongo)│      │
│      └────────────────┘       └────────────────┘       └────────────────┘      │
│                                                                                │
│      ┌────────────────┐       ┌────────────────┐       ┌────────────────┐      │
│      │     MLflow     │       │     Ollama     │       │  FL Registry   │      │
│      │  + PostgreSQL  │       │  (LLaMA 3.2)   │       │    (Docker)    │      │
│      └────────────────┘       └────────────────┘       └────────────────┘      │
└────────────────────────────────────────────────────────────────────────────────┘
```

Each **Worker** consists of two containers:
- **ECC** (Execution Core Container) - the TRUE Connector Java component handling IDS messaging, DAPS tokens, and Broker registration.
- **DataApp** - a Python (FastAPI) application implementing the FL training logic, dataset management, contract handling, and IDS message processing.

---

## IDS Flow - 6 Phases

| Phase | Name | Description |
|:-----:|------|-------------|
| **0** | Connectivity & Topology | Health checks, endpoint resolution, Broker catalog verification |
| **1** | Coordinator Catalog | Dataset publication, federated catalog inspection, LLM recommendation |
| **2** | FL Artifact Preparation | Algorithm + config packaged as Docker image, pushed to private registry |
| **3** | Peer Discovery & Filtering | SPARQL discovery via Broker, self-description inspection, compatibility filter |
| **4** | IDS Contract Negotiation | `ContractRequest → Agreement/Rejection` per peer. Worker 4 is rejected |
| **5** | Federated Training | Algorithm distribution via IDS, local training, weight exchange (ECC-WSS), FedAvg aggregation |
| **6** | Data Sovereignty Audit | Verify rejected workers cannot access the final model. Clearing House audit trail |

The full orchestration is implemented in [`pfg_ids_fl_flow.py`](pfg_ids_fl_flow.py) and can be triggered via [Postman collections](postman/).

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **IDS Connectors** | [TRUE Connector](https://github.com/Engineering-Research-and-Development/true-connector) v1.14.8 | IDS messaging, DAPS auth, Broker registration |
| **Identity Provider** | Omejdn Server 1.6.0 + Nginx | Dynamic Attribute Token (DAT) issuance |
| **Metadata Broker** | IDS Testbed Broker 5.0.3 + Fuseki | Connector discovery and SPARQL catalog |
| **Clearing House** | Custom (FastAPI + MongoDB) | Immutable audit logging with hash chaining |
| **FL DataApp** | Python 3.10, FastAPI, TensorFlow 2.15 | Training, aggregation, IDS message handling |
| **ML Model** | DNN (512→256→128→64) with Focal Loss, FedProx | 5-class intrusion classification |
| **Dataset** | UNSW-NB15 (Moustafa & Slay, 2015) | Network traffic - 4 worker partitions |
| **Experiment Tracking** | MLflow 3.x + PostgreSQL | Metrics, artifacts, federated vs. baseline comparison |
| **LLM** | Ollama (LLaMA 3.2, local) | AI-assisted dataset recommendation |
| **Algorithm Distribution** | Docker Registry (private) | Immutable FL algorithm images |
| **Orchestration** | Docker Compose | ~20 services, single-command deployment |

---

## Requirements

### System

- **Docker** ≥ 24.0 and **Docker Compose** v2
- **RAM** ≥ 16 GB (recommended 24 GB - 4 ECCs + 4 DataApps + Ollama)
- **Disk** ≥ 15 GB (Docker images + Ollama model + datasets)
- **OS**: Linux, macOS, or Windows (WSL2)

### Dataset

Place the UNSW-NB15 CSV partitions in `ia-dataapp/data/worker{1..4}/`:

```
ia-dataapp/data/
├── worker1/unsw_nb15_worker_1.csv
├── worker2/unsw_nb15_worker_2.csv
├── worker3/unsw_nb15_worker_3.csv
└── worker4/unsw_nb15_worker_4.csv
```

Partitions can be generated from the raw dataset using [`scripts/generate_worker_partitions.py`](scripts/generate_worker_partitions.py).

---

## Quick Start

### 1. Deploy the full stack

```bash
docker compose down -v
docker compose build be-dataapp-worker1
docker compose up -d
```

### 2. Run the local baseline (non-federated comparison)

```bash
docker compose up -d mlflow-db mlflow
docker compose --profile baseline run --rm baseline-trainer
```

### 3. Execute the federated learning flow

```bash
python pfg_ids_fl_flow.py
```

Or use the [Postman collections](postman/) for step-by-step execution.

### 4. Monitor

| Service | URL |
|---------|-----|
| MLflow UI | [http://localhost:5005](http://localhost:5005) |
| Clearing House API | [http://localhost:8100/docs](http://localhost:8100/docs) |
| Fuseki SPARQL | [http://localhost:3030](http://localhost:3030) |
| Worker 1 DataApp | [https://localhost:5001/health](https://localhost:5001/health) |
| Worker 2 DataApp (Coordinator) | [https://localhost:5002/health](https://localhost:5002/health) |

### 5. Hard reset

> **Caution:** This removes all containers, volumes, and built images.

```bash
docker compose down -v --rmi all --remove-orphans
docker system prune --volumes
```

---

## Project Structure

```
.
├── ia-dataapp/                  # FL DataApp (Python) - shared by all workers
│   ├── app.py                   # Main application (7500+ lines): IDS handling, FL coordination
│   ├── algorithm.py             # DNN model, Focal Loss, SMOTE, feature selection
│   ├── fl_config.json           # FL hyperparameters (rounds, epochs, FedProx μ, etc.)
│   ├── Dockerfile               # Worker image build
│   ├── Dockerfile.algorithm     # FL algorithm image for Docker-based distribution
│   └── data/                    # Per-worker dataset partitions
├── mlflow-baseline/             # Local (non-federated) baseline training
│   ├── MLproject                # MLflow project definition
│   └── baseline_train.py        # Standalone training script for comparison
├── ClearingHouse/               # IDS Clearing House microservice
│   └── app/                     # FastAPI application (audit, alerts, analytics)
├── DAPS/                        # Omejdn DAPS configuration
│   ├── config/                  # Client registrations (clients.yml)
│   └── keys/                    # Worker certificates and TLS keys
├── broker/                      # IDS Metadata Broker certificates
├── certs/                       # Shared TLS certificates and truststores
├── worker{1..4}/ecc/            # Per-worker ECC configuration (Spring properties)
├── scripts/                     # Utility scripts
│   ├── generate_worker_partitions.py
│   └── pfg_fl_grid_search.py    # Hyperparameter grid search
├── postman/                     # Postman collections and environments
├── doc/                         # Extended documentation (TRUE Connector + project)
├── docker-compose.yml           # Full stack definition (~20 services)
├── pfg_ids_fl_flow.py           # End-to-end FL orchestrator (6 phases)
├── .env                         # Environment variables (ports, URIs, credentials)
└── LICENSE                      # AGPL-3.0
```

---

<p align="center">
  <sub>Final Degree Project - Sabin Luja Hernandez</sub>
</p>