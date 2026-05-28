# IDS and Federated Learning DataApp (ia-dataapp)

The **ia-dataapp** is a dual-purpose Python component serving as both the official **IDS DataApp** (mediating secure data exchange within the International Data Spaces architecture) and the **Federated Learning (FL) engine** (orchestrating model training, weights aggregation, and machine learning workflows).

It is deployed as a sidecar application to each worker's **TRUE Connector Execution Core (ECC)**, bridging the gaps between standard IDS protocols and machine learning models.

---

## Overview

The DataApp acts as the logic engine that integrates the IDS connectivity layer with the local machine learning models. Depending on its network configuration, each instance executes both IDS specifications and FL pipeline operations:

### 1. IDS DataApp Role
* **Contract Negotiation**: Implements endpoints to handle contract requests, agreements, and rejections based on custom data usage control rules.
* **Self-Description Provider**: Exposes structured JSON-LD self-descriptions detailing the node's datasets, schemas, and resource access policies.
* **Secure Artifact Exchange**: Services requests for model artifacts and data transfer under active, validated contracts.
* **DAPS Verification**: Integrates JWT/DAT token verification to enforce secure, authenticated message exchanges.

### 2. Federated Learning Role
* **Coordinator (Worker 2)**: Connects to the IDS Broker to discover compatible data providers, negotiates contracts, packages the training algorithm, and triggers multi-round training loops. After each round, it aggregates client model weights (via FedAvg/FedProx) and logs metrics to MLflow.
* **Participant (Workers 1, 3, 4)**: Downloads the distributed training algorithm, trains the model locally on local UNSW-NB15 dataset partitions, and uploads updated weights to the coordinator under IDS contract terms.

---

## Architecture & Component Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       Worker Stack                          │
│                                                             │
│  ┌───────────────────────┐         ┌─────────────────────┐  │
│  │   TRUE Connector      │Multipart│   IDS / FL DataApp  │  │
│  │ (Execution Core / ECC)│◄───────►│      (FastAPI)      │  │
│  └──────────┬────────────┘         └──────────┬──────────┘  │
└─────────────┼─────────────────────────────────┼─────────────┘
              │ IDS Messages                    │ ML Metrics / AI Advice
              ▼ (DAPS, Broker, etc.)            ▼
       IDS Infrastructure               Support Services
       (DAPS/ClearingHouse)            (MLflow / Ollama)
```

1. **ECC Integration**: The DataApp listens on ports exposed only internally to the Docker network. The ECC reverse-proxies incoming IDS artifact/data messages to the DataApp's endpoints.
2. **Security & Authentication**: The DataApp validates DAPS JSON Web Tokens (JWT) before processing data exchange.
3. **MLOps Tracking**: The coordinator DataApp communicates directly with the **MLflow** server to log hyperparameter configurations, metrics per round, confusion matrices, and final models.
4. **AI-Assisted Peer Discovery**: Evaluates local dataset metadata and queries the **Ollama** service (running LLaMA 3.2) to match compatible training profiles.
5. **WebSockets (WS/WSS) Transport Channels**: WebSockets are utilized across two critical pathways in the architecture:
   * **ECC-to-ECC Data Plane**: High-performance distribution of Federated Learning weights between the participant ECC nodes is executed over secure WebSockets (`wss://`) connections to bypass standard HTTP negotiation overhead.
   * **Script-to-Connector Control Plane**: Orchestration and client-facing execution scripts interface with the connector proxy using WebSockets to trigger negotiations and monitor real-time message exchange state.

---

## Core Files

* [app.py](app.py): The main FastAPI application. Contains route definitions for IDS message handling, local training, data app orchestrator state machines, and coordinator aggregation loops.
* [algorithm.py](algorithm.py): Machine Learning implementation. Defines the TensorFlow Keras DNN model, Custom Focal Loss layer, SMOTE class-balancing, feature scaling, evaluation metrics, and FedProx calculation logic.
* [fl_config.json](fl_config.json): Default hyperparameter settings, including number of rounds, local epochs, learning rate, batch size, and the FedProx proximal parameter $\mu$.
* [Dockerfile](Dockerfile): Docker configuration for building the base DataApp service.
* [Dockerfile.algorithm](Dockerfile.algorithm): Builds the isolated, immutable Docker image containing the exact training algorithm, distributed to participants.

---

## API Endpoints

### IDS Connector Specifications
* `GET /api/self-description`: Exposes the worker's data capabilities, dataset schema, and metadata.
* `POST /api/contract/negotiate`: Handles contract negotiations (`ContractRequest`, `ContractAgreement`, `ContractRejection`).
* `POST /api/data/request`: Receives and processes requests for training data or model weights based on active contracts.

### Coordinator & Federated Loop
* `POST /api/orchestration/start`: Triggers the end-to-end 6-phase Federated Learning flow (Coordinator only).
* `POST /api/orchestration/rounds`: Iterates over the specified FL training rounds.
* `POST /api/orchestration/aggregate`: Collects weights from participating workers and performs FedAvg or FedProx aggregation.

### Participant & Training
* `POST /api/train/local`: Performs local training epochs on the worker's dataset partition.
* `GET /api/model/download`: Downloads the latest model weights.
* `POST /api/model/update`: Updates local model weights with the aggregated global model.

---

## ML Model Details

The model is built to detect network intrusions (UNSW-NB15 dataset) categorized into 5 classes (Normal, Generic, Exploits, Fuzzers, DoS).

* **Model Structure**: 
  * Input layer: 19 selected network features.
  * Dense layer: 512 units, ReLU activation, Dropout (0.3).
  * Dense layer: 256 units, ReLU activation, Dropout (0.3).
  * Dense layer: 128 units, ReLU activation, Dropout (0.2).
  * Dense layer: 64 units, ReLU activation.
  * Output layer: 5 units (Softmax) representing the classification probabilities.
* **Extreme Imbalance Management**: 
  * **Focal Loss**: Replaces categorical cross-entropy to focus gradients on hard-to-classify minority attack classes.
  * **SMOTE**: Synthetically oversamples minority attacks in local partitions before training.
* **FedProx Regularization**: Implements a proximal term penalizing local updates that drift too far from the global model:
  $$\text{Loss}_{\text{local}} = \text{Loss}_{\text{focal}} + \frac{\mu}{2} \| w - w^t \|^2$$

---

## Execution

The DataApp starts automatically as part of the `docker-compose` orchestration. For local manual execution (for debugging purposes):

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Service**:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8080
   ```
