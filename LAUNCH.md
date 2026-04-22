# 🚀 TRUE Connector — Professional Deployment Guide

> **Architecture Overview:** BYOA (Bring Your Own Algorithm) pattern.
> The Consumer provides a Python algorithm; the Provider executes it across clustered instances, governed by Usage Control policies.

---

## 🛠️ Prerequisites & System Requirements

Before you begin, ensure your environment meets these standards:

| Component | Minimum Version | Command Check | Notes |
| :--- | :--- | :--- | :--- |
| **Docker Engine** | 24.0+ | `docker version` | Ensure Linux containers are enabled on Windows. |
| **Docker Compose** | 2.20+ | `docker compose version` | V2 plugin recommended. |
| **Git** | 2.30+ | `git --version` | For repository management. |
| **RAM** | 4GB+ | - | Recommended for running 3 concurrent BYOA instances. |

---

## ⚡ Quick Start Commands

Efficient commands for managing the lifecycle of the connector.

### 1. Initialization & Startup
Builds the Python images and starts the entire stack in detached mode.

```bash
docker compose up -d --build

docker compose build --no-cache

docker build -t ia-dataapp:latest ./ia-dataapp
docker compose up -d

docker-compose build ia-dataapp-1
docker compose build be-dataapp-consumer
docker-compose up -d
docker compose build --no-cache ia-dataapp-1
docker compose build --no-cache ia-dataapp-2
docker compose build --no-cache ia-dataapp-3
docker compose build --no-cache be-dataapp-consumer
docker compose up -d

docker compose down -v
docker compose build be-dataapp-worker1
docker compose up -d

docker compose down -v
docker compose up -d

```
> **Note:** The `byoa-dataapp-provider-1` service builds the base image used by instances 2 and 3.

### 2. Monitoring & Logs
Stream logs from all containers in real-time to monitor health and activity.

```bash
docker compose logs -f
```

### 3. Graceful Shutdown
Stops running containers but preserves data volumes and networks.

```bash
docker compose down docker logs be-dataapp-consumer
```

### 4. ⚠️ Deep Clean & Reset (Hard Reset)
**Caution:** This command removes EVERYTHING: containers, networks, volumes (data loss), and built images. Use this to reset the project to a pristine state.

```bash
docker compose down -v --rmi all --remove-orphans
docker system prune --volumes

docker rm -f uc-dataapp-pip-provider uc-dataapp-pip-consumer ecc-provider ecc-consumer be-dataapp-consumer be-dataapp-provider uc-dataapp-provider uc-dataapp-consumer ia-dataapp-2 ia-dataapp-3
```

```bash
docker exec be-dataapp-worker1 keytool -delete -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker1" -noprompt 2>$null
docker exec be-dataapp-worker1 keytool -importcert -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker1" -file //cert/dataapp/cert.pem -noprompt
docker exec be-dataapp-worker2 keytool -delete -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker2" -noprompt 2>$null
docker exec be-dataapp-worker2 keytool -importcert -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker2" -file //cert/dataapp/cert.pem -noprompt
docker exec be-dataapp-worker3 keytool -delete -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker3" -noprompt 2>$null
docker exec be-dataapp-worker3 keytool -importcert -keystore //cert/truststoreEcc.jks -storepass allpassword -alias "dataapp-worker3" -file //cert/dataapp/cert.pem -noprompt
```

---

## 🔍 Verification & Health Checks

Verify that the system is operational before proceeding.

| Service | Check URL | Expected Response |
| :--- | :--- | :--- |
| **BYOA Instance 1** | `curl http://localhost:8183/health` | `{"status": "ok", "instance": "1"}` |
| **ECC Provider** | `curl -k https://localhost:8090/actuator/health` | `{"status": "UP"}` |

---

## 🧪 Algorithm Testing (Iris Classifier)

The deployed algorithm is a **k-Nearest Neighbors (KNN) classifier** trained on the Iris dataset.

### Test Payload (Setosa)
Send a POST request to the main endpoint:

```bash
curl -X POST http://localhost:8183/data \
  -H "Content-Type: application/json" \
  -d '{"features": [5.1, 3.5, 1.4, 0.2]}'
```

**Expected JSON Response:**
```json
{
  "prediction": "setosa",
  "confidence": 1.0,
  "k": 3,
  "model": "KNN-Iris",
  "instance": "1"
}
```

---

## 📂 Project Structure Overview

A high-level map of the critical directories:

```
true-connector/
├── src/dataapp/       # 🐍 BYOA Python Source (FastAPI + Algorithm)
├── provider/          # 🏭 Provider Configuration (ECC, Policy, UC)
├── consumer/          # 🛒 Consumer Configuration (ECC, Policy, UC)
├── certs/             # 🔐 TLS Certificates & Keystores
├── postman/           # 📮 API Collections for Testing
└── docker-compose.yml # 🐳 Orchestration Manifest
```
