# IDS Clearing House Service (ClearingHouse)

A lightweight, high-performance auditing and transaction logging service for the International Data Spaces (IDS) testbed. Built with **FastAPI** and **MongoDB**.

---

## Role in the IDS Ecosystem

The **Clearing House** acts as a neutral, trusted third party that records all transactions and message exchanges between connectors. It ensures:
1. **Auditability**: Provides a verifiable trail of which algorithms, configurations, and models were sent to which workers.
2. **Data Sovereignty Audits (Phase 6)**: During the final phase, audit logs are verified to ensure that unauthorized nodes (like Worker 4) never requested or received model weights or artifact data.
3. **Non-repudiation**: Cryptographically logs message hashes, timestamps, and DAPS token signatures to prevent transaction denial.

---

## Tech Stack

* **Core Framework**: Python 3.10, FastAPI, Uvicorn
* **Database**: MongoDB (transaction storage)
* **Validation**: Pydantic v2
* **Containerization**: Docker & Docker Compose

---

## Codebase Structure

* `app/`: Source code of the FastAPI application.
  * `main.py`: App initialization and route definitions.
  * `database.py`: MongoDB connection management and index definition.
  * `models.py`: Pydantic data schemas for log validation.
* `Dockerfile`: Container build configuration.
* `requirements.txt`: Python package dependencies.

---

## API Endpoint Reference

Access the interactive swagger documentation at `http://localhost:8000/docs` when running.

| Method | Endpoint | Description |
|:---:|:---|:---|
| **POST** | `/api/transactions` | Log a new IDS transaction message |
| **GET** | `/api/transactions` | Query and filter transaction logs |
| **GET** | `/api/stats/system` | Fetch global system statistics |
| **GET** | `/api/alerts/active` | View system alerts (unauthorized access attempts) |
| **GET** | `/health` | Live service health check status |

---

## Deployment

The Clearing House is deployed as a containerized service and starts automatically with the main Docker Compose stack.
