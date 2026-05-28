# Postman Verification Suite (PFG)

This directory contains the Postman collection and environment configurations configured to verify the custom Federated Learning (FL) orchestrator, worker nodes, and security policies.

* **Collection File**: [pfg_collection.json](pfg_collection.json)
* **Environment File**: [pfg_environment.json](pfg_environment.json)

---

## 1. Verification Folders

This collection is structured into six folders, each validating a specific operational module of the PFG architecture:

* **Dataset Registration Catalog (Manual)**: Verifies that worker nodes can load and publish local dataset configurations (e.g., *Titanic dataset*) to make them visible within their local connector catalog.
* **FL Algorithm Deployment Flow**: Coordinates and polls the complete 16-step federated training lifecycle. It validates peer discovery, automated contract negotiations, training rounds (accuracy and loss curves), and model sovereignty (isolating Worker 4 and blocking it from downloading weights due to policy restrictions).
* **DAPS Verification**: Validates the identity provider (Omejdn DAPS) by retrieving its OpenID configuration, downloading public JWKS keys, and checking DAT token requests for the coordinator and worker nodes.
* **Broker Verification**: Validates the registry database by executing direct SPARQL queries against the Apache Jena Fuseki triple store (port `3030`) and checking active connector listings.
* **Contract Negotiation**: Simulates manual HTTPS multipart negotiation messages (Description, Contract, and Artifact requests) to verify security handshake interfaces.
* **Contract Negotiation WS**: Validates the same contract handshakes and payload distribution over WebSockets (`wss://`) channels to test high-performance data planes.

---

## 2. Component Verification Mapping

The folders in this collection map directly to the verification of the following architectural components:

| Component | Target Verification Folder(s) | Key Verified Feature |
| :--- | :--- | :--- |
| **DAPS (Omejdn)** | `DAPS Verification` | Dynamic Attribute Token (DAT) requests and JWKS keys validity |
| **Metadata Broker (Fuseki)** | `Broker Verification` | Active connector discovery and SPARQL query consistency |
| **ECC (Execution Core)** | `Contract Negotiation` & `Contract Negotiation WS` | IDS multipart protocol parsing, HTTP/WebSockets channels |
| **FL DataApps** | `Dataset Registration Catalog` & `FL Algorithm Deployment Flow` | Orchester coordination phases and asynchronous state machine |
| **Data Sovereignty Engine** | `FL Algorithm Deployment Flow` | Access control policy enforcement (Worker 4 exclusion) |




