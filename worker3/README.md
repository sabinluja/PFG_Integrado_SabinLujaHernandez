# Worker 3 Node Configuration (worker3)

This directory contains the runtime configurations for **Worker 3**, a participant (data provider) node in the Federated Learning cluster.

---

## Role in the Federated Learning Stack

* **Role**: FL Participant (Data Provider).
* **Data Partition**: Holds $20\%$ of the partitioned UNSW-NB15 network traffic dataset (representing a small enterprise network node).
* **Behavior**: Receives the training algorithm, verifies identity tokens via DAPS, negotiates the IDS contract, executes local training epochs, and responds with updated model weights.

---

## Configuration Files

* `ecc/`: Configuration files for the **TRUE Connector Execution Core Container (ECC)**:
  * [application-docker.properties](ecc/application-docker.properties): Configures Spring settings, connecting to the worker's DataApp (`http://be-dataapp-worker3:8500`).
  * [firewall.properties](ecc/firewall.properties): Connection access control lists (ACL) for incoming worker/coordinator requests.
  * [users.properties](ecc/users.properties): Credentials for local API authentication.
  * [logback-PROVIDER.xml](ecc/logback-PROVIDER.xml): Logback file configuring ECC log outputs.
