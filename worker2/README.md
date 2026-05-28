# Worker 2 Node Configuration (worker2)

This directory contains the runtime configurations for **Worker 2**, the coordinator and aggregator node in the Federated Learning cluster.

---

## Role in the Federated Learning Stack

* **Role**: FL Coordinator & Aggregator.
* **Data Partition**: Holds $30\%$ of the partitioned UNSW-NB15 dataset.
* **Behavior**: Orchestrates the 6-phase Federated Learning loop. It queries the Broker catalog, initiates contracts, packages the training algorithm, aggregates participant weights using FedAvg/FedProx, and pushes metrics to MLflow.

---

## Configuration Files

* `ecc/`: Configuration files for the **TRUE Connector Execution Core Container (ECC)**:
  * [application-docker.properties](ecc/application-docker.properties): Configures Spring settings, connecting to the coordinator's DataApp (`http://be-dataapp-worker2:8500`).
  * [firewall.properties](ecc/firewall.properties): Connection access control lists (ACL) for the broker and active worker nodes.
  * [users.properties](ecc/users.properties): Credentials for local API authentication.
  * [logback-PROVIDER.xml](ecc/logback-PROVIDER.xml): Logback file configuring ECC log outputs.
