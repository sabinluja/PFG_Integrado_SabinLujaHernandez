# Worker 4 Node Configuration (worker4)

This directory contains the runtime configurations for **Worker 4**, a participant (data provider) node configured to simulate data sovereignty and contract rejection.

---

## Role in the Federated Learning Stack

* **Role**: FL Participant (Data Sovereignty demonstrator).
* **Data Partition**: Holds no data/active partition, as it is configured to reject contract requests.
* **Behavior**: Evaluates the contract request proposed by the coordinator and rejects it (`ContractRejection` message). This serves to demonstrate data sovereignty by design: the node is excluded from training rounds, and verification steps prove it is denied access to the resulting aggregated model.

---

## Configuration Files

* `ecc/`: Configuration files for the **TRUE Connector Execution Core Container (ECC)**:
  * [application-docker.properties](ecc/application-docker.properties): Configures Spring settings, connecting to the worker's DataApp (`http://be-dataapp-worker4:8500`).
  * [firewall.properties](ecc/firewall.properties): Connection access control lists (ACL) for blocking unauthenticated or unwanted hosts.
  * [users.properties](ecc/users.properties): Credentials for local API authentication.
  * [logback-PROVIDER.xml](ecc/logback-PROVIDER.xml): Logback file configuring ECC log outputs.
