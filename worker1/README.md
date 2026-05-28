# Worker 1 Node Configuration (worker1)

This directory contains the runtime configurations for **Worker 1**, a participant (data provider) node in the Federated Learning cluster.

---

## Role in the Federated Learning Stack

* **Role**: FL Participant (Data Provider).
* **Data Partition**: Holds $50\%$ of the partitioned UNSW-NB15 network traffic dataset (representing a large enterprise network node).
* **Behavior**: Receives the training algorithm, verifies identity tokens via DAPS, negotiates the IDS contract, executes local training epochs, and responds with updated model weights.

---

## Configuration Files

* `ecc/`: Configuration files for the **TRUE Connector Execution Core Container (ECC)**:
  * [application-docker.properties](ecc/application-docker.properties): Configures Spring properties including DAPS URL, Metadata Broker URL, H2 local audit database, memory limits, and the internal DataApp endpoint (`http://be-dataapp-worker1:8500`).
  * [firewall.properties](ecc/firewall.properties): Specifies white/blacklisted connection rules for partner connector instances.
  * [users.properties](ecc/users.properties): Defines local administrator credentials for accessing the connector's administration REST API.
  * [logback-PROVIDER.xml](ecc/logback-PROVIDER.xml): Logback file configuring ECC log outputs.
