# IDS Metadata Broker (broker)

The **IDS Metadata Broker** is the central directory service of the IDS ecosystem. Connectors query the Broker to search and discover available data endpoints, and publish their own self-description profiles.

---

## Role in the Federated Flow

In this Federated Learning pipeline, the Broker plays a key role during the **Discovery Phase (Phase 3)**:
1. **Publishing**: Worker nodes register their connector profiles and dataset metadata on the Broker catalog during startup.
2. **Discovery**: The coordinator DataApp (Worker 2) queries the Broker catalog via SPARQL to find all registered connectors that advertise compatibility with the Federated Learning job.
3. **Retrieval**: Retrieves the endpoints and certificates needed to negotiate contracts and distribute training payloads.

---

## Cryptographic Credentials

This folder contains the TLS keys and Java Keystore (JKS) files used by the Broker instance to secure its HTTPS/TLS channels and verify client credentials:
* `server.crt` / `server.key`: Public TLS certificate and private key used to expose the Broker reverse proxy endpoint safely over HTTPS.
* `isstbroker-keystore.jks`: Java Keystore containing the Broker's private certificate chain, allowing it to authenticate against the DAPS to fetch its own DAT token.

---

## SPARQL Verification & Catalog Inspection

The Broker stores connector catalog profiles as RDF triples using an internal Apache Jena Fuseki database. You can query the live catalog state using SPARQL queries executed directly from Docker.

For the complete list of inspection queries, check the verification guide:
* **[IDS Metadata Broker Verification (Fuseki)](../doc/advancedConfiguration/broker-verification.md)**

### Example: Count Registered Connectors
To quickly check how many connectors are currently registered in the Broker database:
```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT (COUNT(?s) as ?connectors) WHERE { ?s a <https://w3id.org/idsa/core/Connector> }" \
  -H "Accept: application/sparql-results+json"
```
