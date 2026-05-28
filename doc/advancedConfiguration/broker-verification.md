# IDS Metadata Broker Verification (Fuseki)

SPARQL queries to inspect the live state of the IDS Metadata Broker.  
All commands run against the internal Fuseki endpoint (`broker-fuseki:3030`) from within the Docker network.

---

## 1. Count registered connectors

Returns the total number of IDS connectors (`ids:BaseConnector`) present in the Broker catalog.

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT (COUNT(*) as ?n) WHERE { GRAPH ?g { ?s a <https://w3id.org/idsa/core/BaseConnector> } }" \
  -H "Accept: application/sparql-results+json"
```

**Expected result:** `?n = 4` (workers 1–4 self-register on startup).

---

## 2. List connectors with endpoints

Shows every registered connector along with its default endpoint (`ids:hasDefaultEndpoint`).

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT DISTINCT ?connector ?endpoint WHERE { GRAPH ?g { ?connector a <https://w3id.org/idsa/core/BaseConnector> . OPTIONAL { ?connector <https://w3id.org/idsa/core/hasDefaultEndpoint> ?endpoint } } }" \
  -H "Accept: application/sparql-results+json"
```

**Expected result:** 4 rows with URIs like `http://w3id.org/engrd/connector/workerN` and endpoints `https://ecc-workerN:8449/api/ids/data`.

---

## 3. Count total triples

Returns the total number of triples stored across all named graphs. Useful to verify that connectors have published their full self-description.

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT (COUNT(*) as ?n) WHERE { GRAPH ?g { ?s ?p ?o } }" \
  -H "Accept: application/sparql-results+json"
```

---

## 4. Inspect available graphs

Lists the first triples in N-Triples format to see which named graphs exist. Each registered connector generates its own graph.

```bash
docker exec broker-fuseki curl -s \
  http://localhost:3030/connectorData/data \
  -H "Accept: application/n-triples" | head -5
```

---

> **Note:** These queries target Fuseki directly (port `3030`). The IDS Broker exposes its standard catalog at `https://broker-reverseproxy/infrastructure` (host port `444`), which is the URL used by ECCs for registration and discovery.
