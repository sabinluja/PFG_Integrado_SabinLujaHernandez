# Verificación del IDS Metadata Broker (Fuseki)

Consultas SPARQL para inspeccionar el estado del Broker IDS en tiempo real.  
Todas se ejecutan contra el endpoint Fuseki interno (`broker-fuseki:3030`) desde dentro de la red Docker.

---

## 1. Contar conectores registrados

Devuelve el número total de conectores IDS (`ids:BaseConnector`) presentes en el catálogo del Broker.

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT (COUNT(*) as ?n) WHERE { GRAPH ?g { ?s a <https://w3id.org/idsa/core/BaseConnector> } }" \
  -H "Accept: application/sparql-results+json"
```

**Resultado esperado:** `?n = 4` (workers 1–4 se auto-registran al arrancar).

---

## 2. Listar conectores con endpoint

Muestra cada conector registrado junto con su endpoint por defecto (`ids:hasDefaultEndpoint`).

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT DISTINCT ?connector ?endpoint WHERE { GRAPH ?g { ?connector a <https://w3id.org/idsa/core/BaseConnector> . OPTIONAL { ?connector <https://w3id.org/idsa/core/hasDefaultEndpoint> ?endpoint } } }" \
  -H "Accept: application/sparql-results+json"
```

**Resultado esperado:** 4 filas con URIs tipo `http://w3id.org/engrd/connector/workerN` y endpoints `https://ecc-workerN:8449/api/ids/data`.

---

## 3. Contar triples totales

Muestra el número total de triples almacenados en todos los grafos del Broker. Útil para verificar que los conectores han publicado su self-description completa.

```bash
docker exec broker-fuseki curl -s -X POST \
  http://localhost:3030/connectorData/sparql \
  --data-urlencode "query=SELECT (COUNT(*) as ?n) WHERE { GRAPH ?g { ?s ?p ?o } }" \
  -H "Accept: application/sparql-results+json"
```

---

## 4. Inspeccionar grafos disponibles

Lista los primeros triples en formato N-Triples para ver qué grafos (named graphs) existen. Cada conector registrado genera su propio grafo.

```bash
docker exec broker-fuseki curl -s \
  http://localhost:3030/connectorData/data \
  -H "Accept: application/n-triples" | head -5
```

---

> **Nota:** Estas consultas se ejecutan directamente contra Fuseki (puerto `3030`). El Broker IDS expone el catálogo de forma estándar en `https://broker-reverseproxy/infrastructure` (puerto host `444`), que es la URL que usan los ECCs para registro y descubrimiento.
