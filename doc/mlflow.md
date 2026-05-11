# MLflow en el proyecto IDS + Federated Learning

## Que es MLflow

MLflow es una herramienta de MLOps para registrar experimentos de machine learning.
En este proyecto no sustituye al IDS, al Broker, al Clearing House ni al coordinador
federado. Su papel es mas sencillo: guardar una bitacora consultable de cada
entrenamiento.

En la practica, MLflow responde a preguntas como:

- Que parametros se usaron: rondas, epochs, batch size, learning rate, FedProx.
- Que metrica dio cada worker en cada ronda: accuracy, AUC, F1, MCC, loss.
- Que metrica global salio tras FedAvg.
- Que dataset local uso cada worker.
- Que artefactos se generaron: `global_model.json`, `fl_results.json`,
  matrices de confusion y resumenes JSON.

## Como encaja con esta arquitectura

El proyecto ya tiene una arquitectura distribuida:

- `be-dataapp-worker1..4`: DataApps Python que entrenan y/o coordinan FL.
- `ecc-worker1..4`: conectores IDS para transporte y control.
- `fl-registry`: registry Docker privado para distribuir el algoritmo.
- `clearinghouse`: auditoria IDS de mensajes y trazabilidad contractual.

MLflow se anade como un servicio mas:

- `mlflow`: servidor de tracking y UI.
- `mlflow-db`: base de datos PostgreSQL para evitar bloqueos cuando varios
  workers escriben metricas a la vez.
- Puerto interno Docker: `http://mlflow:5000`.
- UI desde Windows/host: `http://localhost:5005`.
- Volumen persistente de artefactos: `mlflow_data`.
- Volumen persistente de base de datos: `mlflow_db_data`.

Se desactiva `MLFLOW_SERVER_ENABLE_JOB_EXECUTION`, porque este PFG solo usa
MLflow Tracking. Los jobs internos de MLflow 3.x arrancan Huey para tareas
GenAI/online scoring y Huey usa una cola SQLite separada; al no necesitarse,
desactivarlos evita mensajes `sqlite3.OperationalError: database is locked`.

Las DataApps tratan MLflow como observabilidad no critica: si el servidor de
tracking no responde o Docker tiene un fallo temporal de resolucion DNS, el
registro falla rapido y el entrenamiento federado continua por IDS/ECC.

Los DataApps registran runs automaticamente cuando hacen entrenamiento:

- Run local: `worker-N-round-R-local`.
- Run global: `coordinator-N-round-R-global`.
- Run resumen: `coordinator-N-summary`.

## Como arrancarlo

Reconstruye la imagen Python porque se ha anadido la dependencia `mlflow`:

```bash
docker compose up -d --build mlflow-db mlflow be-dataapp-worker1 be-dataapp-worker2 be-dataapp-worker3 be-dataapp-worker4
```

O, si quieres levantar todo el stack:

```bash
docker compose up -d --build
```

Despues abre:

```text
http://localhost:5005
```

Tambien puedes comprobar desde un DataApp:

```bash
curl http://localhost:5001/mlflow/status
```

## Que mirar en la UI

En la UI de MLflow abre el experimento `PFG_IDS_Federated_Learning`.

Runs locales:

- `worker-1-round-1-local`
- `worker-2-round-1-local`
- `worker-3-round-1-local`

Runs globales:

- `coordinator-1-round-1-global`
- `coordinator-1-round-2-global`

Resumen final:

- `coordinator-1-summary`

En cada run puedes comparar parametros, metricas y artefactos. Para el PFG,
esto complementa muy bien al Clearing House: Clearing House demuestra la
trazabilidad IDS de los intercambios; MLflow demuestra la trazabilidad tecnica
del entrenamiento de IA.

## Graficos generados para la memoria

Ademas de las curvas interactivas de MLflow, la integracion genera imagenes PNG
como artefactos para poder usarlas directamente en la memoria o presentacion:

- `f1_per_class_round_<ronda>_worker_<n>.png`: F1-score por clase de cada worker.
- `confusion_matrix_round_<ronda>_worker_<n>.png`: matriz de confusion local.
- `feature_importance_round_<ronda>_worker_<n>.png`: top de variables mas influyentes.
- `worker_comparison_round_<ronda>.png`: comparativa de accuracy, F1, focus F1 y MCC entre workers.
- `global_metrics_evolution.png`: evolucion global de accuracy, AUC, F1, focus F1 y MCC.
- `global_loss_evolution.png`: perdida global por ronda.
- `round_time_and_workers.png`: duracion de cada ronda y quorum de workers.
- `best_global_metrics.png`: resumen visual del mejor modelo global.
- `transport_performance.png`: latencia y tamano de payload en las transferencias de pesos.

Para verlas:

1. Entra en `Experiments`.
2. Abre `PFG_IDS_Federated_Learning`.
3. Abre un run local, global o de resumen.
4. Ve a la pestana `Artifacts`.
