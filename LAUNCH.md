#  TRUE Connector — Professional Deployment Guide

### 1. Initialization & Startup
Builds the Python images and starts the entire stack in detached mode.


```bash
#DESCEN

docker compose down -v
docker compose build be-dataapp-worker1
docker compose up -d

#BASELINE

docker compose up -d mlflow-db mlflow
docker compose --profile baseline run --rm baseline-trainer

```

### 4.  Deep Clean & Reset (Hard Reset)
**Caution:** This command removes EVERYTHING: containers, networks, volumes (data loss), and built images. Use this to reset the project to a pristine state.

```bash
docker compose down -v --rmi all --remove-orphans
docker system prune --volumes
```