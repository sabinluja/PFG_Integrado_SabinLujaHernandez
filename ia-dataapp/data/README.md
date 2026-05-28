# Data Partition Directory

This directory serves as the local persistent volume storage for datasets, local models, and output logs generated during the Federated Learning simulation.

## Directory Structure

* **`raw/`**: Contains the baseline raw datasets (such as UNSW-NB15, phishing URLs, and Titanic data) used to generate and partition local data for the worker nodes.
* **`worker1/` to `worker4/`**: Isolated local partitions representing the independent storage volumes for each simulation participant. In the dockerized deployment, each container mounts its corresponding directory as its private `data/` volume:
  * **`workerX/input/`**: Contains the local train/test dataset partition (e.g., `unsw_nb15_worker_X.csv`).
  * **`workerX/output/`**: Stores the outputs generated throughout the training and coordination lifecycle:
    * **Local Metrics & Results (`.json` files)**: Contains JSON files documenting local training results, parameters, evaluations, and round metrics.
    * **MLflow Tracking**: Logs training parameters, epoch metrics, confusion matrices, and run history directly to the central MLflow server.
    * **Algorithm & Configuration**: Each worker pulls the training algorithm (`algorithm.py`) and execution configuration (`fl_config.json`) as well as the needed dependencies from the local Docker Registry at the beginning of each round.
    * **Docker Algorithm Image (Coordinator Only)**: The coordinator (Worker 2) packages the required training logic and configurations into a Docker image built from this directory, pushing it to the local registry (`fl-registry:5000`) for distribution.
    * **Final Global Model Weights (Coordinator Only)**: Stores the final aggregated global model weights generated at the end of the federated learning rounds.

## Security Note
These directories simulate isolated, air-gapped filesystems for the different nodes. Access to files in `workerX/` is strictly guarded by the respective connector policies.
