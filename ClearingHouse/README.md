# IDS Clearing House Service

A lightweight, high-performance auditing and logging service for the International Data Spaces (IDS) testbed. Built with **FastAPI** and **MongoDB**.

## Features

- **Immutable Logging**: Securely records connector transactions and IDS messages.
- **Analytics**: Real-time insights, connector statistics, and performance metrics.
- **Alerting**: Automated detection of errors, high response times, and anomalies.
- **Search**: Advanced filtering by connector ID, message type, date, and status.

## Tech Stack

- **Core**: Python 3.9+, FastAPI, Uvicorn
- **Database**: MongoDB (via PyMongo)
- **Validation**: Pydantic v2

## Quick Start

### Docker (Recommended)

Run as part of the IDS Testbed environment:

```bash
docker-compose up -d clearing-house
```

### Local Development

1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the service**:
    ```bash
    uvicorn app.main:app --reload --port 8000
    ```

## Configuration

Configuration is managed via environment variables (defaults shown):

| Variable | Default | Description |
|:--- |:--- |:--- |
| `CH_MONGO_URI` | `mongodb://mongo-ch:27017` | MongoDB connection string |
| `CH_LOG_LEVEL` | `INFO` | Logging verbosity |
| `CH_ENABLE_AUTH` | `False` | Enable API key authentication |
| `CH_ENABLE_ALERTS` | `True` | Enable automated alerts |
| `CH_LOG_RETENTION_DAYS`| `90` | Days to keep logs (0 = forever) |

## API Endpoints

Access the interactive documentation at `http://localhost:8000/docs`.

**Key Resources:**

-   `POST /api/transactions` - Log a new transaction
-   `GET /api/transactions` - Query/search logs
-   `GET /api/stats/system` - Global system statistics
-   `GET /api/alerts/active` - View active system alerts
-   `GET /health` - Health check status
