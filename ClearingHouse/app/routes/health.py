import time

from datetime import datetime

from fastapi import APIRouter, status

from app.config import config
from app.services.database import db_service
from app.models import HealthResponse, APIResponse

router = APIRouter()
start_time = time.time()

@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check():
    try:
        db_connected = db_service.connected
        total_logs = 0
        if db_connected:
            try:
                total_logs = db_service.count_transactions()
            except:
                total_logs = -1
        
        uptime = time.time() - start_time
        health_status = "healthy" if db_connected else "unhealthy"
        
        response = HealthResponse(
            status=health_status,
            version=config.APP_VERSION,
            uptime_seconds=round(uptime, 2),
            database_connected=db_connected,
            total_logs=total_logs,
            features_enabled={
                "authentication": config.ENABLE_AUTH,
                "alerts": config.ENABLE_ALERTS,
                "cache": config.ENABLE_CACHE,
                "rate_limiting": config.RATE_LIMIT_ENABLED,
                "dashboard": config.DASHBOARD_ENABLED,
                "metrics": config.ENABLE_METRICS,
                "ids_validation": config.VALIDATE_IDS_MESSAGES
            }
        )
        
        status_code = status.HTTP_200_OK if health_status == "healthy" else status.HTTP_503_SERVICE_UNAVAILABLE
        return response
    
    except Exception as e:
        return HealthResponse(
            status="unhealthy",
            version=config.APP_VERSION,
            uptime_seconds=0,
            database_connected=False,
            total_logs=-1,
            features_enabled={}
        )

@router.get("/", response_model=APIResponse)
@router.get("/info", response_model=APIResponse)
async def info():
    response = APIResponse(
        status="success",
        data={
            "service": config.APP_NAME,
            "version": config.APP_VERSION,
            "ids_version": config.IDS_VERSION,
            "supported_ids_versions": config.SUPPORTED_IDS_VERSIONS,
            "endpoints": {
                "health": "/health",
                "info": "/info",
                "transactions": {
                    "create": "POST /api/transactions",
                    "query": "GET /api/transactions",
                    "get_by_id": "GET /api/transactions/{id}"
                },
                "statistics": {
                    "system": "GET /api/stats",
                    "connector": "GET /api/stats/connector/{connector_id}",
                    "time_series": "GET /api/stats/timeseries"
                },
                "alerts": {
                    "list": "GET /api/alerts"
                },
                "docs": "/docs"
            }
        }
    )
    return response

@router.get("/ping")
async def ping():
    return {
        "status": "success",
        "message": "pong",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/ready")
async def readiness():
    if not db_service.connected:
        return {
            "status": "not_ready",
            "reason": "database_not_connected"
        }
    return {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/live")
async def liveness():
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }