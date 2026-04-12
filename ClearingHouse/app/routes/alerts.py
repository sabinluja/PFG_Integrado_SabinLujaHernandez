import logging

from fastapi import APIRouter, HTTPException, status

from app.models import APIResponse
from app.services.logging_service import logging_service

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("", response_model=APIResponse)
@router.get("/active", response_model=APIResponse)
async def get_active_alerts():
    try:
        alerts = logging_service.get_active_alerts()
        response = APIResponse(
            status="success",
            data={
                "total_alerts": len(alerts),
                "alerts": [alert.dict() for alert in alerts]
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in get_active_alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/count", response_model=APIResponse)
async def count_alerts():
    try:
        alerts = logging_service.get_active_alerts()
        severity_counts = {
            "info": 0,
            "warning": 0,
            "error": 0,
            "critical": 0
        }
        
        for alert in alerts:
            severity_counts[alert.severity.value] += 1
        
        response = APIResponse(
            status="success",
            data={
                "total_active_alerts": len(alerts),
                "by_severity": severity_counts
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in count_alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )