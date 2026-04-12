import logging

from fastapi import APIRouter, HTTPException, Query, status

from app.config import config
from app.models import APIResponse
from app.services.logging_service import logging_service

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("", response_model=APIResponse)
@router.get("/system", response_model=APIResponse)
async def get_system_statistics():
    try:
        stats = logging_service.get_system_statistics()
        if stats:
            response = APIResponse(status="success", data=stats)
            return response
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get system statistics"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_system_statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/connector/{connector_id:path}", response_model=APIResponse)
async def get_connector_statistics(connector_id: str):
    try:
        stats = logging_service.get_connector_statistics(connector_id)
        if stats:
            response = APIResponse(status="success", data=stats)
            return response
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No statistics found for connector: {connector_id}"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_connector_statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/timeseries", response_model=APIResponse)
async def get_time_series_data(hours: int = Query(24, ge=1, le=168)):
    try:
        data = logging_service.get_time_series_data(hours=hours)
        response = APIResponse(
            status="success",
            data={
                "hours": hours,
                "data_points": len(data),
                "time_series": data
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in get_time_series_data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/connectors", response_model=APIResponse)
async def list_connectors():
    try:
        from app.services.database import db_service
        collection = db_service.db[config.COLLECTION_LOGS]
        
        pipeline = [
            {"$group": {
                "_id": "$source_connector",
                "transaction_count": {"$sum": 1},
                "last_activity": {"$max": "$timestamp"}
            }},
            {"$sort": {"transaction_count": -1}}
        ]
        
        connectors = []
        for doc in collection.aggregate(pipeline):
            connectors.append({
                "connector_id": doc["_id"],
                "transaction_count": doc["transaction_count"],
                "last_activity": doc["last_activity"].isoformat() if doc.get("last_activity") else None
            })
        
        response = APIResponse(
            status="success",
            data={
                "total_connectors": len(connectors),
                "connectors": connectors
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in list_connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/message-types", response_model=APIResponse)
async def get_message_type_distribution():
    try:
        from app.services.database import db_service
        collection = db_service.db[config.COLLECTION_LOGS]
        
        pipeline = [
            {"$group": {"_id": "$message_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        
        distribution = {}
        total = 0
        for doc in collection.aggregate(pipeline):
            distribution[doc["_id"]] = doc["count"]
            total += doc["count"]
        
        percentages = {}
        for msg_type, count in distribution.items():
            percentages[msg_type] = {
                "count": count,
                "percentage": round(count / total * 100, 2) if total > 0 else 0
            }
        
        response = APIResponse(
            status="success",
            data={
                "total_messages": total,
                "unique_types": len(distribution),
                "distribution": percentages
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in get_message_type_distribution: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/performance", response_model=APIResponse)
async def get_performance_metrics():
    try:
        from app.services.database import db_service
        collection = db_service.db[config.COLLECTION_LOGS]
        
        pipeline = [
            {"$match": {"response_time_ms": {"$exists": True, "$ne": None}}},
            {"$group": {
                "_id": None,
                "avg_response_time": {"$avg": "$response_time_ms"},
                "min_response_time": {"$min": "$response_time_ms"},
                "max_response_time": {"$max": "$response_time_ms"}
            }}
        ]
        
        performance = list(collection.aggregate(pipeline))
        
        if performance:
            perf_data = performance[0]
            metrics = {
                "average_response_time_ms": round(perf_data.get("avg_response_time", 0), 2),
                "min_response_time_ms": round(perf_data.get("min_response_time", 0), 2),
                "max_response_time_ms": round(perf_data.get("max_response_time", 0), 2)
            }
        else:
            metrics = {
                "average_response_time_ms": 0,
                "min_response_time_ms": 0,
                "max_response_time_ms": 0
            }
        
        total = collection.count_documents({})
        success = collection.count_documents({"status": "success"})
        failed = collection.count_documents({"status": {"$in": ["failed", "error"]}})
        
        metrics.update({
            "total_transactions": total,
            "successful_transactions": success,
            "failed_transactions": failed,
            "success_rate": round(success / total * 100, 2) if total > 0 else 0,
            "error_rate": round(failed / total * 100, 2) if total > 0 else 0
        })
        
        response = APIResponse(status="success", data=metrics)
        return response
    except Exception as e:
        logger.error(f"Error in get_performance_metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/top-connectors", response_model=APIResponse)
async def get_top_connectors(limit: int = Query(10, ge=1, le=100)):
    try:
        from app.services.database import db_service
        collection = db_service.db[config.COLLECTION_LOGS]
        
        pipeline = [
            {"$group": {
                "_id": "$source_connector",
                "transaction_count": {"$sum": 1},
                "success_count": {"$sum": {"$cond": [{"$eq": ["$status", "success"]}, 1, 0]}},
                "failed_count": {"$sum": {"$cond": [{"$in": ["$status", ["failed", "error"]]}, 1, 0]}},
                "avg_response_time": {"$avg": "$response_time_ms"},
                "last_activity": {"$max": "$timestamp"}
            }},
            {"$sort": {"transaction_count": -1}},
            {"$limit": limit}
        ]
        
        top_connectors = []
        for doc in collection.aggregate(pipeline):
            top_connectors.append({
                "connector_id": doc["_id"],
                "transaction_count": doc["transaction_count"],
                "success_count": doc["success_count"],
                "failed_count": doc["failed_count"],
                "success_rate": round(doc["success_count"] / doc["transaction_count"] * 100, 2) if doc["transaction_count"] > 0 else 0,
                "average_response_time_ms": round(doc.get("avg_response_time", 0) or 0, 2),
                "last_activity": doc["last_activity"].isoformat() if doc.get("last_activity") else None
            })
        
        response = APIResponse(
            status="success",
            data={
                "limit": limit,
                "connectors": top_connectors
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in get_top_connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )