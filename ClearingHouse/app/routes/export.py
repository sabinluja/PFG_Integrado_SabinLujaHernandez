from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from datetime import datetime
from typing import Optional
import logging
import csv
import json
import io
from app.services.database import db_service
from app.models import TransactionStatus
from app.config import config

logger = logging.getLogger(__name__)

router = APIRouter()

def build_query(
    source_connector: Optional[str],
    target_connector: Optional[str],
    message_type: Optional[str],
    status_filter: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str]
) -> dict:
    query = {}
    
    if source_connector:
        query["source_connector"] = {"$regex": source_connector, "$options": "i"}
    if target_connector:
        query["target_connector"] = {"$regex": target_connector, "$options": "i"}
    if message_type:
        query["message_type"] = message_type
    if status_filter:
        query["status"] = status_filter
    if date_from or date_to:
        date_query = {}
        if date_from:
            date_query["$gte"] = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
        if date_to:
            date_query["$lte"] = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
        query["timestamp"] = date_query
    
    return query

def serialize_doc(doc: dict) -> dict:
    result = {}
    for key, value in doc.items():
        if key == "_id":
            continue
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = serialize_doc(value)
        elif isinstance(value, list):
            result[key] = [serialize_doc(i) if isinstance(i, dict) else i for i in value]
        else:
            result[key] = value
    return result

@router.get("/json")
async def export_json(
    source_connector: Optional[str] = None,
    target_connector: Optional[str] = None,
    message_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=10000)
):
    try:
        collection = db_service.db[config.COLLECTION_LOGS]
        
        query = build_query(
            source_connector,
            target_connector,
            message_type,
            status_filter,
            date_from,
            date_to
        )
        
        cursor = collection.find(query).sort("timestamp", -1).limit(limit)
        docs = [serialize_doc(doc) for doc in cursor]
        
        export_data = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "total_records": len(docs),
            "filters": {
                "source_connector": source_connector,
                "target_connector": target_connector,
                "message_type": message_type,
                "status": status_filter,
                "date_from": date_from,
                "date_to": date_to
            },
            "data": docs
        }
        
        json_content = json.dumps(export_data, indent=2, ensure_ascii=False)
        
        filename = f"clearing_house_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        return StreamingResponse(
            io.StringIO(json_content),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"Error in export_json: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/csv")
async def export_csv(
    source_connector: Optional[str] = None,
    target_connector: Optional[str] = None,
    message_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=10000)
):
    try:
        collection = db_service.db[config.COLLECTION_LOGS]
        
        query = build_query(
            source_connector,
            target_connector,
            message_type,
            status_filter,
            date_from,
            date_to
        )
        
        cursor = collection.find(query).sort("timestamp", -1).limit(limit)
        docs = [serialize_doc(doc) for doc in cursor]
        
        if not docs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found for the given filters"
            )
        
        csv_fields = [
            "transaction_id",
            "timestamp",
            "source_connector",
            "target_connector",
            "message_type",
            "status",
            "http_status_code",
            "response_time_ms",
            "contract_id",
            "resource_id",
            "error_message",
            "client_ip"
        ]
        
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=csv_fields,
            extrasaction='ignore'
        )
        
        writer.writeheader()
        writer.writerows(docs)
        
        output.seek(0)
        
        filename = f"clearing_house_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in export_csv: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )