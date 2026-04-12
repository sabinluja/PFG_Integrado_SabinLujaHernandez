import logging

from typing import Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, Query, status

from app.config import config
from app.services.database import db_service
from app.services.dat_validator import dat_validator
from app.services.logging_service import logging_service
from app.models import TransactionLogCreate, QueryFilter, APIResponse, ErrorResponse, TransactionStatus, QueryResponse

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
@router.post("/log", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_transaction_log(transaction_data: TransactionLogCreate, request: Request):
    try:
        request_metadata = {
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent")
        }
        
        transaction_id = logging_service.log_transaction(transaction_data, request_metadata)
        
        if transaction_id:
            response = APIResponse(
                status="success",
                message="Transaction logged successfully",
                data={
                    "transaction_id": transaction_id,
                    "source_connector": transaction_data.source_connector,
                    "message_type": transaction_data.message_type,
                    "status": transaction_data.status.value if transaction_data.status else "success"
                }
            )
            return response
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to log transaction"
            )
    except Exception as e:
        logger.error(f"Error in create_transaction_log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/validate-dat", response_model=APIResponse)
async def validate_dat_token(request: Request):
    try:
        token = request.headers.get("Authorization") or request.headers.get("X-DAT-Token")
        
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No token provided"
            )
        
        result = dat_validator.validate_dat_token(token)
        
        response = APIResponse(
            status="success",
            data=result
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in validate_dat_token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("", response_model=QueryResponse)
@router.get("/query", response_model=QueryResponse)
async def query_transactions(
    source_connector: Optional[str] = None,
    target_connector: Optional[str] = None,
    message_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    contract_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    min_response_time: Optional[float] = None,
    max_response_time: Optional[float] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    sort_by: str = "timestamp",
    sort_order: str = "desc"
):
    try:
        filters_dict = {
            "page": page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_order": sort_order
        }
        
        if source_connector:
            filters_dict["source_connector"] = source_connector
        if target_connector:
            filters_dict["target_connector"] = target_connector
        if message_type:
            filters_dict["message_type"] = message_type
        if contract_id:
            filters_dict["contract_id"] = contract_id
        if resource_id:
            filters_dict["resource_id"] = resource_id
        if min_response_time:
            filters_dict["min_response_time"] = min_response_time
        if max_response_time:
            filters_dict["max_response_time"] = max_response_time
        
        if status_filter:
            try:
                filters_dict["status"] = TransactionStatus(status_filter)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status: {status_filter}"
                )
        
        if date_from:
            try:
                filters_dict["date_from"] = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid date_from format. Use ISO format"
                )
        
        if date_to:
            try:
                filters_dict["date_to"] = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid date_to format. Use ISO format"
                )
        
        if page_size > config.MAX_PAGE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"page_size cannot exceed {config.MAX_PAGE_SIZE}"
            )
        
        filters = QueryFilter(**filters_dict)
        result = logging_service.query_transactions(filters)
        
        if result:
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Query failed"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in query_transactions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/{transaction_id}", response_model=APIResponse)
async def get_transaction(transaction_id: str):
    try:
        transaction = logging_service.get_transaction_by_id(transaction_id)
        
        if transaction:
            response = APIResponse(
                status="success",
                data=transaction.dict()
            )
            return response
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_transaction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/count", response_model=APIResponse)
async def count_transactions():
    try:
        count = db_service.count_transactions()
        response = APIResponse(
            status="success",
            data={"total_transactions": count}
        )
        return response
    except Exception as e:
        logger.error(f"Error in count_transactions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/search/contract/{contract_id}", response_model=APIResponse)
async def search_by_contract(contract_id: str):
    try:
        transactions = logging_service.search_by_contract(contract_id)
        response = APIResponse(
            status="success",
            data={
                "contract_id": contract_id,
                "total_transactions": len(transactions),
                "transactions": [t.dict() for t in transactions]
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in search_by_contract: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/search/resource/{resource_id}", response_model=APIResponse)
async def search_by_resource(resource_id: str):
    try:
        transactions = logging_service.search_by_resource(resource_id)
        response = APIResponse(
            status="success",
            data={
                "resource_id": resource_id,
                "total_transactions": len(transactions),
                "transactions": [t.dict() for t in transactions]
            }
        )
        return response
    except Exception as e:
        logger.error(f"Error in search_by_resource: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/audit/integrity", tags=["Audit"])
async def verify_chain_integrity():
    """
    Recorre todos los logs y verifica que el hash previo coincida.
    """
    logs = db_service.get_all_sorted()
    broken_links = []
    
    for i in range(1, len(logs)):
        current = logs[i]
        previous = logs[i-1]
        
        curr_prev_hash = current.get("previous_hash") if isinstance(current, dict) else getattr(current, "previous_hash", None)
        prev_curr_hash = previous.get("current_hash") if isinstance(previous, dict) else getattr(previous, "current_hash", None)
        
        if curr_prev_hash != prev_curr_hash:
            broken_links.append({
                "transaction_id": current.get("transaction_id") if isinstance(current, dict) else getattr(current, "transaction_id", None),
                "error": "Broken chain detected"
            })
            
    if broken_links:
        return {"status": "CORRUPTED", "broken_links": broken_links}
    return {"status": "INTEGRITY_OK", "checked_logs": len(logs)}