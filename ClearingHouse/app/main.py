import os
import sys
import json
import logging

from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request, status, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from app.config import config
from app.services.database import db_service
from app.services.logging_service import logging_service
from app.routes import health, transactions, statistics, alerts, export
from app.models import TransactionLogCreate

from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

def setup_logging():
    os.makedirs('logs', exist_ok=True)
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    
    file_handler = RotatingFileHandler(
        f'logs/{config.LOG_FILE}',
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logging.getLogger('uvicorn').setLevel(logging.WARNING)
    logging.getLogger('pymongo').setLevel(logging.WARNING)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger = logging.getLogger(__name__)
    logger.info("=" * 70)
    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION}")
    logger.info("=" * 70)
    
    if not db_service.connect():
        logger.critical("Could not connect to database")
        logger.warning("Service will continue without database")
    else:
        logger.info("Database connected successfully")
    
    logger.info("=" * 70)
    logger.info(f"{config.APP_NAME} started successfully")
    logger.info(f"Server: {config.HOST}:{config.PORT}")
    logger.info(f"Mode: {'DEBUG' if config.DEBUG else 'PRODUCTION'}")
    logger.info(f"Authentication: {'Enabled' if config.ENABLE_AUTH else 'Disabled'}")
    logger.info(f"Alerts: {'Enabled' if config.ENABLE_ALERTS else 'Disabled'}")
    logger.info("=" * 70)
    
    yield
    
    logger.info("Shutting down...")
    db_service.disconnect()

setup_logging()

app = FastAPI(
    title=config.APP_NAME,
    description="Sistema de Auditoría y Logging para International Data Spaces",
    version=config.APP_VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(transactions.router, prefix="/api/transactions", tags=["transactions"])
app.include_router(statistics.router, prefix="/api/stats", tags=["statistics"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(export.router, prefix="/api/export", tags=["export"])


async def _read_form_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, UploadFile):
        raw = await value.read()
        return raw.decode("utf-8", errors="ignore")
    return str(value)


def _normalize_ids_header(header: dict) -> dict:
    recipient = header.get("ids:recipientConnector") or header.get("recipient_connector") or []
    recipient_ids = []
    for item in recipient:
        if isinstance(item, dict):
            uri = item.get("@id") or item.get("id")
        else:
            uri = str(item)
        if uri:
            recipient_ids.append(uri)

    issued = header.get("issued")
    ids_issued = header.get("ids:issued")
    if not issued and isinstance(ids_issued, dict):
        issued = ids_issued.get("@value")

    issuer = header.get("issuer_connector")
    ids_issuer = header.get("ids:issuerConnector")
    if not issuer and isinstance(ids_issuer, dict):
        issuer = ids_issuer.get("@id")

    sender = header.get("sender_agent")
    ids_sender = header.get("ids:senderAgent")
    if not sender and isinstance(ids_sender, dict):
        sender = ids_sender.get("@id")

    transfer_contract = header.get("transfer_contract")
    ids_transfer_contract = header.get("ids:transferContract")
    if not transfer_contract and isinstance(ids_transfer_contract, dict):
        transfer_contract = ids_transfer_contract.get("@id")

    security_token = header.get("security_token") or header.get("ids:securityToken")

    return {
        "message_type": header.get("message_type") or header.get("@type") or "ids:LogMessage",
        "issued": issued,
        "issuer_connector": issuer,
        "sender_agent": sender,
        "recipient_connector": recipient_ids,
        "security_token": security_token,
        "transfer_contract": transfer_contract,
        "content_version": header.get("content_version") or header.get("ids:contentVersion"),
        "model_version": header.get("model_version") or header.get("ids:modelVersion"),
    }


@app.post("/data")
async def receive_ids_log_message(request: Request):
    """
    Endpoint DataApp-compatible para el ECC del Clearing House.
    Recibe multipart IDS desde el connector y lo traduce al modelo interno
    de auditoria ya existente.
    """
    logger = logging.getLogger(__name__)
    try:
        logger.info("Incoming IDS multipart log received from ECC gateway")
        form = await request.form()
        header_raw = await _read_form_value(form.get("header"))
        payload_raw = await _read_form_value(form.get("payload"))

        header = json.loads(header_raw) if header_raw else {}
        payload = json.loads(payload_raw) if payload_raw else {}
        ids_header = _normalize_ids_header(header)

        source_connector = (
            payload.get("source_connector")
            or ids_header.get("issuer_connector")
            or "http://w3id.org/engrd/connector/unknown"
        )
        target_connector = (
            payload.get("target_connector")
            or (ids_header.get("recipient_connector") or [None])[0]
        )
        message_type = (
            payload.get("message_type")
            or ids_header.get("message_type")
            or "ids:LogMessage"
        )

        status_value = str(payload.get("status", "success")).lower()
        if status_value not in {"success", "failed", "pending", "error"}:
            status_value = "success"

        transaction_data = TransactionLogCreate(
            source_connector=source_connector,
            target_connector=target_connector,
            message_type=message_type,
            message_header=ids_header,
            payload=payload,
            status=status_value,
            response_time_ms=payload.get("response_time_ms"),
            security_token_valid=payload.get("security_token_valid"),
            contract_id=payload.get("contract_id"),
            resource_id=payload.get("resource_id"),
            error_message=payload.get("error_message"),
            additional_data=payload.get("additional_data"),
        )

        request_metadata = {
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
        transaction_id = logging_service.log_transaction(transaction_data, request_metadata)
        if not transaction_id:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "error", "message": "Could not persist IDS log message"},
            )

        logger.info(
            "IDS LogMessage received via ECC: %s -> %s (%s)",
            source_connector,
            target_connector,
            message_type,
        )
        return {
            "status": "success",
            "message": "IDS log message received",
            "transaction_id": transaction_id,
        }
    except Exception as exc:
        logger.error(f"Error processing IDS log message from ECC: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "message": str(exc)},
        )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "error": "Validation error",
            "error_code": "VALIDATION_ERROR",
            "details": exc.errors()
        }
    )

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "status": "error",
            "error": "Endpoint not found",
            "error_code": "NOT_FOUND"
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger = logging.getLogger(__name__)
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error": "Internal server error",
            "error_code": "INTERNAL_ERROR"
        }
    )
