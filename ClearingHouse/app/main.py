import os
import sys
import logging

from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from app.config import config
from app.services.database import db_service
from app.routes import health, transactions, statistics, alerts, export

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