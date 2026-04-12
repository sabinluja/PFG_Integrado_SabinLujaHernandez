import os

class Config:
    APP_NAME = "IDS Clearing House"
    APP_VERSION = "1.0.0"
    HOST = os.getenv("CH_SERVER_HOST", "0.0.0.0")
    PORT = int(os.getenv("CH_SERVER_PORT", "8000"))
    DEBUG = os.getenv("CH_DEBUG", "False").lower() == "true"
    
    MONGO_URI = os.getenv("CH_MONGO_URI", "mongodb://mongo-ch:27017")
    MONGO_DB_NAME = os.getenv("CH_MONGO_DB_NAME", "clearinghouse")
    MONGO_CONNECT_TIMEOUT = int(os.getenv("CH_MONGO_CONNECT_TIMEOUT", "5000"))
    MONGO_SERVER_SELECTION_TIMEOUT = int(os.getenv("CH_MONGO_SERVER_SELECTION_TIMEOUT", "5000"))
    
    COLLECTION_LOGS = "transaction_logs"
    COLLECTION_CONNECTORS = "connectors"
    COLLECTION_STATS = "statistics"
    COLLECTION_ALERTS = "alerts"
    
    SECRET_KEY = os.getenv("CH_SECRET_KEY", "dev-secret-key-change-in-production")
    API_KEY_HEADER = "X-API-Key"
    API_KEYS = os.getenv("CH_API_KEYS", "").split(",") if os.getenv("CH_API_KEYS") else []
    ENABLE_AUTH = os.getenv("CH_ENABLE_AUTH", "False").lower() == "true"
    
    CORS_ORIGINS = os.getenv("CH_CORS_ORIGINS", "*").split(",")
    
    LOG_LEVEL = os.getenv("CH_LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = os.getenv("CH_LOG_FILE", "clearing-house.log")
    LOG_MAX_BYTES = int(os.getenv("CH_LOG_MAX_BYTES", "10485760"))
    LOG_BACKUP_COUNT = int(os.getenv("CH_LOG_BACKUP_COUNT", "5"))
    
    MAX_PAGE_SIZE = int(os.getenv("CH_MAX_PAGE_SIZE", "1000"))
    DEFAULT_PAGE_SIZE = int(os.getenv("CH_DEFAULT_PAGE_SIZE", "100"))
    MAX_QUERY_DURATION = int(os.getenv("CH_MAX_QUERY_DURATION", "30"))
    
    LOG_RETENTION_DAYS = int(os.getenv("CH_LOG_RETENTION_DAYS", "90"))
    CLEANUP_INTERVAL_HOURS = int(os.getenv("CH_CLEANUP_INTERVAL_HOURS", "24"))
    
    IDS_VERSION = "4.2.7"
    SUPPORTED_IDS_VERSIONS = ["4.0.0", "4.1.0", "4.2.0", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7"]
    
    VALIDATE_IDS_MESSAGES = os.getenv("CH_VALIDATE_IDS_MESSAGES", "True").lower() == "true"
    REQUIRE_DAT_TOKEN = os.getenv("CH_REQUIRE_DAT_TOKEN", "False").lower() == "true"
    
    ENABLE_ALERTS = os.getenv("CH_ENABLE_ALERTS", "True").lower() == "true"
    ALERT_THRESHOLD_ERROR_RATE = float(os.getenv("CH_ALERT_THRESHOLD_ERROR_RATE", "0.1"))
    ALERT_THRESHOLD_RESPONSE_TIME = float(os.getenv("CH_ALERT_THRESHOLD_RESPONSE_TIME", "5.0"))
    
    ENABLE_CACHE = os.getenv("CH_ENABLE_CACHE", "True").lower() == "true"
    CACHE_TTL = int(os.getenv("CH_CACHE_TTL", "300"))
    
    RATE_LIMIT_ENABLED = os.getenv("CH_RATE_LIMIT_ENABLED", "False").lower() == "true"
    RATE_LIMIT_PER_MINUTE = int(os.getenv("CH_RATE_LIMIT_PER_MINUTE", "60"))
    
    DASHBOARD_ENABLED = os.getenv("CH_DASHBOARD_ENABLED", "True").lower() == "true"
    DASHBOARD_REFRESH_INTERVAL = int(os.getenv("CH_DASHBOARD_REFRESH_INTERVAL", "5000"))
    
    ENABLE_METRICS = os.getenv("CH_ENABLE_METRICS", "True").lower() == "true"
    METRICS_UPDATE_INTERVAL = int(os.getenv("CH_METRICS_UPDATE_INTERVAL", "60"))

config = Config()