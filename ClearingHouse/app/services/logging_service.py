import uuid
import logging
import hashlib
import json
import threading

from datetime import datetime
from typing import Optional, Dict, Any, List

from app.config import config
from app.services.database import db_service
from app.models import TransactionLog, TransactionLogCreate, Alert, AlertSeverity, QueryFilter, QueryResponse


logger = logging.getLogger(__name__)

class LoggingService:
    def __init__(self):
        self._lock = threading.Lock()
        self.alert_thresholds = {
            "error_rate": config.ALERT_THRESHOLD_ERROR_RATE,
            "response_time": config.ALERT_THRESHOLD_RESPONSE_TIME
        }
    
    def _calculate_hash(self, data: Dict) -> str:
        encoded_data = json.dumps(data, sort_keys=True, default=str).encode()
        return hashlib.sha256(encoded_data).hexdigest()

    def log_transaction(self, transaction_data: TransactionLogCreate, request_metadata: Optional[Dict] = None) -> Optional[str]:
        try:
            transaction_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            log_dict = transaction_data.dict(exclude_none=True)
            log_dict["transaction_id"] = transaction_id
            log_dict["timestamp"] = timestamp
            
            if request_metadata:
                log_dict["client_ip"] = request_metadata.get("client_ip")
                log_dict["user_agent"] = request_metadata.get("user_agent")
            
            if config.VALIDATE_IDS_MESSAGES:
                validation_result = self._validate_ids_message(log_dict)
                if not validation_result["valid"]:
                    log_dict["additional_data"] = log_dict.get("additional_data", {})
                    log_dict["additional_data"]["validation_warnings"] = validation_result["warnings"]

            with self._lock:
                previous_hash = db_service.get_last_log_hash() 
                if not previous_hash:
                    previous_hash = "0" * 64

                log_dict["previous_hash"] = previous_hash

                current_hash = self._calculate_hash(log_dict)
                log_dict["current_hash"] = current_hash
                
                inserted_id = db_service.insert_transaction_log(log_dict)
            
            if inserted_id:
                logger.info(f"Transaction logged: {transaction_id} | Hash: {current_hash[:8]}...")
                if config.ENABLE_ALERTS:
                    self._check_and_create_alerts(log_dict)
                return transaction_id
            else:
                logger.error(f"Insert failed: {transaction_id}")
                return None
        except Exception as e:
            logger.error(f"Log transaction error: {e}")
            return None
    
    def _validate_ids_message(self, log_data: Dict) -> Dict[str, Any]:
        warnings = []

        message_type = log_data.get("message_type")
        if not message_type:
            warnings.append("message_type is missing")
        elif not (str(message_type).startswith("ids:") or "LogMessage" in str(message_type)):
            warnings.append(f"message_type is not in IDS format: {message_type}")

        source = log_data.get("source_connector")
        if not source:
            warnings.append("source_connector is missing")
        elif not (str(source).startswith("http") or str(source).startswith("urn")):
            warnings.append(f"source_connector is not a valid URI: {source}")

        if not log_data.get("target_connector"):
            warnings.append("target_connector is missing")

        header = log_data.get("message_header", {})
        token = header.get("security_token") or log_data.get("security_token") or log_data.get("dat_token")

        if config.REQUIRE_DAT_TOKEN and not token:
            warnings.append("DAT token is missing")

        model_version = log_data.get("model_version") or header.get("model_version")
        if not model_version:
            warnings.append("model_version is missing")

        if not log_data.get("payload") and not log_data.get("payload_hash"):
            warnings.append("Missing payload or payload_hash")

        return {
            "valid": len(warnings) == 0,
            "warnings": warnings
        }
    
    def _check_and_create_alerts(self, log_data: Dict):
        try:
            if log_data.get("status") in ["failed", "error"]:
                self._create_alert(
                    AlertSeverity.ERROR,
                    "Transaction Failed",
                    f"Failed: {log_data.get('source_connector')} -> {log_data.get('target_connector')}",
                    log_data.get("source_connector"),
                    log_data.get("transaction_id"),
                    {"error_message": log_data.get("error_message"), "error_code": log_data.get("error_code")}
                )
            
            response_time = log_data.get("response_time_ms", 0)
            if response_time > self.alert_thresholds["response_time"] * 1000:
                self._create_alert(
                    AlertSeverity.WARNING,
                    "High Response Time",
                    f"Response time: {response_time}ms (threshold: {self.alert_thresholds['response_time']*1000}ms)",
                    log_data.get("source_connector"),
                    log_data.get("transaction_id"),
                    {"response_time_ms": response_time}
                )
            
            self._check_connector_error_rate(log_data.get("source_connector"))
        except Exception as e:
            logger.error(f"Alert check error: {e}")
    
    def _check_connector_error_rate(self, connector_id: str):
        try:
            stats = db_service.get_connector_stats(connector_id)
            if stats and stats["error_rate"] > self.alert_thresholds["error_rate"] * 100:
                self._create_alert(
                    AlertSeverity.WARNING,
                    "High Error Rate",
                    f"Connector {connector_id}: error rate {stats['error_rate']:.2f}%",
                    connector_id,
                    None,
                    {
                        "error_rate": stats["error_rate"],
                        "total_transactions": stats["total_transactions"],
                        "failed_transactions": stats["failed_transactions"]
                    }
                )
        except Exception as e:
            logger.error(f"Error rate check error: {e}")
    
    def _create_alert(self, severity: AlertSeverity, title: str, message: str,
                     connector_id: Optional[str] = None, transaction_id: Optional[str] = None,
                     additional_info: Optional[Dict] = None):
        try:
            alert = Alert(
                severity=severity,
                title=title,
                message=message,
                connector_id=connector_id,
                transaction_id=transaction_id,
                additional_info=additional_info
            )
            alert_id = db_service.insert_alert(alert.dict())
            if alert_id:
                logger.warning(f"Alert created: {title}")
        except Exception as e:
            logger.error(f"Create alert error: {e}")
    
    def query_transactions(self, filters: QueryFilter) -> Optional[QueryResponse]:
        try:
            start_time = datetime.utcnow()
            results, total_count = db_service.query_transactions(filters)
            query_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            transaction_logs = []
            for result in results:
                try:
                    log = TransactionLog(**result)
                    transaction_logs.append(log)
                except Exception as e:
                    logger.warning(f"Parse transaction error: {e}")
                    continue
            
            total_pages = (total_count + filters.page_size - 1) // filters.page_size
            
            return QueryResponse(
                total_count=total_count,
                page=filters.page,
                page_size=filters.page_size,
                total_pages=total_pages,
                data=transaction_logs,
                query_time_ms=round(float(query_time), 2)
            )
        except Exception as e:
            logger.error(f"Query transactions error: {e}")
            return None
    
    def get_transaction_by_id(self, transaction_id: str) -> Optional[TransactionLog]:
        try:
            result = db_service.get_transaction_by_id(transaction_id)
            if result:
                return TransactionLog(**result)
            return None
        except Exception as e:
            logger.error(f"Get transaction error: {e}")
            return None
    
    def get_system_statistics(self) -> Optional[Dict]:
        try:
            return db_service.get_system_stats()
        except Exception as e:
            logger.error(f"System stats error: {e}")
            return None
    
    def get_connector_statistics(self, connector_id: str) -> Optional[Dict]:
        try:
            return db_service.get_connector_stats(connector_id)
        except Exception as e:
            logger.error(f"Connector stats error: {e}")
            return None
    
    def get_time_series_data(self, hours: int = 24) -> List[Dict]:
        try:
            return db_service.get_time_series_data(hours=hours)
        except Exception as e:
            logger.error(f"Time series error: {e}")
            return []
    
    def get_active_alerts(self, limit: int = 100) -> List[Alert]:
        try:
            results = db_service.get_active_alerts(limit=limit)
            return [Alert(**result) for result in results]
        except Exception as e:
            logger.error(f"Get alerts error: {e}")
            return []
    
    def cleanup_old_logs(self, days: Optional[int] = None) -> int:
        try:
            days = days or config.LOG_RETENTION_DAYS
            return db_service.cleanup_old_logs(days)
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0
    
    def search_by_contract(self, contract_id: str) -> List[TransactionLog]:
        try:
            filters = QueryFilter(contract_id=contract_id, page_size=1000)
            response = self.query_transactions(filters)
            return response.data if response else []
        except Exception as e:
            logger.error(f"Search by contract error: {e}")
            return []
    
    def search_by_resource(self, resource_id: str) -> List[TransactionLog]:
        try:
            filters = QueryFilter(resource_id=resource_id, page_size=1000)
            response = self.query_transactions(filters)
            return response.data if response else []
        except Exception as e:
            logger.error(f"Search by resource error: {e}")
            return []

logging_service = LoggingService()