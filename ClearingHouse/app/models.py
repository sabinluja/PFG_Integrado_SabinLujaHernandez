from enum import Enum
from datetime import datetime

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

class TransactionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    ERROR = "error"

class MessageType(str, Enum):
    DESCRIPTION_REQUEST = "ids:DescriptionRequestMessage"
    DESCRIPTION_RESPONSE = "ids:DescriptionResponseMessage"
    ARTIFACT_REQUEST = "ids:ArtifactRequestMessage"
    ARTIFACT_RESPONSE = "ids:ArtifactResponseMessage"
    CONTRACT_REQUEST = "ids:ContractRequestMessage"
    CONTRACT_AGREEMENT = "ids:ContractAgreementMessage"
    CONTRACT_OFFER = "ids:ContractOfferMessage"
    REJECTION = "ids:RejectionMessage"
    NOTIFICATION = "ids:NotificationMessage"
    QUERY = "ids:QueryMessage"
    RESULT = "ids:ResultMessage"
    OTHER = "other"

class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class IDSMessageHeader(BaseModel):
    message_type: str
    issued: Optional[datetime] = Field(default_factory=datetime.utcnow)
    issuer_connector: Optional[str] = None
    sender_agent: Optional[str] = None
    recipient_connector: Optional[List[str]] = None
    security_token: Optional[Dict[str, Any]] = None
    transfer_contract: Optional[str] = None
    content_version: Optional[str] = None

class TransactionLog(BaseModel):
    transaction_id: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_connector: str
    target_connector: Optional[str] = None
    message_type: str
    message_header: Optional[IDSMessageHeader] = None
    payload: Optional[Any] = None
    payload_size: Optional[int] = None
    status: TransactionStatus = TransactionStatus.SUCCESS
    http_status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    security_token_valid: Optional[bool] = None
    security_token_issuer: Optional[str] = None
    contract_id: Optional[str] = None
    policy_enforced: Optional[bool] = None
    resource_id: Optional[str] = None
    artifact_id: Optional[str] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

class TransactionLogCreate(BaseModel):
    source_connector: str
    target_connector: Optional[str] = None
    message_type: str
    message_header: Optional[Dict[str, Any]] = None
    payload: Optional[Any] = None
    status: Optional[TransactionStatus] = TransactionStatus.SUCCESS
    http_status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    security_token_valid: Optional[bool] = None
    contract_id: Optional[str] = None
    resource_id: Optional[str] = None
    error_message: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None

class QueryFilter(BaseModel):
    source_connector: Optional[str] = None
    target_connector: Optional[str] = None
    message_type: Optional[str] = None
    status: Optional[TransactionStatus] = None
    contract_id: Optional[str] = None
    resource_id: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    min_response_time: Optional[float] = None
    max_response_time: Optional[float] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=1000)
    sort_by: str = Field(default="timestamp")
    sort_order: str = Field(default="desc")

class QueryResponse(BaseModel):
    status: str = "success"
    total_count: int
    page: int
    page_size: int
    total_pages: int
    data: List[TransactionLog]
    query_time_ms: Optional[float] = None

class ConnectorStats(BaseModel):
    connector_id: str
    total_transactions: int = 0
    successful_transactions: int = 0
    failed_transactions: int = 0
    average_response_time: float = 0.0
    total_data_transferred_bytes: int = 0
    last_activity: Optional[datetime] = None
    message_type_distribution: Dict[str, int] = {}
    error_rate: float = 0.0

class SystemStats(BaseModel):
    total_transactions: int = 0
    total_connectors: int = 0
    active_connectors_24h: int = 0
    successful_transactions: int = 0
    failed_transactions: int = 0
    success_rate: float = 0.0
    average_response_time: float = 0.0
    total_data_transferred_bytes: int = 0
    most_active_connector: Optional[str] = None
    most_used_message_type: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class TimeSeriesDataPoint(BaseModel):
    timestamp: datetime
    count: int
    success_count: int
    failed_count: int
    average_response_time: float

class Alert(BaseModel):
    alert_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: AlertSeverity
    title: str
    message: str
    connector_id: Optional[str] = None
    transaction_id: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None

class APIResponse(BaseModel):
    status: str
    message: Optional[str] = None
    data: Optional[Any] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseModel):
    status: str = "error"
    error: str
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    database_connected: bool
    total_logs: int
    features_enabled: Dict[str, bool]
    timestamp: datetime = Field(default_factory=datetime.utcnow)