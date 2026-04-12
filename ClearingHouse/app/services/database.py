import logging

from bson import ObjectId
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.config import config
from app.models import QueryFilter

logger = logging.getLogger(__name__)

class DatabaseService:
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self.connected = False
        
    def connect(self) -> bool:
        try:
            self.client = MongoClient(
                config.MONGO_URI,
                connectTimeoutMS=config.MONGO_CONNECT_TIMEOUT,
                serverSelectionTimeoutMS=config.MONGO_SERVER_SELECTION_TIMEOUT
            )
            self.client.server_info()
            self.db = self.client[config.MONGO_DB_NAME]
            self.connected = True
            self._create_indexes()
            logger.info(f"Connected to MongoDB: {config.MONGO_DB_NAME}")
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"MongoDB connection error: {e}")
            self.connected = False
            return False
    
    def _create_indexes(self):
        try:
            logs = self.db[config.COLLECTION_LOGS]
            logs.create_index([("timestamp", DESCENDING)])
            logs.create_index([("source_connector", ASCENDING)])
            logs.create_index([("target_connector", ASCENDING)])
            logs.create_index([("message_type", ASCENDING)])
            logs.create_index([("status", ASCENDING)])
            logs.create_index([("contract_id", ASCENDING)])
            logs.create_index([("resource_id", ASCENDING)])
            logs.create_index([("timestamp", DESCENDING), ("source_connector", ASCENDING), ("status", ASCENDING)])
            if config.LOG_RETENTION_DAYS > 0:
                logs.create_index("timestamp", expireAfterSeconds=config.LOG_RETENTION_DAYS * 24 * 3600)
            logger.info("Indexes created")
        except Exception as e:
            logger.warning(f"Index creation error: {e}")
    
    def disconnect(self):
        if self.client:
            self.client.close()
            self.connected = False
    
    def insert_transaction_log(self, log_data: Dict[str, Any]) -> Optional[str]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.utcnow()
            if "payload" in log_data and log_data["payload"]:
                import json
                log_data["payload_size"] = len(json.dumps(log_data["payload"]))
            result = collection.insert_one(log_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Insert error: {e}")
            return None
    
    def get_transaction_by_id(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            query = {}
            if ObjectId.is_valid(transaction_id):
                query = {"_id": ObjectId(transaction_id)}
            else:
                query = {"transaction_id": transaction_id}
            result = collection.find_one(query)
            if result:
                result["_id"] = str(result["_id"])
                return result
            return None
        except Exception as e:
            logger.error(f"Get transaction error: {e}")
            return None
    
    def query_transactions(self, filters: QueryFilter) -> Tuple[List[Dict], int]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            query = {}
            
            if filters.source_connector:
                query["source_connector"] = {"$regex": filters.source_connector, "$options": "i"}
            if filters.target_connector:
                query["target_connector"] = {"$regex": filters.target_connector, "$options": "i"}
            if filters.message_type:
                query["message_type"] = filters.message_type
            if filters.status:
                query["status"] = filters.status.value
            if filters.contract_id:
                query["contract_id"] = filters.contract_id
            if filters.resource_id:
                query["resource_id"] = filters.resource_id
            
            if filters.date_from or filters.date_to:
                date_query = {}
                if filters.date_from:
                    date_query["$gte"] = filters.date_from
                if filters.date_to:
                    date_query["$lte"] = filters.date_to
                query["timestamp"] = date_query
            
            if filters.min_response_time or filters.max_response_time:
                response_time_query = {}
                if filters.min_response_time:
                    response_time_query["$gte"] = filters.min_response_time
                if filters.max_response_time:
                    response_time_query["$lte"] = filters.max_response_time
                query["response_time_ms"] = response_time_query
            
            total_count = collection.count_documents(query)
            sort_direction = DESCENDING if filters.sort_order == "desc" else ASCENDING
            skip = (filters.page - 1) * filters.page_size
            cursor = collection.find(query).sort(filters.sort_by, sort_direction).skip(skip).limit(filters.page_size)
            
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            
            return results, total_count
        except Exception as e:
            logger.error(f"Query error: {e}")
            return [], 0
    
    def count_transactions(self, filters: Optional[Dict] = None) -> int:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            return collection.count_documents(filters or {})
        except Exception as e:
            logger.error(f"Count error: {e}")
            return 0
    
    def get_last_log_hash(self) -> Optional[str]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            last_log = collection.find_one(
                {}, 
                sort=[("timestamp", -1), ("_id", -1)], 
                projection={"current_hash": 1}
            )
            return last_log["current_hash"] if last_log else None
        except Exception:
            return None
    
    def get_system_stats(self) -> Optional[Dict]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            total = collection.count_documents({})
            successful = collection.count_documents({"status": "success"})
            failed = collection.count_documents({"status": {"$in": ["failed", "error"]}})
            success_rate = (successful / total * 100) if total > 0 else 0
            
            pipeline = [{"$match": {"response_time_ms": {"$exists": True, "$ne": None}}}, 
                       {"$group": {"_id": None, "avg": {"$avg": "$response_time_ms"}}}]
            avg_result = list(collection.aggregate(pipeline))
            avg_response_time = avg_result[0]["avg"] if avg_result else 0.0
            
            pipeline = [{"$match": {"payload_size": {"$exists": True}}}, 
                       {"$group": {"_id": None, "total": {"$sum": "$payload_size"}}}]
            bytes_result = list(collection.aggregate(pipeline))
            total_bytes = bytes_result[0]["total"] if bytes_result else 0
            
            unique_connectors = set()
            for doc in collection.find({}, {"source_connector": 1, "target_connector": 1}):
                if "source_connector" in doc:
                    unique_connectors.add(doc["source_connector"])
                if "target_connector" in doc:
                    unique_connectors.add(doc["target_connector"])
            
            yesterday = datetime.utcnow() - timedelta(days=1)
            active_24h = len(set(doc["source_connector"] for doc in collection.find({"timestamp": {"$gte": yesterday}}, {"source_connector": 1})))
            
            pipeline = [{"$group": {"_id": "$source_connector", "count": {"$sum": 1}}}, 
                       {"$sort": {"count": -1}}, {"$limit": 1}]
            most_active = list(collection.aggregate(pipeline))
            most_active_connector = most_active[0]["_id"] if most_active else None
            
            pipeline = [{"$group": {"_id": "$message_type", "count": {"$sum": 1}}}, 
                       {"$sort": {"count": -1}}, {"$limit": 1}]
            most_used = list(collection.aggregate(pipeline))
            most_used_message_type = most_used[0]["_id"] if most_used else None
            
            return {
                "total_transactions": total,
                "total_connectors": len(unique_connectors),
                "active_connectors_24h": active_24h,
                "successful_transactions": successful,
                "failed_transactions": failed,
                "success_rate": round(success_rate, 2),
                "average_response_time": round(avg_response_time, 2),
                "total_data_transferred_bytes": total_bytes,
                "most_active_connector": most_active_connector,
                "most_used_message_type": most_used_message_type,
                "timestamp": datetime.utcnow()
            }
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return None
    
    def get_connector_stats(self, connector_id: str) -> Optional[Dict]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            query = {"source_connector": connector_id}
            total = collection.count_documents(query)
            successful = collection.count_documents({**query, "status": "success"})
            failed = collection.count_documents({**query, "status": {"$in": ["failed", "error"]}})
            
            pipeline = [{"$match": {**query, "response_time_ms": {"$exists": True}}}, 
                       {"$group": {"_id": None, "avg": {"$avg": "$response_time_ms"}}}]
            avg_result = list(collection.aggregate(pipeline))
            avg_response = avg_result[0]["avg"] if avg_result else 0.0
            
            pipeline = [{"$match": {**query, "payload_size": {"$exists": True}}}, 
                       {"$group": {"_id": None, "total": {"$sum": "$payload_size"}}}]
            bytes_result = list(collection.aggregate(pipeline))
            total_bytes = bytes_result[0]["total"] if bytes_result else 0
            
            last_doc = collection.find_one(query, sort=[("timestamp", DESCENDING)])
            last_activity = last_doc["timestamp"] if last_doc else None
            
            pipeline = [{"$match": query}, {"$group": {"_id": "$message_type", "count": {"$sum": 1}}}]
            msg_dist = {doc["_id"]: doc["count"] for doc in collection.aggregate(pipeline)}
            
            error_rate = (failed / total * 100) if total > 0 else 0
            
            return {
                "connector_id": connector_id,
                "total_transactions": total,
                "successful_transactions": successful,
                "failed_transactions": failed,
                "average_response_time": round(avg_response, 2),
                "total_data_transferred_bytes": total_bytes,
                "last_activity": last_activity,
                "message_type_distribution": msg_dist,
                "error_rate": round(error_rate, 2)
            }
        except Exception as e:
            logger.error(f"Connector stats error: {e}")
            return None
    
    def get_time_series_data(self, hours: int = 24) -> List[Dict]:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            start_time = datetime.utcnow() - timedelta(hours=hours)
            pipeline = [
                {"$match": {"timestamp": {"$gte": start_time}}},
                {"$group": {
                    "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$timestamp"}},
                    "count": {"$sum": 1},
                    "success_count": {"$sum": {"$cond": [{"$eq": ["$status", "success"]}, 1, 0]}},
                    "failed_count": {"$sum": {"$cond": [{"$in": ["$status", ["failed", "error"]]}, 1, 0]}},
                    "avg_response_time": {"$avg": "$response_time_ms"}
                }},
                {"$sort": {"_id": 1}}
            ]
            results = list(collection.aggregate(pipeline))
            return [{
                "timestamp": doc["_id"],
                "count": doc["count"],
                "success_count": doc["success_count"],
                "failed_count": doc["failed_count"],
                "average_response_time": round(doc.get("avg_response_time", 0) or 0, 2)
            } for doc in results]
        except Exception as e:
            logger.error(f"Time series error: {e}")
            return []
    
    def insert_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        try:
            collection = self.db[config.COLLECTION_ALERTS]
            result = collection.insert_one(alert_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Alert insert error: {e}")
            return None
    
    def get_active_alerts(self, limit: int = 100) -> List[Dict]:
        try:
            collection = self.db[config.COLLECTION_ALERTS]
            cursor = collection.find({"acknowledged": False}).sort("timestamp", DESCENDING).limit(limit)
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except Exception as e:
            logger.error(f"Get alerts error: {e}")
            return []
    
    def cleanup_old_logs(self, days: int) -> int:
        try:
            collection = self.db[config.COLLECTION_LOGS]
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            result = collection.delete_many({"timestamp": {"$lt": cutoff_date}})
            deleted_count = result.deleted_count
            if deleted_count > 0:
                logger.info(f"Deleted {deleted_count} old logs")
            return deleted_count
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0

    def get_all_sorted(self) -> List[Dict]:
        """Devuelve todos los logs ordenados por timestamp ASC para verificar integridad de la cadena de hashes."""
        try:
            collection = self.db[config.COLLECTION_LOGS]
            cursor = collection.find({}).sort([("timestamp", ASCENDING), ("_id", ASCENDING)])
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except Exception as e:
            logger.error(f"Get all sorted error: {e}")
            return []

db_service = DatabaseService()