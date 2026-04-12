import logging
import requests
from typing import Optional, Dict, Any
from datetime import datetime
from app.config import config

logger = logging.getLogger(__name__)

class DATValidator:
    def __init__(self):
        self.daps_jwks_url = "https://omejdn/auth/jwks.json"
        self.daps_token_url = "https://omejdn/auth/token"
        self._jwks_cache: Optional[Dict] = None
        self._jwks_cache_time: Optional[datetime] = None
    
    def validate_dat_token(self, token: str) -> Dict[str, Any]:
        try:
            if not token:
                return {
                    "valid": False,
                    "error": "Token not provided",
                    "error_code": "NO_TOKEN"
                }
            
            token = token.replace("Bearer ", "").strip()
            
            parts = token.split(".")
            if len(parts) != 3:
                return {
                    "valid": False,
                    "error": "Invalid token format",
                    "error_code": "INVALID_FORMAT"
                }
            
            claims = self._decode_payload(parts[1])
            if not claims:
                return {
                    "valid": False,
                    "error": "Could not decode token",
                    "error_code": "DECODE_ERROR"
                }
            
            expiry_check = self._check_expiry(claims)
            if not expiry_check["valid"]:
                return expiry_check
            
            audience_check = self._check_audience(claims)
            if not audience_check["valid"]:
                return audience_check
            
            return {
                "valid": True,
                "issuer": claims.get("iss"),
                "subject": claims.get("sub"),
                "audience": claims.get("aud"),
                "expiry": claims.get("exp"),
                "claims": claims
            }
        except Exception as e:
            logger.error(f"DAT validation error: {e}")
            return {
                "valid": False,
                "error": str(e),
                "error_code": "VALIDATION_ERROR"
            }
    
    def _decode_payload(self, payload_b64: str) -> Optional[Dict]:
        try:
            import base64
            import json
            
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            
            decoded = base64.urlsafe_b64decode(payload_b64)
            return json.loads(decoded)
        except Exception as e:
            logger.error(f"Payload decode error: {e}")
            return None
    
    def _check_expiry(self, claims: Dict) -> Dict[str, Any]:
        try:
            exp = claims.get("exp")
            if not exp:
                return {
                    "valid": False,
                    "error": "Token has no expiry",
                    "error_code": "NO_EXPIRY"
                }
            
            now = datetime.utcnow().timestamp()
            if now > exp:
                return {
                    "valid": False,
                    "error": "Token has expired",
                    "error_code": "TOKEN_EXPIRED",
                    "expired_at": datetime.utcfromtimestamp(exp).isoformat()
                }
            
            return {"valid": True}
        except Exception as e:
            logger.error(f"Expiry check error: {e}")
            return {
                "valid": False,
                "error": str(e),
                "error_code": "EXPIRY_CHECK_ERROR"
            }
    
    def _check_audience(self, claims: Dict) -> Dict[str, Any]:
        try:
            audience = claims.get("aud")
            if not audience:
                return {
                    "valid": False,
                    "error": "Token has no audience",
                    "error_code": "NO_AUDIENCE"
                }
            
            valid_audiences = [
                "idsc:IDS_CONNECTORS_ALL",
                "clearing-house"
            ]
            
            if isinstance(audience, list):
                if not any(a in valid_audiences for a in audience):
                    return {
                        "valid": False,
                        "error": f"Invalid audience: {audience}",
                        "error_code": "INVALID_AUDIENCE"
                    }
            else:
                if audience not in valid_audiences:
                    return {
                        "valid": False,
                        "error": f"Invalid audience: {audience}",
                        "error_code": "INVALID_AUDIENCE"
                    }
            
            return {"valid": True}
        except Exception as e:
            logger.error(f"Audience check error: {e}")
            return {
                "valid": False,
                "error": str(e),
                "error_code": "AUDIENCE_CHECK_ERROR"
            }
    
    def get_jwks(self) -> Optional[Dict]:
        try:
            if self._jwks_cache and self._jwks_cache_time:
                cache_age = (datetime.utcnow() - self._jwks_cache_time).seconds
                if cache_age < 3600:
                    return self._jwks_cache
            
            response = requests.get(
                self.daps_jwks_url,
                verify=False,
                timeout=5
            )
            response.raise_for_status()
            
            self._jwks_cache = response.json()
            self._jwks_cache_time = datetime.utcnow()
            
            return self._jwks_cache
        except Exception as e:
            logger.error(f"JWKS fetch error: {e}")
            return None

dat_validator = DATValidator()