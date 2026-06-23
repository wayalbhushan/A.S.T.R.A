"""
ASTRA API Key Authentication Module
Provides middleware decorators for API key generation, storage, and validation.
"""

from datetime import datetime, timezone
from functools import wraps
import json
import os
import secrets
from flask import jsonify, request
import structlog
from app.extensions import redis_client

logger = structlog.get_logger()

MASTER_API_KEY = os.environ.get("MASTER_API_KEY", "dev-master-key")


def generate_api_key() -> str:
    """Generates a cryptographically secure 64-character hex API key."""
    return secrets.token_hex(32)


def validate_api_key(key: str) -> bool:
    """Validates an API key against the Redis datastore.
    
    Supports MASTER_API_KEY for developer/test access.
    """
    if not key:
        return False
    if key == MASTER_API_KEY:
        return True
    redis_key = f"apikey:{key}"
    return redis_client.exists(redis_key) == 1


def store_api_key(key: str) -> bool:
    """Stores a newly generated API key in Redis with no expiration."""
    redis_key = f"apikey:{key}"
    data = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "request_count": 0
    }
    return redis_client.set(redis_key, json.dumps(data))


def require_api_key(f):
    """Enforces X-API-Key authentication as a decorator.
    
    Returns a 401 JSON error payload if missing or invalid.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key or not validate_api_key(key):
            logger.warning("invalid_api_key_attempt", ip=request.remote_addr)
            return jsonify({
                "status": "error",
                "message": "Invalid or missing API key. Generate one at POST /api/v1/auth/generate",
                "code": 401
            }), 401
        return f(*args, **kwargs)
    return decorated
