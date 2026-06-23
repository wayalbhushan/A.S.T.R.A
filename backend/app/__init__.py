import os
import sys
import logging
from flask import Flask, jsonify
from sqlalchemy import text
import structlog

from app.config import config_by_name
from app.extensions import db, init_extensions, celery_init_app, redis_client

logger = structlog.get_logger()

def setup_logging():
    """Configure structlog to output logs in JSON format to stdout."""
    # Ensure stdout does standard JSON formatting
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Re-direct standard library loggers to structlog
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer()
    ))
    
    root_logger = logging.getLogger()
    root_logger.handlers = []  # Clear default handlers
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


def create_app(config_name: str = None) -> Flask:
    """Create Flask application instance using the factory pattern."""
    setup_logging()
    
    app = Flask(__name__)
    
    # Load configuration
    if not config_name:
        config_name = os.environ.get("FLASK_ENV", "development")
    
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))
    
    # Initialize extensions
    init_extensions(app)
    
    # Initialize Celery
    celery_init_app(app)

    # Health check endpoint (checks PostgreSQL & Redis connection as requested)
    @app.route('/health')
    def health():
        checks = {}
        try:
            db.session.execute(text('SELECT 1'))
            checks['database'] = 'ok'
        except Exception as e:
            logger.error("Healthcheck database failure", error=str(e))
            checks['database'] = 'error'
        try:
            redis_client.ping()
            checks['redis'] = 'ok'
        except Exception as e:
            logger.error("Healthcheck redis failure", error=str(e))
            checks['redis'] = 'error'
        
        status = 'healthy' if all(
            v == 'ok' for v in checks.values()
        ) else 'degraded'
        
        response_code = 200 if status == 'healthy' else 503
        return jsonify({'status': status, 'checks': checks}), response_code

    # Global Error Handlers (Coding Rule 9)
    @app.errorhandler(Exception)
    def handle_internal_server_error(e):
        logger.exception("Unhandled application error occurred", error=str(e))
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred.",
            "code": 500
        }), 500

    @app.errorhandler(404)
    def handle_not_found_error(e):
        return jsonify({
            "status": "error",
            "message": "Resource not found.",
            "code": 404
        }), 404

    @app.errorhandler(429)
    def handle_rate_limit_error(e):
        return jsonify({
            "status": "error",
            "message": "Rate limit exceeded. Please try again later.",
            "code": 429
        }), 429

    logger.info("Application factory instantiated successfully", env=config_name)
    return app
