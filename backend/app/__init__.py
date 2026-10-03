import os
import sys
import logging
from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException
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

    # Register the API blueprint (Task 5)
    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    # Add Prometheus metrics after app creation (Task 5)
    from prometheus_flask_exporter import PrometheusMetrics
    metrics = PrometheusMetrics(app)
    metrics.info('astra_app_info', 'ASTRA Application', version='1.0.0')

    # CORS Middleware to handle cross-origin requests locally
    from flask_cors import CORS
    CORS(app, origins=["http://localhost:5173", "http://localhost:5000"])

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
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        code = e.code or 500
        if code == 413:
            max_mb = app.config.get("MAX_UPLOAD_MB", 150)
            message = f"File is too large. The maximum upload size is {max_mb} MB."
        elif code == 429:
            message = "Rate limit exceeded. Please try again later."
        elif code == 404:
            message = "Resource not found."
        else:
            message = e.description or "An HTTP error occurred."
        return jsonify({
            "status": "error",
            "message": message,
            "code": code
        }), code

    @app.errorhandler(Exception)
    def handle_internal_server_error(e):
        if isinstance(e, HTTPException):
            return handle_http_exception(e)
        logger.exception("Unhandled application error occurred", error=str(e))
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred.",
            "code": 500
        }), 500

    logger.info("Application factory instantiated successfully", env=config_name)
    return app
