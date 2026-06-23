import redis
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from celery import Celery, Task

# Database extensions
db = SQLAlchemy()
migrate = Migrate()
celery = Celery()

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Redis cache client initialized globally
redis_client = redis.Redis()

def celery_init_app(app) -> Celery:
    """Initialize Celery with Flask application context.
    
    Creates a subclass of celery.Task that runs the task inside the 
    Flask application context, allowing DB models and configs to be accessible.
    """
    class FlaskTask(Task):
        def __call__(self, *args: object, **kwargs: object) -> object:
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.main = app.name
    celery.task_cls = FlaskTask
    celery.config_from_object(app.config.get("CELERY", {}))
    celery.set_default()
    app.extensions["celery"] = celery
    return celery


def init_extensions(app):
    """Register extensions with the Flask app instance."""
    # Database initialization
    db.init_app(app)
    
    # Migration initialization
    migrate.init_app(app, db)
    
    # Configure Limiter storage dynamically from REDIS_URL (Task 5)
    import os
    if "REDIS_URL" not in app.config:
        app.config["REDIS_URL"] = os.environ.get("REDIS_URL", app.config.get("CACHE_REDIS_URL", "redis://redis:6379/2"))
    
    limiter.storage_uri = app.config["REDIS_URL"]
    limiter.init_app(app)
    
    # Re-initialize Redis client connection pool using the CACHE_REDIS_URL
    redis_client.connection_pool = redis.ConnectionPool.from_url(
        app.config["CACHE_REDIS_URL"], 
        decode_responses=True
    )
