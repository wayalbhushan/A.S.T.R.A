import redis
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from celery import Celery, Task

# Database extensions
db = SQLAlchemy()
migrate = Migrate()

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="redis://redis:6379/2"  # Fallback/default storage for limiter
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

    celery_app = Celery(app.name, task_cls=FlaskTask)
    celery_app.config_from_object(app.config.get("CELERY", {}))
    celery_app.set_default()
    app.extensions["celery"] = celery_app
    return celery_app


def init_extensions(app):
    """Register extensions with the Flask app instance."""
    # Database initialization
    db.init_app(app)
    
    # Migration initialization
    migrate.init_app(app, db)
    
    # Limiter initialization
    limiter.init_app(app)
    
    # Re-initialize Redis client connection pool using the CACHE_REDIS_URL
    redis_client.connection_pool = redis.ConnectionPool.from_url(
        app.config["CACHE_REDIS_URL"], 
        decode_responses=True
    )
