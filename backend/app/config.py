import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration settings."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-prod")
    
    # Database Settings
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/astra"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Redis Configurations (separated by DB index as requested)
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
    CACHE_REDIS_URL = os.environ.get("CACHE_REDIS_URL", "redis://localhost:6379/2")

    # File Upload Options
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))  # 50MB

    # Celery configuration structure format for modern celery_init_app
    CELERY = {
        "broker_url": CELERY_BROKER_URL,
        "result_backend": CELERY_RESULT_BACKEND,
        "task_ignore_result": False,
    }


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Use SQLite in-memory for unit tests if required


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    TESTING = False
    # In production, require secure secrets
    SECRET_KEY = os.environ.get("SECRET_KEY")


# Configuration mapping
config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
