"""
config.py
Application configuration for the
Enterprise Ransomware Risk Assessment System.
"""

import os

# Resolve the directory that contains this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    """Base configuration shared by all environments."""

    # Flask secret key – override with a strong random value in production
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-production-please")

    # Application display name
    APP_NAME = "Enterprise Ransomware Risk Assessment System"
    APP_VERSION = "1.0.0"

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "ransomware_risk.db")

    # Pagination
    RISKS_PER_PAGE = 15

    # Debug off by default
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "test_ransomware_risk.db")


class ProductionConfig(Config):
    DEBUG = False


# Map name → class
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(env: str = "default") -> Config:
    return config_map.get(env, DevelopmentConfig)()
