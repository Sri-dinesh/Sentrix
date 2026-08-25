import os
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentrix API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    # Database & Supabase
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/postgres"
    SUPABASE_URL: str = "https://unfmcryvabbuncsfyhvu.supabase.co"
    SUPABASE_SERVICE_ROLE_KEY: str = "placeholder_service_role_key"
    SUPABASE_STORAGE_BUCKET: str = "sentrix-models"

    # Clerk Authentication
    CLERK_SECRET_KEY: str = "sk_test_placeholder"
    CLERK_WEBHOOK_SECRET: str = "whsec_placeholder"
    CLERK_JWKS_URL: str = "https://api.clerk.com/v1/jwks"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # Ollama & SDN
    OLLAMA_HOST: str = "http://localhost:11434"
    RYU_API_URL: str = "http://localhost:8080"

    model_config = SettingsConfigDict(
        env_file=("infra/env/.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
