"""
core/config.py
==============
Central configuration using pydantic-settings.
Reads from environment variables / .env file automatically.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "AttackGraph AI"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    SECRET_KEY: str = "change-me-in-production"

    # Neo4j
 NEO4J_URI=neo4j+s://0b7ca4f2.databases.neo4j.io
NEO4J_USERNAME=0b7ca4f2
NEO4J_PASSWORD=oAm0MrzT6HfVPubAtEszWGboUtdf-ScPBjk-dhdX_XM
NEO4J_DATABASE=0b7ca4f2

    # Qdrant
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_GRPC_PORT: int = 6334
    QDRANT_API_KEY: str = ""
    QDRANT_CVE_COLLECTION: str = "cve_descriptions"
    QDRANT_ASSETS_COLLECTION: str = "asset_metadata"
    QDRANT_THREAT_INTEL_COLLECTION: str = "threat_intel"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Gemini
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_EMBEDDING_MODEL: str = "models/gemini-embedding-001"
    GEMINI_TEMPERATURE: float = 0.1
    GEMINI_MAX_TOKENS: int = 8192

    # LangChain
    LANGCHAIN_TRACING_V2: bool = False
    LANGCHAIN_API_KEY: str = ""
    LANGCHAIN_PROJECT: str = "attackgraph-ai"

    # CORS
    FRONTEND_URL: str = "http://localhost:3000"

    # Embeddings
    EMBEDDING_DIMENSIONS: int = 3072

    # Attack Analysis
    MAX_ATTACK_PATH_HOPS: int = 8
    MAX_PATHS_RETURNED: int = 10
    PATH_SCORE_CVSS_WEIGHT: float = 0.6
    PATH_SCORE_HOP_WEIGHT: float = 0.4

    # Logging
    LOG_LEVEL: str = "DEBUG"
    LOG_FORMAT: str = "json"


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached Settings instance.
    lru_cache means this is only created once — the .env file
    is only read once at startup, not on every function call.
    """
    return Settings()


# Module-level singleton — import this everywhere
settings = get_settings()
