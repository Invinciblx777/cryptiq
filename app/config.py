"""Application settings, loaded from the environment or a local .env file."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the deterministic analysis backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "development"

    database_url: str = "sqlite:///./cryptiq.db"

    github_api_url: str = "https://api.github.com"
    github_token: str | None = None
    github_timeout_seconds: int = 30

    max_archive_bytes: int = 250 * 1024 * 1024
    max_extracted_bytes: int = 500 * 1024 * 1024
    max_files: int = 20_000
    max_file_bytes: int = 5 * 1024 * 1024

    scan_timeout_seconds: int = 300

    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: int = 30
    gemini_max_output_tokens: int = 1500

    parser_version: str = "python-ast-1"
    ruleset_version: str = "0.1.0"
    pqc_ruleset_version: str = "0.1.0"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
