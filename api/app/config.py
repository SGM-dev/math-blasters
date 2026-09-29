"""Application settings, read from the environment (or a local .env file)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # postgresql+psycopg://<user>:<password>@<host>:<port>/<database>
    database_url: str = "postgresql+psycopg://mathblasters:mathblasters@localhost:5433/mathblasters"

    # Comma-separated list of origins allowed to call the API from a browser.
    cors_origins: str = "http://localhost:5173"

    # Log-level
    log_level: str = "INFO"

    # Production-safe default; local HTTP development must explicitly opt out.
    cookie_secure: bool = True

    # Default rate limit for POST /api/completions
    completions_rate_limit: str = "20/minute"

    # Environment mode: 'development', 'test', 'production'
    env: str = "development"

    # Secret key for HMAC-signing OAuth state cookies.
    auth_secret_key: str = "insecure-dev-secret-key-change-in-production"

    # Public base URL of the API (for constructing callback URLs).
    api_base_url: str = "http://localhost:8000"

    # Comma-separated list of allowed post-login redirect targets/prefixes.
    allowed_post_login_redirects: str = "http://localhost:5173,/"

    # GitHub OAuth credentials (provider registered only when both are present).
    github_client_id: str | None = None
    github_client_secret: str | None = None

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_post_login_redirect_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.allowed_post_login_redirects.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if (
        settings.env.lower() == "production"
        and settings.auth_secret_key == "insecure-dev-secret-key-change-in-production"
    ):
        raise RuntimeError(
            "AUTH_SECRET_KEY must be set to a secure, unique secret in production environments."
        )
    return settings
