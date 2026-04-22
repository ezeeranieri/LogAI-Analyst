import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, ConfigDict


class Settings(BaseSettings):
    """Application settings with validation via Pydantic."""

    # Security Configuration - REQUIRED, no default for security
    API_KEY: str = Field(..., description="Secret key for API authentication. MUST be set in environment.")

    # Directory Configuration
    DATA_DIR: str = Field(default="data", description="Directory for data storage")

    # Network Configuration
    DEFAULT_LOCAL_HOST: str = "127.0.0.1"   # nosonar: not a hardcoded production value
    DEFAULT_DOCKER_HOST: str = "0.0.0.0"  # nosonar: not a hardcoded production value
    APP_HOST: str = Field(default="127.0.0.1", description="Host to bind the application")
    APP_PORT: int = Field(default=8000, ge=1, le=65535, description="Port to bind the application")

    # Logging and Model Configuration
    LOG_FILE: str = Field(default="app_production.log", description="Log file path")
    MODEL_PATH: str | None = Field(default=None, description="Path to ML model file")
    REDIS_URL: str | None = Field(default=None, description="Redis URL for rate limiting (optional)")
    WORKERS: int = Field(default=1, ge=1, description="Number of worker processes (affects rate limiting)")

    model_config = ConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent / ".env"),
        env_file_encoding="utf-8"
    )

    @field_validator('APP_PORT', mode='before')
    @classmethod
    def validate_port(cls, v):
        """Validate port is a valid integer in valid range."""
        if isinstance(v, str):
            # Handle cases like "8080a" by extracting digits
            digits = ''.join(c for c in v if c.isdigit())
            if not digits:
                raise ValueError(f"Invalid port value: {v}")
            v = int(digits)
        if not 1 <= v <= 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v

    @field_validator('MODEL_PATH', mode='after')
    @classmethod
    def set_default_model_path(cls, v: str | None, info) -> str:
        """Set default model path if not provided via environment."""
        if v is not None:
            return v
        # Compute default path based on BASE_DIR and DATA_DIR
        base_dir = Path(__file__).resolve().parent.parent
        data_dir = info.data.get('DATA_DIR', 'data')
        return str(base_dir / data_dir / "model.pkl")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Computed paths after initialization (MODEL_PATH now handled by validator)
        self._BASE_DIR = Path(__file__).resolve().parent.parent

    @property
    def BASE_DIR(self) -> Path:
        return self._BASE_DIR

    @property
    def ABS_DATA_DIR(self) -> str:
        return str((self._BASE_DIR / self.DATA_DIR).resolve())


# Singleton instance
_settings = Settings()

# Backward-compatible exports
API_KEY = _settings.API_KEY
APP_HOST = _settings.APP_HOST
APP_PORT = _settings.APP_PORT
DATA_DIR = _settings.DATA_DIR
LOG_FILE = _settings.LOG_FILE
MODEL_PATH = _settings.MODEL_PATH
REDIS_URL = _settings.REDIS_URL
WORKERS = _settings.WORKERS
BASE_DIR = _settings.BASE_DIR
ABS_DATA_DIR = _settings.ABS_DATA_DIR
