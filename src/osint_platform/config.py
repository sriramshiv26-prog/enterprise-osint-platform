import os
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic_settings import BaseSettings
from pydantic import Field

logger = logging.getLogger(__name__)


def expand_env_vars(obj: Any) -> Any:
    """Recursively expand environment variables in config values."""
    if isinstance(obj, dict):
        return {k: expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        # Handle ${VAR} and ${VAR:-default} syntax
        import re

        def replace_var(match):
            var_name = match.group(1)
            default = match.group(2)
            return os.getenv(var_name, default or "")

        return re.sub(r'\$\{([^}:]+)(?::([^}]+))?\}', replace_var, obj)
    return obj


class Settings(BaseSettings):
    """Application settings loaded from environment and config file."""

    # App configuration
    app_name: str = Field(default="Enterprise OSINT Platform", alias="app_name")
    version: str = Field(default="0.1.0", alias="version")
    environment: str = Field(default="development", alias="environment")
    debug: bool = Field(default=True, alias="debug")

    # Database
    database_url: str = Field(
        default="postgresql://postgres:dev_password@localhost:5432/osint_platform",
        alias="database_url"
    )
    database_pool_size: int = Field(default=20, alias="database_pool_size")
    database_max_overflow: int = Field(default=40, alias="database_max_overflow")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", alias="redis_url")

    # Neo4j
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="neo4j_uri")
    neo4j_user: str = Field(default="neo4j", alias="neo4j_user")
    neo4j_password: str = Field(default="dev_password", alias="neo4j_password")

    # JWT
    jwt_secret_key: str = Field(
        default="dev_secret_key_change_in_production",
        alias="jwt_secret_key"
    )
    jwt_algorithm: str = Field(default="HS256", alias="jwt_algorithm")
    jwt_expiry_hours: int = Field(default=24, alias="jwt_expiry_hours")
    jwt_refresh_expiry_days: int = Field(default=7, alias="jwt_refresh_expiry_days")

    # OSINT
    osint_default_depth: int = Field(default=2, alias="osint_default_depth")
    osint_timeout: int = Field(default=60, alias="osint_timeout")
    osint_max_concurrent_tasks: int = Field(default=10, alias="osint_max_concurrent_tasks")

    # API
    api_host: str = Field(default="0.0.0.0", alias="api_host")
    api_port: int = Field(default=8000, alias="api_port")

    # Claude API
    anthropic_api_key: Optional[str] = Field(default=None, alias="anthropic_api_key")

    # Ollama
    ollama_enabled: bool = Field(default=True, alias="ollama_enabled")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="ollama_base_url")
    ollama_model: str = Field(default="qwen2.5-coder:1.5b", alias="ollama_model")

    class Config:
        env_file = "config/.env"
        case_sensitive = False
        extra = "allow"


def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file and environment variables."""
    config_file = Path(__file__).parent.parent.parent / "config" / "osint_platform.yaml"

    config = {}

    # Load from YAML if exists
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                yaml_config = yaml.safe_load(f)
                config = expand_env_vars(yaml_config) if yaml_config else {}
            logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Failed to load config from YAML: {e}")

    # Load environment-based settings
    try:
        env_file = Path(__file__).parent.parent.parent / "config" / ".env"
        if env_file.exists():
            settings = Settings(_env_file=str(env_file))
        else:
            settings = Settings()

        # Merge settings into config
        config.update(settings.model_dump(by_alias=True))
    except Exception as e:
        logger.warning(f"Failed to load settings from environment: {e}")

    return config


def get_config() -> Dict[str, Any]:
    """Get application configuration (cached)."""
    if not hasattr(get_config, '_config'):
        get_config._config = load_config()
    return get_config._config


# Convenience function to get specific config values
def get_config_value(path: str, default: Any = None) -> Any:
    """Get a nested config value using dot notation.

    Example:
        get_config_value("database.url")
        get_config_value("jwt.expiry_hours", 24)
    """
    config = get_config()
    keys = path.split('.')
    value = config

    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
            if value is None:
                return default
        else:
            return default

    return value if value is not None else default
