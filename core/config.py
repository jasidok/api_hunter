"""
Configuration management for API Hunter using Pydantic settings.
"""

import os
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict
from pathlib import Path

try:
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseSettings


class RedisConfig(BaseModel):
    """Redis configuration settings."""

    url: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
        description="Redis connection URL"
    )
    password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    ssl_cert_reqs: Optional[str] = Field(default=None, env="REDIS_SSL_CERT_REQS")


class ScanningConfig(BaseModel):
    """Scanning configuration settings."""

    max_concurrent_requests: int = Field(default=50, env="MAX_CONCURRENT_REQUESTS")
    request_timeout: int = Field(default=30, env="REQUEST_TIMEOUT")
    retry_attempts: int = Field(default=3, env="RETRY_ATTEMPTS")
    rate_limit: int = Field(default=100, env="RATE_LIMIT", description="Requests per second")
    user_agent: str = Field(
        default="API-Hunter/1.0 (Security Research Tool)",
        env="USER_AGENT"
    )


class AIConfig(BaseModel):
    """AI and ML configuration settings."""

    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    model: str = Field(default="gpt-4-turbo-preview", env="OPENAI_MODEL")
    max_tokens: int = Field(default=4000, env="OPENAI_MAX_TOKENS")
    enable_ai_analysis: bool = Field(default=True, env="ENABLE_AI_ANALYSIS")


class PluginsConfig(BaseModel):
    """Plugin system configuration."""

    enabled: List[str] = Field(
        default=["burp_integration", "slack_notifications"],
        env="ENABLED_PLUGINS"
    )
    disabled: List[str] = Field(default=[], env="DISABLED_PLUGINS")
    custom_plugin_path: Optional[str] = Field(default=None, env="CUSTOM_PLUGIN_PATH")


class ReportingConfig(BaseModel):
    """Reporting system configuration."""

    output_directory: str = Field(default="./reports", env="REPORT_OUTPUT_DIR")
    formats: List[str] = Field(default=["html", "pdf", "json"], env="REPORT_FORMATS")
    include_evidence: bool = Field(default=True, env="INCLUDE_EVIDENCE")
    template_dir: Optional[str] = Field(default=None, env="TEMPLATE_DIR")


class SecurityConfig(BaseModel):
    """Security configuration settings."""

    verify_ssl: bool = Field(default=False, env="VERIFY_SSL")
    proxy_url: Optional[str] = Field(default=None, env="PROXY_URL")
    proxy_auth: Optional[str] = Field(default=None, env="PROXY_AUTH")
    max_redirects: int = Field(default=10, env="MAX_REDIRECTS")


class Config(BaseSettings):
    """Main configuration class for API Hunter."""

    # Application settings
    app_name: str = Field(default="API Hunter", env="APP_NAME")
    version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # Component configurations
    # database: DatabaseConfig = Field(default_factory=DatabaseConfig)  # Removed since it's not currently used
    redis: RedisConfig = Field(default_factory=RedisConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    # Working directories
    base_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent.parent)
    logs_dir: Path = Field(default_factory=lambda: Path("./logs"))

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive = False
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()

    @field_validator("logs_dir", mode='before')
    @classmethod
    def ensure_directories_exist(cls, v):
        """Ensure directories exist."""
        if isinstance(v, str):
            v = Path(v)
        v.mkdir(parents=True, exist_ok=True)
        return v

    def get_redis_url(self) -> str:
        """Get the Redis URL."""
        return self.redis.url

    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        return self.debug

    def get_report_output_path(self) -> Path:
        """Get the full path for report output."""
        path = Path(self.reporting.output_directory)
        path.mkdir(parents=True, exist_ok=True)
        return path


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance."""
    return config


def reload_config() -> Config:
    """Reload the configuration from environment variables."""
    global config
    config = Config()
    return config
