import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATA_DIR = Path(os.environ.get("VULNCANO_DATA_DIR", Path.home() / ".vulncano"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNCANO_", env_file=".env", extra="ignore")

    database_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'vulncano.db'}"
    data_dir: Path = DEFAULT_DATA_DIR
    secret_key: str = ""
    auth_enabled: bool = False
    auth_user: str = "admin"
    auth_password: str = ""
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cors_origins: str = "http://localhost:5173"
    report_templates_dir: Path | None = None

    @property
    def scan_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def cors_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.scan_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    return settings
