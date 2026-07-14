from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECMIND_", case_sensitive=False, extra="ignore")

    env: str = "development"
    demo_mode: bool = True
    database_url: str = "sqlite:///./data/secmind.db"
    input_root: Path = Path("data/inputs")
    run_root: Path = Path("data/runs")
    upload_root: Path = Path("data/uploads")

    qwen_base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    qwen_api_key: str = ""
    planner_model: str = "qwen-plus"
    worker_model: str = "qwen-turbo"
    fallback_model: str = "qwen-max"
    embedding_model: str = "text-embedding-v3"
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = "secmind_knowledge"
    qdrant_vector_size: int = Field(default=1024, ge=64, le=4096)
    model_timeout_seconds: float = 45.0
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)

    max_steps: int = Field(default=12, ge=1, le=100)
    max_tool_calls: int = Field(default=12, ge=1, le=100)
    max_model_calls: int = Field(default=20, ge=1, le=200)
    max_runtime_seconds: int = Field(default=600, ge=10, le=7200)
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_extracted_bytes: int = Field(default=200 * 1024 * 1024, ge=1024)
    max_files: int = Field(default=10_000, ge=1)
    max_zip_ratio: int = Field(default=100, ge=1)

    def prepare_directories(self) -> None:
        for path in (self.input_root, self.run_root, self.upload_root):
            path.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            Path(self.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_directories()
    return settings
