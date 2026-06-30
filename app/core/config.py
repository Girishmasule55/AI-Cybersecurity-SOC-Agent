from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Cybersecurity SOC Agent"
    environment: str = "local"
    database_url: str = "postgresql+psycopg://soc:soc@localhost:5432/soc"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4.1-mini"
    llm_provider: str = "openai"
    chroma_dir: str = ".chroma"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
