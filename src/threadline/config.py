"""Settings from environment / .env. Secrets never live in code."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str
    neo4j_database: str = "neo4j"
    neo4j_write_username: str
    neo4j_write_password: SecretStr
    # Same account as write on Aura Professional (no RBAC); read-only is enforced in code.
    neo4j_read_username: str
    neo4j_read_password: SecretStr
    org_id: str = "org-kestrel"
