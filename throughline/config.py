"""Runtime configuration (environment variables, .env file)."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=REPO_ROOT / ".env", env_file_encoding="utf-8", extra="ignore")

    # --- data & graph ---
    data_dir: Path = REPO_ROOT / "data" / "generated"
    graph_backend: str = "ladybug"  # ladybug | kuzu | networkx | neo4j
    graph_db_path: Path = REPO_ROOT / "data" / "generated" / "graph.lbdb"
    neo4j_uri: str | None = None
    neo4j_user: str = "neo4j"
    neo4j_password: str | None = None
    neo4j_database: str = "neo4j"

    # --- simulation ---
    sim_seed: int = 20260911
    sim_scale: float = 1.0
    sim_now: str = "2026-09-11T14:00:00Z"

    # --- analyst agent ---
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-5"
    agent_effort: str = "high"
    agent_mode: str = "auto"  # auto | llm | offline
    agent_max_tool_calls: int = 12
    agent_max_rounds: int = 8
    agent_enable_fallbacks: bool = True

    # --- serving ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    log_level: str = "info"
    web_dist: Path = REPO_ROOT / "web" / "dist"

    # --- limits ---
    max_fragment_nodes: int = 300
    max_fragment_edges: int = 800
    cypher_row_limit: int = 200
    cypher_timeout_ms: int = 3000


settings = Settings()
