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
    api_host: str = "127.0.0.1"  # containers set API_HOST=0.0.0.0
    api_port: int = 8000  # the PORT variable injected by Cloud Run / Render / Fly / Heroku-style hosts wins when set
    log_level: str = "info"
    web_dist: Path = REPO_ROOT / "web" / "dist"
    # Optional shared password for hosted demos: when set, every route except the health check requires HTTP basic
    # auth (user DEMO_USER, password DEMO_PASSWORD). Good enough to keep a demo URL off the open internet; not a
    # substitute for real authentication.
    demo_password: str | None = None
    demo_user: str = "team"
    public_url: str | None = None  # extra allowed CORS origin for a hosted UI on another domain

    # --- limits ---
    max_fragment_nodes: int = 300
    max_fragment_edges: int = 800
    cypher_row_limit: int = 200
    cypher_timeout_ms: int = 3000


settings = Settings()
