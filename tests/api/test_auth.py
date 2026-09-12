"""The optional shared-password gate for hosted demos."""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from throughline.api.app import create_app
from throughline.config import Settings


def _client(tmp_path, **overrides) -> TestClient:
    settings = Settings(_env_file=None, web_dist=tmp_path / "no-dist", **overrides)
    return TestClient(create_app(settings=settings), raise_server_exceptions=False)


def _basic(user: str, password: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def test_no_password_means_open(tmp_path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/schema").status_code in (200, 503)


def test_password_gate(tmp_path) -> None:
    client = _client(tmp_path, demo_password="s3cret", demo_user="team")
    # health stays open for platform health checks
    assert client.get("/api/v1/health").status_code == 200
    r = client.get("/api/v1/schema")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Basic")
    assert r.json()["error"]["code"] == "unauthorized"
    assert client.get("/api/v1/schema", headers=_basic("team", "wrong")).status_code == 401
    assert client.get("/api/v1/schema", headers=_basic("other", "s3cret")).status_code == 401
    assert client.get("/api/v1/schema", headers=_basic("team", "s3cret")).status_code in (200, 503)
    assert client.get("/", headers=_basic("team", "s3cret")).status_code == 200
