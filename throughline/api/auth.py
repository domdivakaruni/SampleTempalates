"""Optional shared-password gate for hosted demos (HTTP basic auth on every route except the health check)."""
from __future__ import annotations

import base64
import secrets
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

OPEN_PATHS = {"/api/v1/health"}


class DemoPasswordMiddleware(BaseHTTPMiddleware):
    """When ``settings.demo_password`` is set, require ``Authorization: Basic <user:password>`` on every request.

    The health endpoint stays open so platform health checks work. Credentials are compared in constant time.
    """

    def __init__(self, app: Any, user: str, password: str) -> None:
        super().__init__(app)
        self._user = user
        self._password = password

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in OPEN_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
                user, _, password = decoded.partition(":")
            except Exception:  # malformed header
                user, password = "", ""
            if secrets.compare_digest(user, self._user) and secrets.compare_digest(password, self._password):
                return await call_next(request)
        return JSONResponse(
            {"error": {"code": "unauthorized", "message": "This Throughline demo is password protected."}},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Throughline demo", charset="UTF-8"'},
        )
