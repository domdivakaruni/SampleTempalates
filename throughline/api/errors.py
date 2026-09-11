"""Error envelope for the serving API (docs/05-api-contract.md).

Every error is ``{"error": {"code": ..., "message": ..., "details": {...}}}`` with codes ``not_found`` (404),
``invalid_argument`` (400), ``limit_exceeded`` (400), ``query_rejected`` (400), ``not_supported`` (501),
``timeout`` (504), ``upstream_error`` (502) and ``internal_error`` (500).

The graph layer's exception classes live in ``throughline.graph.store`` (Agent B). They are imported when present;
otherwise same-named fallbacks are defined here so the API and its tests work while that module is being built.
Handlers also match exceptions by class *name*, so either definition maps to the right status.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from throughline.api.responses import ORJSONResponse

log = logging.getLogger(__name__)

try:  # pragma: no cover - exercised when the graph layer is present
    from throughline.graph.store import NotSupported, QueryRejected, QueryTimeout
except ImportError:  # graph layer not built yet

    class NotSupported(Exception):  # type: ignore[no-redef]
        """The store cannot perform the operation (e.g. Cypher on the NetworkX backend)."""

    class QueryRejected(Exception):  # type: ignore[no-redef]
        """The read-only Cypher gate rejected the statement."""

    class QueryTimeout(Exception):  # type: ignore[no-redef]
        """The query exceeded its time budget."""


STATUS_FOR_CODE: dict[str, int] = {
    "not_found": 404,
    "invalid_argument": 400,
    "limit_exceeded": 400,
    "query_rejected": 400,
    "not_supported": 501,
    "timeout": 504,
    "upstream_error": 502,
    "internal_error": 500,
}

CODE_FOR_EXCEPTION_NAME: dict[str, str] = {
    "NotSupported": "not_supported",
    "QueryRejected": "query_rejected",
    "QueryTimeout": "timeout",
    "TimeoutError": "timeout",
    "KeyError": "not_found",
    "LookupError": "not_found",
    "ValueError": "invalid_argument",
    "ValidationError": "invalid_argument",
}


class ApiError(Exception):
    """Raise anywhere in a router to produce the error envelope."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.status = status or STATUS_FOR_CODE.get(code, 500)


def error_response(code: str, message: str, *, details: dict[str, Any] | None = None, status: int | None = None) -> ORJSONResponse:
    payload = {"error": {"code": code, "message": message, "details": details or {}}}
    return ORJSONResponse(payload, status_code=status or STATUS_FOR_CODE.get(code, 500))


def not_found(what: str, ident: str | None = None) -> ApiError:
    msg = f"{what} not found" if ident is None else f"{what} {ident!r} not found"
    return ApiError("not_found", msg, details={"id": ident} if ident else None)


def bounded(value: int, *, cap: int, name: str, minimum: int = 1) -> int:
    """Enforce a hard cap from 05 ('Limits'); values above the cap are a 400 ``limit_exceeded``."""
    if value > cap:
        raise ApiError("limit_exceeded", f"{name} must be <= {cap} (got {value})", details={"param": name, "max": cap, "value": value})
    if value < minimum:
        raise ApiError("invalid_argument", f"{name} must be >= {minimum} (got {value})", details={"param": name, "min": minimum, "value": value})
    return value


def _message_of(exc: BaseException) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return str(exc) or exc.__class__.__name__


def _code_for(exc: BaseException) -> str | None:
    for klass in type(exc).__mro__:
        code = CODE_FOR_EXCEPTION_NAME.get(klass.__name__)
        if code:
            return code
    return None


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> ORJSONResponse:
        return error_response(exc.code, exc.message, details=exc.details, status=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> ORJSONResponse:
        errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return error_response("invalid_argument", "request validation failed", details={"errors": errors})

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> ORJSONResponse:
        code = {404: "not_found", 405: "invalid_argument", 422: "invalid_argument", 400: "invalid_argument"}.get(exc.status_code)
        if code is None:
            code = next((c for c, s in STATUS_FOR_CODE.items() if s == exc.status_code), "internal_error")
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return error_response(code, detail, status=exc.status_code)

    @app.exception_handler(NotSupported)
    async def _not_supported(_: Request, exc: Exception) -> ORJSONResponse:
        return error_response("not_supported", _message_of(exc))

    @app.exception_handler(QueryRejected)
    async def _rejected(_: Request, exc: Exception) -> ORJSONResponse:
        return error_response("query_rejected", _message_of(exc))

    @app.exception_handler(QueryTimeout)
    async def _timeout(_: Request, exc: Exception) -> ORJSONResponse:
        return error_response("timeout", _message_of(exc))

    @app.exception_handler(LookupError)
    async def _lookup(_: Request, exc: LookupError) -> ORJSONResponse:
        return error_response("not_found", _message_of(exc))

    @app.exception_handler(ValueError)
    async def _value(_: Request, exc: ValueError) -> ORJSONResponse:
        return error_response("invalid_argument", _message_of(exc))

    @app.exception_handler(Exception)
    async def _any(_: Request, exc: Exception) -> ORJSONResponse:
        code = _code_for(exc)
        if code is None:
            log.exception("unhandled error in API request")
            return error_response("internal_error", "internal error", details={"type": type(exc).__name__})
        return error_response(code, _message_of(exc))
