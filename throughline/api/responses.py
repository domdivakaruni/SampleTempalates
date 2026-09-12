"""orjson-backed JSON response used as the app's default response class.

FastAPI's bundled ``ORJSONResponse`` is deprecated (it warns on every request); this thin ``Response`` subclass keeps
the fast serialisation (``orjson`` handles pydantic-dumped dicts, datetimes and numpy-free payloads) without the
deprecation path. Content that ``orjson`` cannot encode natively falls back to ``str``.
"""
from __future__ import annotations

from typing import Any

import orjson
from starlette.responses import Response


class ORJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return orjson.dumps(content, default=str, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY)
