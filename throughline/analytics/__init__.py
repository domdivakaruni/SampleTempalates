"""Analytics library: build-time enrichment and on-demand graph engines over the ContextGraph.

Build time (``materialize.enrich``): vulnerability TI overlay, IOC matching, attribution, lateral movement,
storyline correlation, contextual risk scoring, crown-jewel reach, TI-adjusted exposure.
Request time (``engine.AnalyticsEngine``): blast radius, attack paths, path finding, typed investigations,
containment simulation, threat-intel context and the dashboard payload.

``AnalyticsEngine`` and ``enrich`` are exposed lazily so that submodules can be imported on their own.
"""
from __future__ import annotations

from typing import Any

__all__ = ["AnalyticsEngine", "enrich"]


def __getattr__(name: str) -> Any:
    if name == "AnalyticsEngine":
        from throughline.analytics.engine import AnalyticsEngine

        return AnalyticsEngine
    if name == "enrich":
        from throughline.analytics.materialize import enrich

        return enrich
    raise AttributeError(name)
