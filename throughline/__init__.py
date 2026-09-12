"""Throughline: security context graph prototype.

Package layout:
    schema      - the canonical graph schema registry (labels, edge types, typed columns)
    models      - pydantic models shared by analytics, API, agent and (mirrored) the web UI
    simulator   - deterministic data simulation (cloud, identity, EDR, cloud audit, TI, storylines)
    graph       - GraphStore backends (LadybugDB/Kuzu embedded, Neo4j, NetworkX) and the ContextGraph projection
    analytics   - blast radius, attack paths, contextual risk scoring, TI impact, correlation, insights
    agent       - analyst agent: tool registry, Claude tool-use loop, offline playbook analyst
    api         - FastAPI application serving the UI and the agent-facing API
"""

__version__ = "0.1.0"
