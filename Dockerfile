# Throughline: one container with the API, the analyst, the built UI and the simulated dataset baked in.
# Build:  docker build -t throughline .
# Run:    docker run --rm -p 8000:8000 -e DEMO_PASSWORD=change-me throughline
#         (add -e ANTHROPIC_API_KEY=... to use Claude as the analyst instead of the offline playbooks)

# ---- stage 1: web bundle -------------------------------------------------------------------------------------
FROM node:22-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --loglevel=error
COPY web/ ./
RUN npm run build

# ---- stage 2: python runtime + dataset -----------------------------------------------------------------------
FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 throughline
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY throughline/ ./throughline/
# Editable install keeps the source at /app so the package's repo-relative defaults (data/, web/dist) resolve there.
RUN pip install --no-cache-dir -e .
COPY data/fixtures/ ./data/fixtures/
COPY --from=web /src/web/dist ./web/dist
ENV API_HOST=0.0.0.0 PORT=8000 DATA_DIR=/app/data/generated GRAPH_DB_PATH=/app/data/generated/graph.lbdb WEB_DIST=/app/web/dist AGENT_MODE=auto
# Simulate the estate, enrich the graph and build the embedded graph database into the image (deterministic seed).
RUN python -m throughline.simulator.build --out /app/data/generated && chown -R throughline:throughline /app/data
USER throughline
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 CMD curl -fsS "http://127.0.0.1:${PORT}/api/v1/health" || exit 1
CMD ["python", "-m", "throughline.cli", "serve"]
