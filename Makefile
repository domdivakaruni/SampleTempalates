# Throughline prototype - one-command demo and developer targets.
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
DATA ?= data/generated
PORT ?= 8000

.PHONY: help setup data db web serve dev demo test test-fast lint screenshots snapshot ask static static-check bench clean clean-data

help:
	@echo "make setup        create .venv, install python deps (+ web deps)"
	@echo "make data         simulate the estate, enrich it and build the embedded graph database"
	@echo "make web          build the web UI into web/dist (served by the API)"
	@echo "make serve        run the API + UI on http://127.0.0.1:$(PORT)"
	@echo "make dev          run API (reload) and Vite dev server side by side"
	@echo "make demo         data (if missing) + web (if missing) + serve"
	@echo "make test         run the python test suite (unit, conformance, api, scenarios)"
	@echo "make ask Q='...'  ask the analyst a question from the command line"
	@echo "make screenshots  capture UI screenshots into docs/screenshots"
	@echo "make snapshot     precompute the static-edition payloads into web/snapshot-out (docs/10)"
	@echo "make static       export the snapshot + build the no-backend static edition into web/dist-static"
	@echo "make static-check serve web/dist-static and run the Playwright verification (web/scripts/check-static.mjs)"
	@echo "make bench        graph vs SQL benchmark of the twelve demo questions (docs/11-graph-benefits.md)"

setup:
	test -d .venv || python3 -m venv .venv
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -e ".[dev]"
	cd web && npm install --no-audit --no-fund --loglevel=error

data:
	$(PY) -m throughline.simulator.build --out $(DATA)

db:
	$(PY) -c "from pathlib import Path; from throughline.config import settings; from throughline.graph.loader import load_context_graph, build_embedded_db; from throughline.graph.factory import make_store; g=load_context_graph(Path('$(DATA)')); build_embedded_db(make_store(settings, g), Path('$(DATA)'), force=True)"

web:
	cd web && npm run build

serve:
	$(PY) -m throughline.cli serve --port $(PORT)

dev:
	( $(PY) -m throughline.cli serve --port $(PORT) --reload & cd web && npm run dev )

demo:
	@test -f $(DATA)/graph/nodes.jsonl || $(MAKE) data
	@test -f web/dist/index.html || $(MAKE) web
	$(MAKE) serve

test:
	$(PY) -m pytest -q

test-fast:
	$(PY) -m pytest -q tests/unit tests/api tests/conformance

lint:
	.venv/bin/ruff check throughline tests scripts
	cd web && npx oxlint src

ask:
	$(PY) -m throughline.cli ask "$(Q)"

screenshots:
	$(PY) scripts/screenshots.py

snapshot:
	$(PY) scripts/export_snapshot.py --out web/snapshot-out

# Static snapshot edition (docs/10-static-snapshot.md). STATIC_ARGS=--export forces a fresh export.
static:
	bash scripts/build_static.sh $(STATIC_ARGS)

static-check:
	cd web && node scripts/check-static.mjs --dir dist-static

bench:
	$(PY) scripts/graph_vs_sql.py --replicate 1 --runs 5

clean:
	rm -rf web/dist web/dist-static .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

clean-data:
	rm -rf $(DATA)
