# Standing Throughline up as a shared web app

The prototype is a single process: FastAPI serves the API, the built React UI and the analyst; the graph lives in an
embedded LadybugDB file plus an in-memory projection. That makes it a good fit for **one container with the dataset
baked in**, run on any host that gives you an HTTPS URL. The dataset is deterministic, so the image builds it once
(about 30 seconds) and every deployment shows the same estate.

Sizing: the server holds the graph projection in memory and uses about 550 MB RSS after warm-up; give the container
**2 GB** and one or two vCPUs. Cold start (loading the graph) takes 5-10 seconds.

## What you get with the image

`Dockerfile` (multi-stage: Node builds the UI, Python installs the package and builds the dataset). Environment:

| Variable | Purpose |
|---|---|
| `PORT` (default 8000) | Listening port; Cloud Run, Render and Fly inject it |
| `API_HOST` | Set to `0.0.0.0` in the image |
| `DEMO_PASSWORD`, `DEMO_USER` (default `team`) | When `DEMO_PASSWORD` is set, every route except `/api/v1/health` requires HTTP basic auth. Share the URL plus the password with the team; the browser prompts once |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Optional. With a key the analyst uses Claude (`claude-opus-5` by default); without it the deterministic offline analyst answers |
| `AGENT_MODE` | `auto` (default), `llm` or `offline` |
| `PUBLIC_URL` | Extra allowed CORS origin if the UI is served from another domain |

Keep `DEMO_PASSWORD` set on anything reachable from the internet, especially when an API key is configured: every
question costs tokens, and the agent's per-turn budgets bound but do not eliminate that cost.

## Option 1 (recommended): Google Cloud Run

Builds from source with Cloud Build, scales to zero when idle, HTTPS URL out of the box.

```bash
gcloud auth login && gcloud config set project YOUR_PROJECT
gcloud run deploy throughline --source . --region us-central1 \
  --memory 2Gi --cpu 2 --min-instances 0 --max-instances 3 --timeout 300 \
  --allow-unauthenticated \
  --set-env-vars DEMO_USER=team,DEMO_PASSWORD='pick-a-strong-one',AGENT_MODE=auto
# optional: --set-secrets ANTHROPIC_API_KEY=throughline-anthropic-key:latest
```

Prefer Google accounts over a shared password? Deploy with `--no-allow-unauthenticated` and grant your team
`roles/run.invoker`, or put Identity-Aware Proxy in front of the service; then drop `DEMO_PASSWORD`.

## Option 2: Fly.io

```bash
fly launch --copy-config --no-deploy        # uses fly.toml; choose an app name and region
fly secrets set DEMO_PASSWORD='pick-a-strong-one' # ANTHROPIC_API_KEY=... optional
fly deploy
fly open
```

## Option 3: Render

In the Render dashboard choose **New > Blueprint**, point it at this repository and branch; `render.yaml` defines the
service (Docker runtime, health check, 2 GB plan). Render asks for `DEMO_PASSWORD` and `ANTHROPIC_API_KEY` on the
first deploy and redeploys on every push to the branch.

## Option 4: the prebuilt image (no cloud account needed)

The `docker` GitHub Actions workflow builds the image on every push, smoke-tests it (health, password gate, UI) and
publishes it to GitHub Container Registry. Anyone on the team with Docker can run:

```bash
docker run --rm -p 8000:8000 -e DEMO_PASSWORD=throughline ghcr.io/domdivakaruni/sampletempalates:claude-exciting-babbage-exn48g
# open http://127.0.0.1:8000  (user team / password throughline)
```

The same image is what the cloud options run, so behaviour is identical everywhere. For a laptop without Docker,
`make setup && make demo` remains the zero-container path.

## Locally with Docker

```bash
docker compose up --build          # http://127.0.0.1:8000, user team / password throughline-demo
DEMO_PASSWORD=other docker compose up
```

## Operational notes

- Everything is read-only at runtime; the container has no writable state worth persisting, so restarts and
  redeploys are free.
- Chat sessions are kept in memory per instance; with more than one instance a conversation may not follow the
  user. Keep `--max-instances 1` if you want multi-turn chat to be sticky, or accept single-question use.
- The health endpoint reports the backend (`ladybug` when the embedded database loaded, `networkx` otherwise),
  node/edge counts and the analyst mode, which is the quickest way to confirm a deployment is complete.
- To ship a different dataset (another seed or scale), set `SIM_SEED` / `SIM_SCALE` as build arguments in a
  derived Dockerfile, or rebuild the image after changing `.env.example` defaults.
