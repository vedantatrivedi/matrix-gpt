# MatrixGPT

Autonomous adversarial security war game demo. Red Team agents attack a target app while Blue Team agents detect and patch in real time.

## Local development

### 1) Sample app (target)

```
cd sample-app
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8001
```

### 2) Orchestrator

```
cd orchestrator
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
export TARGET_URL=http://localhost:8001
export RUN_MODE=demo
export VULN_LIMIT=5
export RED_TEAM_MODEL=gpt-5.2-pro
export BLUE_TEAM_MODEL=gpt-5.2-pro
export RECON_MODEL=gpt-5-mini
export VULN_HUNTER_MODEL=gpt-5-mini
export EXPLOIT_MODEL=gpt-5.2-pro
export SOC_MODEL=gpt-5-mini
export PATCH_MODEL=gpt-5.2-codex
export GAME_MASTER_MODEL=gpt-4.1-mini
export AGENT_THROTTLE_SECONDS=2.0
export AGENT_RATE_LIMIT_BACKOFF=3.0
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000

## Tests

```
pytest tests/ -v
```

## Deployment (Railway)

- Each service has its own `Dockerfile` and `railway.json`.
- Configure `OPENAI_API_KEY` and `TARGET_URL` for orchestrator.
