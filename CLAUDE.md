# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Vulnerability remediation prioritisation aligned to CISA's BOD 26-04 directive: ingest CISA KEV data, enrich it with NVD/EPSS, run it through an SSVC decision engine, embed the results, and let an OpenAI tool-calling agent answer natural-language questions grounded in that data (`"What should I patch immediately?"`, `"Tell me about CVE-2022-31199"`).

Pipeline: `CISA KEV/NVD/EPSS → Ingestion & Enrichment → SSVC Decision Engine → SQLite (kev.db) → Embedding (sentence-transformers) → ChromaDB → Agent Loop (gpt-4o-mini, tool-calling) → FastAPI → Streamlit`

## Environment setup

**This project uses pyenv, not the `.venv`/`venv` directories that exist on disk.** The repo root's `.python-version` pins the pyenv-virtualenv named `vuln-priority-tool` (Python 3.12), which auto-activates via pyenv-virtualenv when you `cd` into the repo. Install/work against that environment — the stray `.venv`, `venv`, and `backend/.venv` folders are leftover local artifacts, not the canonical env, and should be ignored/not relied upon. (The README's plain `python3 -m venv .venv` instructions are the from-scratch path for a new contributor without pyenv; they and the pyenv env are not the same environment.)

```bash
pip install -r backend/requirements.txt -r frontend/requirements.txt
```

Required env vars (see `.env`, gitignored): `OPENAI_API_KEY`, `NVD_API_KEY`, `APP_PORT`.

## Common commands

Run from `backend/` unless noted:

```bash
# One-time full pipeline: KEV ingestion, mock assets, NVD/EPSS enrichment, prioritisation, embedding
python -m scripts.complete_setup

# Individual pipeline steps (re-run daily in production use)
python -m scripts.ingest_cisa_kev
python -m scripts.generate_mock_assets
python -m scripts.run_enrichment
python -m scripts.run_prioritisation
python -m scripts.embed_priorities

# Run the agent loop directly against a hardcoded question (ad hoc manual testing)
python -m scripts.run_agent

# Backend API (from backend/)
uvicorn app.api.main:app --reload

# Frontend (from repo root, in a separate terminal)
streamlit run frontend/app.py
```

There is no unit test suite (no pytest config, no `test_*.py` files) — correctness is checked via evals instead:

```bash
python -m scripts.run_agent_evals        # tool-selection accuracy, repeated runs per case (backend/app/evals/agent_eval_dataset.py)
python -m scripts.run_faithfulness_evals # RAGAS faithfulness/relevancy on final answers (backend/app/evals/faithfulness_eval_dataset.py)
```

No lint/format config is checked in (no ruff/flake8/black/pyproject config) — match surrounding style rather than assuming a specific tool's rules apply.

Query the API directly without the dashboard:
```bash
curl -X POST http://localhost:8000/priorities/analyse -H "Content-Type: application/json" -d '{"question": "What should I patch immediately?"}'
```

## Architecture

**Layering** follows repository → service/retrieval → orchestration → API, wired together by hand (no DI framework):
- `app/repositories/` — SQLAlchemy CRUD against SQLite (`kev.db`): `priority_repository.py`, `vulnerability_repository.py`, `asset_repository.py`.
- `app/models/db/` — SQLAlchemy ORM models (`vulnerability.py`, `asset.py`, `asset_vulnerability.py`, `remediation_priority.py`). Note: `app/models/vulnerability.py` also exists at the top level of `models/`, separate from `app/models/db/vulnerability.py` — check which one a given import actually points to before assuming they're the same thing.
- `app/prioritisation/ssvc_decision_engine.py` — pure decision logic: takes an `Asset` + `Vulnerability`, returns one of `immediate` (3 days) / `out-of-cycle` (14 days) / `scheduled` (60 days) / `defer`, based on internet-facing exposure, KEV membership, automatability, and technical impact.
- `app/embeddings/` + `app/vector_store/chroma_client.py` — embeds prioritisation/vulnerability data (`all-MiniLM-L6-v2`) into ChromaDB for semantic search.
- `app/retrieval/` — semantic search + context-building over the embedded data, consumed by both the agent tools and the (older) orchestrator.
- `app/orchestration/` — the agent layer:
  - `tools.py` (`Tools`) defines the OpenAI function-calling schemas (`search_priorities`, `lookup_cve_details`) and dispatches them to repositories/retrieval services.
  - `agent_loop.py` (`AgentLoop`) runs the tool-calling loop against `gpt-4o-mini` via the OpenAI Responses API: send transcript → model emits function call(s) → `Tools.execute_tool` runs them locally → append `function_call_output` → repeat until the model returns plain text or `max_iterations` (5) is hit. The model never executes tools itself — only requests them.
  - `priority_analysis_orchestrator.py` / `prioritisation_orchestrator.py` — earlier, non-agentic orchestration kept alongside the agent loop; `POST /priorities/analyse` now goes through `AgentLoop`, not `PriorityAnalysisOrchestrator` (see `app/api/routes/priorities.py`).
- `app/api/` — FastAPI app. `dependencies.py` builds the DI chain (session → repositories → retrieval/tools → agent loop) via `Depends`; `scripts/wiring.py` builds the equivalent object graphs for standalone scripts (`run_agent.py`, evals) outside the FastAPI request lifecycle — the two wiring paths are separate and both need updating if a dependency changes shape.
- `frontend/` — Streamlit chat UI (`app.py`) that POSTs questions to `/priorities/analyse`; `pages/dashboard.py` is a separate Streamlit page.

**Data flow for a question:** frontend/API → `AgentLoop.run_agent` → model picks a tool → `Tools.execute_tool` → repository/retrieval call against `kev.db`/ChromaDB → result fed back to the model → repeat until a final answer.

`docker-compose.yml`/`Dockerfile` exist for containerised deployment but are **unverified** — the manual local setup (pyenv env + `uvicorn` + `streamlit`) is the confirmed working path.
