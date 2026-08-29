# vuln-priority-tool

Vulnerability remediation prioritisation aligned to CISA's BOD 26-04 directive, which is built on SSVC decision logic, enriched with NVD/EPSS data, with a RAG-based AI layer for natural-language analysis, now being rearchitected into an agentic tool-calling system.

## Why

CISA's [BOD 26-04](https://www.cisa.gov/) directive moves federal vulnerability remediation away from raw CVSS severity scores toward **SSVC** (Stakeholder-Specific Vulnerability Categorization) - reasoning about exploitation likelihood, technical impact, and asset context rather than a single numeric score. This project implements that decision logic end-to-end: ingest known-exploited vulnerabilities, enrich them with live NVD/EPSS data, run them through an SSVC decision engine, and let an LLM layer answer natural-language questions grounded in the resulting prioritisation data.

## Current status

**Working, on `main`:**
- CISA KEV ingestion, NVD/EPSS enrichment pipeline
- SSVC decision engine producing remediation priorities per CVE/asset pair
- ChromaDB semantic retrieval over both vulnerability and priority data
- RAG-based Q&A: retrieve relevant priorities → build context → generate a grounded answer via `gpt-4o-mini`
- FastAPI backend + Streamlit dashboard, containerised with Docker Compose

**In progress, on `agentic-loop`:**
Rearchitecting the fixed RAG pipeline into a genuine agent loop using OpenAI's tool-calling API. Instead of always following one hardcoded retrieve-then-generate sequence, the model decides (per question) which tool(s) it needs and in what order, observing each tool's output before deciding its next step.

- ✅ Core agent loop (reason → act → observe, repeating until the model has enough to answer)
- ✅ First tool: `search_priorities`, wrapping the existing semantic retrieval as a callable the model can choose to invoke
- [TODO] Second tool: exact-match CVE/asset lookup (structured SQLite query, as a genuine alternative retrieval strategy alongside semantic search)
- [TODO] Session memory across questions
- [TODO] Evals redesigned around tool-selection correctness and trajectory quality, not just single-pass answer faithfulness

## Architecture

```
CISA KEV / NVD / EPSS
        │
        ▼
  Ingestion & Enrichment
        │
        ▼
   SSVC Decision Engine ──► SQLite (priorities, assets, vulnerabilities)
        │
        ▼
  Embedding Service (sentence-transformers) ──► ChromaDB
        │
        ▼
  Agent Loop (OpenAI tool-calling, gpt-4o-mini)
        │
        ▼
  FastAPI ──► Streamlit dashboard / chat
```

## Tech stack

- **Backend:** FastAPI, SQLAlchemy + SQLite
- **Retrieval:** ChromaDB, sentence-transformers (`all-MiniLM-L6-v2`)
- **LLM / agent layer:** OpenAI API (`gpt-4o-mini`), tool/function calling
- **Frontend:** Streamlit
- **Infra:** Docker, Docker Compose
- **Evals:** RAGAS (being reworked for trajectory-level evaluation)

## Running locally

Requires Python 3.12 and an OpenAI API key.

```bash
git clone https://github.com/RubyDowds/vuln-priority-tool.git
cd vuln-priority-tool
pip install -r backend/requirements.txt -r frontend/requirements.txt
export OPENAI_API_KEY=your-key-here
```

**First run: set up the database, enrichment, and embeddings:**
```bash
cd backend
python -m scripts.complete_setup
```
This runs CISA KEV ingestion, mock asset generation, NVD/EPSS enrichment, and SSVC prioritisation end-to-end.

**Start the backend:**
```bash
cd backend
uvicorn app.api.main:app --reload
```

**Start the frontend, in a separate terminal, from the project root:**
```bash
streamlit run frontend/app.py
```

Dashboard: `http://localhost:8501`

> A `docker-compose.yml` is included for containerised deployment but is currently unverified, the manual setup above is the confirmed working path.

## Data

Uses public CISA KEV data plus enrichment from NVD and EPSS. Asset data is synthetic, generated with Faker, no real infrastructure or organisational data is represented.
