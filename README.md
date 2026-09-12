# vuln-priority-tool

Vulnerability remediation prioritisation aligned to CISA's BOD 26-04 directive, built on SSVC decision logic and enriched with NVD/EPSS data, with an agentic AI layer that reasons over the data using tool-calling to answer natural-language questions.

## Why

CISA's [BOD 26-04](https://www.cisa.gov/) directive moves federal vulnerability remediation away from raw CVSS severity scores toward **SSVC** (Stakeholder-Specific Vulnerability Categorization) - reasoning about exploitation likelihood, technical impact, and asset context rather than a single numeric score. This project implements that decision logic end-to-end: ingest known-exploited vulnerabilities, enrich them with live NVD/EPSS data, run them through an SSVC decision engine, and let an AI agent answer natural-language questions grounded in the resulting prioritisation data.

## What it does

Ask it things like:

- *"What should I patch immediately?"* - the agent searches prioritisation data semantically and summarises the most urgent decisions.
- *"Tell me about CVE-2022-31199"* - the agent looks up the CVE directly, combining raw vulnerability facts with any organisational exposure (or honestly reporting that none exists, or that the CVE isn't in the data at all).

The agent decides for itself which tool it needs, per question, rather than following one fixed pipeline - it reasons, calls a tool, observes the result, and repeats until it has enough to answer.

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

**The agent loop** has three tools available to it:
- `search_priorities` - semantic search over prioritisation decisions, for open-ended questions
- `lookup_cve_details` - exact lookup for a named CVE, combining vulnerability facts with organisational exposure (or an honest "not found" / "no exposure" if either is missing)

## Tech stack

- **Backend:** FastAPI, SQLAlchemy + SQLite
- **Retrieval:** ChromaDB, sentence-transformers (`all-MiniLM-L6-v2`)
- **LLM / agent layer:** OpenAI API (`gpt-4o-mini`), tool/function calling
- **Frontend:** Streamlit
- **Infra:** Docker, Docker Compose
- **Evals:** RAGAS (faithfulness/relevancy), plus a custom tool-selection accuracy harness

## Running locally

Requires Python 3.12, an [OpenAI API key](https://platform.openai.com/api-keys), and a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key).

**1. Clone and set up a virtual environment:**
```bash
git clone https://github.com/RubyDowds/vuln-priority-tool.git
cd vuln-priority-tool
python3 -m venv .venv
source .venv/bin/activate
```

**2. Install dependencies:**
```bash
pip install -r backend/requirements.txt -r frontend/requirements.txt
```

**3. Set required environment variables:**
```bash
export OPENAI_API_KEY=your-key-here
export NVD_API_KEY=your-key-here
```

**4. First run — set up the database, enrichment, and embeddings:**
```bash
cd backend
python -m scripts.complete_setup
```
This runs CISA KEV ingestion, mock asset generation, NVD/EPSS enrichment, prioritisation, and embedding, end to end. Safe to re-run from scratch at any point.

**5. Start the backend:**
```bash
uvicorn app.api.main:app --reload
```

**6. Start the frontend, in a separate terminal, from the project root:**
```bash
streamlit run frontend/app.py
```

Dashboard: `http://localhost:8501`

> A `docker-compose.yml` is included for containerised deployment but is currently unverified — the manual setup above is the confirmed working path.

### Querying it directly

Via the API, without the dashboard:
```bash
curl -X POST http://localhost:8000/priorities/analyse \
  -H "Content-Type: application/json" \
  -d '{"question": "What should I patch immediately?"}'
```

### Running the evals

```bash
cd backend
python -m scripts.run_agent_evals        # tool-selection accuracy across repeated runs
python -m scripts.run_faithfulness_evals # RAGAS faithfulness/relevancy on final answers
```

## Data

Uses public CISA KEV data plus enrichment from NVD and EPSS. Asset data is synthetic, generated with Faker - no real infrastructure or organisational data is represented.