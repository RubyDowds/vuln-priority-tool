"""
Exposes the existing OpenAI-agent tools (Tools.search_priorities / Tools.lookup_cve_details) as MCP
tools over stdio, for use by MCP clients such as Claude Code. These are thin wrappers only - no
duplicated business logic. Both wrappers call the exact same `Tools` instance that `AgentLoop` uses;
`Tools` itself has no OpenAI-specific code, so nothing about the existing agent loop changes.

Run directly:
    python mcp_server.py
(Registration with an MCP client is a separate step - not done here.)
"""
import logging
import os
import re
import sys
from pathlib import Path

# app.db.database / app.vector_store.chroma_client both resolve relative paths ("./kev.db",
# "./chroma_db") against the process's cwd at import time. Every other entry point in this repo
# only works because it's always launched with cwd already set to backend/ (e.g. `cd backend &&
# uvicorn ...`). An MCP client launches this file as a subprocess with an unknown cwd, so pin cwd
# to this file's own directory BEFORE importing anything from `app` or `scripts` - this fixes path
# resolution without touching database.py/chroma_client.py, and therefore without changing how the
# existing FastAPI app / AgentLoop behave.
BACKEND_DIR = Path(__file__).resolve().parent
os.chdir(BACKEND_DIR)

# stdio is the wire protocol's transport - nothing but MCP protocol frames may reach stdout, or the
# stream is corrupted. Route all logging to stderr explicitly (the SDK also redirects any stray
# flushed stdout to stderr as a safety net, but don't rely on that for anything under our control).
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

from mcp.server import MCPServer

from app.db.database import SessionLocal
from app.orchestration.tools import Tools
from app.repositories.priority_repository import PriorityRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Reuse the descriptions from the OpenAI tool schemas verbatim, so the two interfaces stay
# consistent without hand-duplicating description text.
_OPENAI_TOOL_DESCRIPTIONS = {t["name"]: t["description"] for t in Tools.tools}

# Mirrors scripts/wiring.py's build_agent_loop() construction order exactly, but stops at Tools -
# deliberately NOT reusing build_agent_loop() itself, since that also constructs AgentLoop, which
# constructs an OpenAI() client and therefore requires OPENAI_API_KEY. Tools has no OpenAI
# dependency at all, so this server shouldn't need that env var either.
_session = SessionLocal()
_priority_repository = PriorityRepository(_session)
_tools = Tools(
    priority_repository=_priority_repository,
    priority_retrieval_service=PriorityRetrievalService(_priority_repository),
    vulnerability_repository=VulnerabilityRepository(_session),
)

mcp = MCPServer(name="vuln-priority-tool")


@mcp.tool(description=_OPENAI_TOOL_DESCRIPTIONS["search_priorities"])
def search_priorities(question: str) -> dict:
    """
    Semantic search over prioritised vulnerability data (SSVC decisions, CVE IDs, remediation
    timelines). Use this for open-ended questions about remediation priority or what to patch,
    rather than questions about one specific named CVE.

    Args:
        question: The user's natural-language question, used as the semantic search query.
    """
    try:
        return {"result": _tools.search_priorities(question)}
    except Exception as exc:  # underlying services shouldn't raise, but never crash the MCP process
        logger.exception("search_priorities failed for question=%r", question)
        return {"error": f"Failed to search priorities: {exc}"}


@mcp.tool(description=_OPENAI_TOOL_DESCRIPTIONS["lookup_cve_details"])
def lookup_cve_details(cve_id: str) -> dict:
    """
    Full lookup for a specific CVE: vulnerability facts (what it is, affected vendor/product) plus
    organisational exposure (which of our assets are affected and their remediation priority, if
    any).

    Args:
        cve_id: The CVE identifier, e.g. CVE-2024-12345.
    """
    normalised = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(normalised):
        return {
            "error": f"'{cve_id}' is not a valid CVE ID. Expected format: CVE-YYYY-NNNN (e.g. CVE-2024-12345)."
        }

    try:
        return {"result": _tools.lookup_cve_details(normalised)}
    except Exception as exc:
        logger.exception("lookup_cve_details failed for cve_id=%r", cve_id)
        return {"error": f"Failed to look up {cve_id}: {exc}"}


if __name__ == "__main__":
    try:
        mcp.run()
    finally:
        _session.close()
