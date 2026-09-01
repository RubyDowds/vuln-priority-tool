"""
Definitions of tool schemas and functions that get called by the model.
"""
from app.repositories.priority_repository import PriorityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService


class Tools:
    def __init__(self, priority_repository: PriorityRepository,
                 priority_retrieval_service: PriorityRetrievalService) -> None:
        self.priority_repository = priority_repository
        self.priority_retrieval_service = priority_retrieval_service
        self._dispatch = {
            "search_priorities": self.search_priorities,
            "lookup_priority_by_cve": self.lookup_priority_by_cve,
        }

    tools = [
        {
            "type": "function",
            "name": "search_priorities",
            "description": "Semantic search over prioritised vulnerability data (SSVC decisions, CVE IDs, remediation "
                           "timelines). Use this when the user asks about specific vulnerabilities, remediation priority, "
                           "or what to patch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The user's question, used as the semantic search query",
                    },
                },
                "required": ["question"],
            },
        },
        {
            "type": "function",
            "name": "lookup_priority_by_cve",
            "description": "Exact lookup of the prioritisation decision for a specific CVE ID. Use this when the user "
                           "asks about a named CVE, rather than a general or fuzzy question about what to patch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE identifier, e.g. CVE-2024-12345",
                    },
                },
                "required": ["cve_id"],
            },
        }
    ]

    def search_priorities(self, question: str):
        relevant = self.priority_retrieval_service.priority_semantic_search(question)
        return self.priority_retrieval_service.build_priority_context_from_metadata(relevant)

    def execute_tool(self, name: str, args: dict) -> str:
        if name not in self._dispatch:
            raise ValueError(f"Unknown tool: {name}")
        return self._dispatch[name](**args)


    def lookup_priority_by_cve(self, cve_id: str) -> str:
        results = self.priority_repository.get_by_cve_id(cve_id)
        if not results:
            return f"No priority record found for {cve_id}."

        # adapting SQLite results (ORM object, uses attribute access ie priority.cveid)
        # to dict (key access, ie priority["cve_id"]) to pass into the build context method
        # - which expects a dict bc ChromaDB .query method returns a dict
        as_dicts = [
            {
                "asset_id": r.asset_id,
                "cve_id": r.cve_id,
                "ssvc_decision": r.ssvc_decision,
                "remediation_days": r.remediation_days,
                "automatable": r.automatable,
                "technical_impact": r.technical_impact,
            }
            for r in results
        ]
        return self.priority_retrieval_service.build_priority_context_from_metadata(as_dicts)

    # todo
    # third tool combining VulnerabilityRepository and PriorityRepository — a question about a CVE with no
    # asset match should ideally still get something back ("this CVE exists, no organisational exposure found"),
    # rather than either an empty tool result or, worse, the model guessing.