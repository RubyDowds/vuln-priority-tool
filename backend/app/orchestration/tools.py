"""
Definitions of tool schemas and functions that get called by the model.
"""
from app.repositories.priority_repository import PriorityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService
from app.repositories.vulnerability_repository import VulnerabilityRepository


class Tools:
    def __init__(self, priority_repository: PriorityRepository,
                 priority_retrieval_service: PriorityRetrievalService,
                 vulnerability_repository: VulnerabilityRepository) -> None:
        self.priority_repository = priority_repository
        self.priority_retrieval_service = priority_retrieval_service
        self.vulnerability_repository = vulnerability_repository
        self._dispatch = {
            "search_priorities": self.search_priorities,
            "lookup_cve_details": self.lookup_cve_details,
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
            }
        },
        {
            "type": "function",
            "name": "lookup_cve_details",
            "description": "Full lookup for a specific CVE: vulnerability facts (what it is, "
                   "affected vendor/product) plus organisational exposure (which of "
                   "our assets are affected and their remediation priority, if any). "
                   "Use this for general questions about a named CVE.",
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

    def execute_tool(self, name: str, args: dict) -> str:
        if name not in self._dispatch:
            raise ValueError(f"Unknown tool: {name}")
        return self._dispatch[name](**args)

    def search_priorities(self, question: str):
        relevant = self.priority_retrieval_service.priority_semantic_search(question)
        return self.priority_retrieval_service.build_priority_context_from_metadata(relevant)

    def lookup_cve_details(self, cve_id: str) -> str:
        """
        Tool combining VulnerabilityRepository and PriorityRepository lookup - to deal with questions
        about a CVE that exists in the DB and has organisation expousre (affects an asset).
        Also, questions about a CVE which exists in the DB but no org exposure - should state this.
        Finally, questions about a CVE that doesn't exist in the DB at all, response should be explicit,
        rather than model guessing.
        :param cve_id: CVE from the question
        :return: response from the model
        """
        vulnerability = self.vulnerability_repository.get_by_cve_id(cve_id)
        if not vulnerability:
            return f"{cve_id} was not found in the vulnerability database."

        priority_results = self.priority_repository.get_by_cve_id(cve_id)
        parts = [f"CVE: {vulnerability.cve_id}\nDescription: {vulnerability.description}"]  # adjust to real fields

        if priority_results:
            # adapting SQLite results (ORM object, uses attribute access ie priority.cveid)
            # to dict (key access, ie priority["cve_id"]) to pass into the build context method
            # - which expects a dict bc ChromaDB .query method returns a dict
            as_dicts = [ #todo as dicts conversion being done a lot, ORM > dict mapping happens a lot = extract
                {
                    "asset_id":  p.asset_id,
                    "cve_id": p.cve_id,
                    "ssvc_decision": p.ssvc_decision,
                    "remediation_days": p.remediation_days,
                    "automatable": p.automatable,
                    "technical_impact": p.technical_impact,
                } for p in priority_results
            ]
            parts.append(self.priority_retrieval_service.build_priority_context_from_metadata(as_dicts))
        else:
            parts.append("No organisational exposure found — this CVE is not linked to any tracked assets.")

        return "\n\n".join(parts)


