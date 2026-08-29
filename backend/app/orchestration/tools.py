"""
Definitions of tool schemas and functions that get called by the model.
"""

class Tools:
    def __init__(self, orchestrator) -> None:
        self.orchestrator = orchestrator

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
    ]

    def search_priorities(self, question: str):
        relevant = self.orchestrator.priority_embedding_service.semantic_search(question)
        return self.orchestrator.build_priority_context_from_metadata(relevant)

    def execute_tool(self, name: str, args: dict) -> str:
        if name == "search_priorities":
            return self.search_priorities(args["question"])
        raise ValueError(f"Unknown tool: {name}")