from sentence_transformers import SentenceTransformer

from app.repositories.priority_repository import PriorityRepository
from app.vector_store import chroma_client


class PriorityRetrievalService:
    def __init__(self, repository: PriorityRepository | None = None):
        self.repository = repository  # init take the repository, to read from sqlite
        self.model = SentenceTransformer("all-MiniLM-L6-v2")  # model to convert text dense vectors
        self.collection = chroma_client.get_priorities_collection()

    def priority_semantic_search(self, question: str, n_results: int = 5) -> list[dict]:
        """
        Hybrid search approach - first checks question for timeline to make more specific
        structured metadata filtering.
        todo this isn't ideal, real semantic search should be improved - better embedded documents
        Embeds the user's question (same way as priority data is embedded), converted to vector.
        ChromaDB collection is queried using the question embedding to find similar vectors
        Top 5 results (priorities) are returned.
        :param question: User's raw question
        :param n_results: Number of results to return
        :return: Priority metadata results to pass into to LLM
        """

        where_filter = None
        question_lower = question.lower()
        if any(word in question_lower for word in ["immediately", "immediate", "urgent", "critical"]):
            where_filter = {"ssvc_decision": {"$eq": "immediate"}}
        elif any(word in question_lower for word in ["defer", "deprioritise", "low priority"]):
            where_filter = {"ssvc_decision": {"$eq": "defer"}}

        question_embedding = self.model.encode(question).tolist()

        results = self.collection.query(
            query_embeddings=[question_embedding],
            n_results=n_results,
            where=where_filter
        )
        print("Retrieved metadatas:", results["metadatas"][0])
        print("Distances:", results["distances"][0])

        return results["metadatas"][0]  # returns list of metadata dicts (unwrapping the list of lists with [0])

    @staticmethod
    def build_priority_context_from_metadata(meta_data_list: list) -> str:
        if not meta_data_list:
            return "No prioritisation data available."

        chunks = []
        for m in meta_data_list:
            chunk = f"""Asset: {m.get('asset_id')}
                    CVE: {m.get('cve_id')}
                    Decision: {m.get('ssvc_decision')} ({m.get('remediation_days')} days)
                    Automatable: {m.get('automatable')}
                    Technical Impact: {m.get('technical_impact')}""".strip()
            chunks.append(chunk)

        return "\n\n---\n\n".join(chunks)