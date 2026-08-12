"""
Reads remediation priority records from SQLite DB -> Generate Embeddings -> Upsert to ChromaDB collection
"""
from sentence_transformers import SentenceTransformer

from app.repositories.priority_repository import PriorityRepository
from app.vector_store import chroma_client


class PriorityEmbeddingService:
    def __init__(self, repository: PriorityRepository):
        self.repository = repository # init take the repository, to read from sqlite
        self.model = SentenceTransformer("all-MiniLM-L6-v2") # model to convert text dense vectors
        self.collection = chroma_client.get_priorities_collection()

    def embed_all_priorities(self) -> None:
        """
        Embedding the priority data. How it works: the document text is what would answer the natural
        language eg "what should I patch immediately" via semantic search finding the most relevant
        priority results by meaning.
        Metadata is what we use to filter the results - eg only return 'immediate' decisions, or to fetch
        the full record from SQLite using cve_id and asset_id after match.
        """
        all_priorities = self.repository.get_all()
        ids = [f"{p.id}_{p.cve_id}" for p in all_priorities] # unique ID per asset/CVE pair
        documents = [ # this gets embedded — what semantic search matches against
            f"{p.cve_id} on {p.asset_id} is {p.ssvc_decision} — {p.reasoning}. "
            f"Technical impact: {p.technical_impact}. Automatable: {p.automatable}."
            for p in all_priorities ]
        metadatas = [{
            "asset_id": p.asset_id,
            "cve_id": p.cve_id,
            "ssvc_decision": p.ssvc_decision,
            "remediation_days": p.remediation_days or 0,
            "automatable": str(p.automatable),
            "technical_impact": p.technical_impact or "unknown"
        } for p in all_priorities]  # structured data returned alongside results, not embedded

        # takes the document text and converts it into a vector (list of numbers) using sentence transformers
        # this vector gets stored in ChromaDB and used for semantic similarity search
        embeddings = self.model.encode(documents).tolist()

        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )

    def semantic_search(self, question: str, n_results: int = 5) -> list[dict]:
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


