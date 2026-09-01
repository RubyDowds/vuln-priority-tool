"""
Answers questions against already-computed priority data, now also the home for agent tool logic.
Runs per-request, every time someone asks something.
"""
import logging
from openai import OpenAI

from app.repositories.priority_repository import PriorityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class PriorityAnalysisOrchestrator:
    MODEL = "gpt-4o-mini"

    def __init__(self, priority_repository: PriorityRepository,
                 priority_retrieval_service: PriorityRetrievalService,):
        self.priority_retrieval_service = priority_retrieval_service
        self.priority_repository = priority_repository
        self.client = OpenAI()  # picks up OPENAI_API_KEY from environment
        self.logger = logging.getLogger(__name__)

    def analyse(self, question: str) -> str | None:
        """
        Full RAG call - retrieves through semantic search
        Augments through building priority context from metadata
        Generates with the llm call.
        :param question: User question
        :return: response from the LLM
        """
        # semantic search over priority embeddings
        relevant = self.priority_retrieval_service.priority_semantic_search(question)

        context = self.priority_retrieval_service.build_priority_context_from_metadata(relevant)
        prompt = f"""You are a security analyst assistant helping prioritise vulnerability remediation.
            Use only the prioritisation data below to answer the question.
            If the data doesn't contain enough information, say so.
            Be specific — include CVE IDs, asset IDs, and remediation timelines where relevant.
        
            Prioritisation Data:
            {context}
        
            Question: {question}
            Answer:"""
        return self._call_llm(prompt)


    def _call_llm(self, prompt: str):
        response = self.client.chat.completions.create(
            model=self.MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        return response.choices[0].message.content



