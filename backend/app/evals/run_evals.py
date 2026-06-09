import logging
from dotenv import load_dotenv
from datasets import Dataset
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy, answer_correctness

from app.db.database import SessionLocal
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.orchestration.vulnerability_analysis_orchestrator import IntentParser, VulnerabilityAnalysisOrchestrator
from app.retrieval.vulnerability_retrieval_service import VulnerabilityRetrievalService
from app.evals.eval_dataset import eval_dataset

load_dotenv()
logging.getLogger("httpx").setLevel(logging.WARNING)

# 1. SET UP PIPELINE
session = SessionLocal()
repo = VulnerabilityRepository(session)
retrieval = VulnerabilityRetrievalService(repo)
parser = IntentParser(retrieval)
orchestrator = VulnerabilityAnalysisOrchestrator(retrieval, parser)

# 2. RUN PIPELINE AND COLLECT RESULTS
questions = []
answers = []
contexts = []
ground_truths = []
print("about to eval this")
for item in eval_dataset:
    question = item["question"]
    print("question: ", question)

    # get retrieved context from your retrieval service
    vulns = parser.parse(question, vendor=None, product=None, days=None)
    print(f"Vulns found: {len(vulns)}")
    context = retrieval.build_prompt_grounding_content(vulns)

    # get LLM answer from orchestrator
    answer = orchestrator.analyse(question)
    print(f"Answer: {answer}")

    questions.append(question)
    answers.append(answer)
    contexts.append([context])
    ground_truths.append(item["ground_truth"])

# 3. EVALUATE
data = {
    "question": questions,
    "answer": answers,
    "contexts": contexts,
    "ground_truth": ground_truths
}

dataset = Dataset.from_dict(data)
results = evaluate(dataset, metrics=[faithfulness, answer_relevancy, answer_correctness])
print(results)

