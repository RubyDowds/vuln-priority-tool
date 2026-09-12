from datasets import Dataset
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy

def run_faithfulness_eval(agent_loop, dataset):
    questions, answers, contexts, ground_truths = [], [], [], []

    for case in dataset:
        outcome = agent_loop.run_agent(case["question"])
        questions.append(case["question"])
        answers.append(outcome["answer"])
        contexts.append(outcome["tool_outputs"])  # RAGAS wants list[list[str]]
        ground_truths.append(case["ground_truth"])

    data = {
        "question": questions,
        "answer": answers,
        "retrieved_contexts": contexts,
        "ground_truth": ground_truths
    }

    return evaluate(Dataset.from_dict(data), metrics=[faithfulness, answer_relevancy])