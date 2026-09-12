
def run_tool_selection_eval(agent_loop, dataset, runs_per_case: int= 3):
    results = []
    for case in dataset:
        for _ in range(runs_per_case):
            outcome = agent_loop.run_agent(case["question"])
            correct = set(outcome["tools_called"]) == set(case["expected_tools"])
            results.append({
                "question": case["question"],
                "expected_tools": case["expected_tools"],
                "tools_called": outcome["tools_called"],
                "correct": correct,
            })

    pass_rate = sum(r["correct"] for r in results) / len(results)
    return pass_rate, results