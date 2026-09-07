from scripts.wiring import build_agent_loop
from app.evals.agent_eval_dataset import agent_eval_dataset
from app.evals.tool_selection_eval import run_tool_selection_eval

if __name__ == "__main__":
    agent_loop, db = build_agent_loop()
    try:
        pass_rate, results = run_tool_selection_eval(agent_loop, agent_eval_dataset)
        print(f"Tool selection pass rate: {pass_rate:.0%}")
        for r in results:
            status = "✅" if r["correct"] else "❌"
            print(f"{status} {r['question']!r} → expected {r['expected_tools']}, got {r['tools_called']}")
    finally:
        db.close()
