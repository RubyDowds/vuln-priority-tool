# scripts/run_faithfulness_evals.py
import logging
from dotenv import load_dotenv

from scripts.wiring import build_agent_loop
from app.evals.faithfulness_eval_dataset import faithfulness_eval_dataset
from app.evals.faithfulness_eval import run_faithfulness_eval

load_dotenv()
logging.getLogger("httpx").setLevel(logging.WARNING)

if __name__ == "__main__":
    agent_loop, db = build_agent_loop()
    try:
        results = run_faithfulness_eval(agent_loop, faithfulness_eval_dataset)
        print(results)
    finally:
        db.close()