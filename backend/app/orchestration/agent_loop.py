from openai import OpenAI
import json

from app.orchestration.tools import Tools
from app.orchestration.vulnerability_analysis_orchestrator import VulnerabilityAnalysisOrchestrator

class AgentLoop:
    MODEL = "gpt-4o-mini"

    def __init__(self, orchestrator: VulnerabilityAnalysisOrchestrator):
        self.client = OpenAI()
        self.orchestrator = orchestrator
        self.tools = Tools(orchestrator)


    def run_agent(self, question: str):
        """
        Each pass in the agent loop checks whether the model still wants a tool, and only exits when it doesn't
        (or hits the cap).
        The model does not execute the tool - my code runs the tool (tools.execute_tool).
        Model only emits a request (function name + arguments as json) inside its response.
        """
        # Create a running input list we will add to over time
        input_list = [{"role": "user", "content": question}]
        max_iterations = 5

        for _ in range(max_iterations):
            print("sending request with input list: ", input_list)
            response = self.client.responses.create(
                model=self.MODEL,
                tools=self.tools.tools,
                input=input_list,
            )
            # Receive tool call from model - Save function call outputs for subsequent requests
            # input list is the running conversation transcript - the API is stateless, it has
            # no memory of previous turns unless I resend them
            input_list += response.output
            print(input_list)
            tool_calls = [item for item in response.output if item.type == "function_call"]
            if not tool_calls:
                return response.output_text  # model is done, no more tools needed

            # Execute code on application side with input from tool call - bit that acc executes the functions
            for item in tool_calls:
                args = json.loads(item.arguments)
                result = self.tools.execute_tool(item.name, args)
                input_list.append({
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": result,
                })


        # hard cap as a max-iterations guard
        return "Max iterations reached without a final answer."




