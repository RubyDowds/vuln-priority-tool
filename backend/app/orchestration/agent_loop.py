from openai import OpenAI
import json
import logging

from app.orchestration.tools import Tools

class AgentLoop:
    MODEL = "gpt-4o-mini" # todo define elsewhere

    def __init__(self, tools: Tools):
        self.client = OpenAI()
        self.tools = tools
        self.logger = logging.getLogger(__name__)


    def run_agent(self, question: str):
        """
        Each pass in the agent loop checks whether the model still wants a tool, and only exits when it doesn't
        (or hits the cap).
        The model does not execute the tool - my code runs the tool (tools.execute_tool).
        Model only emits a request (function name + arguments as json) inside its response.
        """
        # Create a running input list we will add to over time
        input_list = [
            {
                "role": "developer",
                "content": (
                    "You are a security analyst assistant with access to tools that query "
                    "real prioritisation and vulnerability data. Always use the available "
                    "tools to look up relevant data before asking the user a clarifying "
                    "question. Only ask for clarification if a tool returns no relevant results."
                ),
            },
            {"role": "user", "content": question},
        ]
        tools_called = []
        tool_outputs = []
        max_iterations = 5

        for _ in range(max_iterations):
            response = self.client.responses.create(
                model=self.MODEL,
                tools=self.tools.tools,
                input=input_list,
            )
            # Receive tool call from model - Save function call outputs for subsequent requests
            # input list is the running conversation transcript - the API is stateless, it has
            # no memory of previous turns unless I resend them
            input_list += response.output
            self.logger.debug(input_list)
            tool_calls = [item for item in response.output if item.type == "function_call"]
            tools_called.extend(item.name for item in tool_calls)

            # model is done as it returned text, no more tools needed
            if not tool_calls:
                self.logger.info(f"Agent finished. Tools used: {tools_called}")
                return {"answer": response.output_text, "tools_called": tools_called, "tool_outputs": tool_outputs}

            # Execute code on application side with input from tool call - bit that acc executes the functions
            for item in tool_calls:
                args = json.loads(item.arguments)
                self.logger.info(f"Agent selected tool: {item.name} with args: {args}")
                result = self.tools.execute_tool(item.name, args)
                tool_outputs.append(result)
                input_list.append({
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": result,
                })

        # hard cap as a max-iterations guard
        return {
            "answer": "Max iterations reached without a final answer.",
            "tools_called": tools_called,
            "tool_outputs": tool_outputs,
        }



