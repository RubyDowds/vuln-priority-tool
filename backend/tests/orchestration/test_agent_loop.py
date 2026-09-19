from unittest.mock import call

from app.orchestration.agent_loop import AgentLoop
from tests.conftest import make_function_call, make_message_output, make_response


def _capturing_side_effect(responses):
    """
    AgentLoop mutates the same `input_list` object in place across the whole loop
    (`input_list += response.output`, `input_list.append(...)`), so `mock.call_args_list`
    entries all end up pointing at the *same* list — by the time the test inspects them,
    every recorded call shows the final, fully-mutated state, not what was actually sent on
    that call. Snapshotting a shallow copy of `input` at call time avoids that.
    """
    captured = []

    def _create(*args, **kwargs):
        captured.append(list(kwargs["input"]))
        return responses.pop(0)

    return _create, captured


def test_run_agent_immediate_answer_no_tool_calls(agent_loop, mock_openai_client, mock_tools):
    create, captured_inputs = _capturing_side_effect([
        make_response(output=[make_message_output()], output_text="Here is your answer."),
    ])
    mock_openai_client.responses.create.side_effect = create

    result = agent_loop.run_agent("What should I patch?")

    assert result == {"answer": "Here is your answer.", "tools_called": [], "tool_outputs": []}
    assert mock_openai_client.responses.create.call_count == 1
    mock_tools.execute_tool.assert_not_called()

    _, kwargs = mock_openai_client.responses.create.call_args
    assert kwargs["model"] == AgentLoop.MODEL
    assert kwargs["tools"] == mock_tools.tools
    assert captured_inputs[0][0]["role"] == "developer"
    assert captured_inputs[0][1] == {"role": "user", "content": "What should I patch?"}
    assert len(captured_inputs[0]) == 2


def test_run_agent_single_tool_call_then_answer(agent_loop, mock_openai_client, mock_tools):
    create, captured_inputs = _capturing_side_effect([
        make_response(output=[
            make_function_call("search_priorities", {"question": "what to patch"}, call_id="call_1"),
        ]),
        make_response(output=[make_message_output()], output_text="Final answer using search results."),
    ])
    mock_openai_client.responses.create.side_effect = create
    mock_tools.execute_tool.return_value = "tool result text"

    result = agent_loop.run_agent("What should I patch?")

    assert result == {
        "answer": "Final answer using search results.",
        "tools_called": ["search_priorities"],
        "tool_outputs": ["tool result text"],
    }
    assert mock_openai_client.responses.create.call_count == 2
    mock_tools.execute_tool.assert_called_once_with("search_priorities", {"question": "what to patch"})
    mock_tools.search_priorities.assert_not_called()

    # captured_inputs[1] is what was sent on the *second* create() call
    assert captured_inputs[1][-1] == {
        "type": "function_call_output",
        "call_id": "call_1",
        "output": "tool result text",
    }


def test_run_agent_multi_tool_call_in_single_response(agent_loop, mock_openai_client, mock_tools):
    create, captured_inputs = _capturing_side_effect([
        make_response(output=[
            make_function_call("search_priorities", {"question": "q1"}, call_id="call_1"),
            make_function_call("lookup_cve_details", {"cve_id": "CVE-2024-1"}, call_id="call_2"),
        ]),
        make_response(output=[make_message_output()], output_text="Combined answer."),
    ])
    mock_openai_client.responses.create.side_effect = create
    mock_tools.execute_tool.side_effect = ["search result", "cve result"]

    result = agent_loop.run_agent("Tell me everything")

    assert mock_tools.execute_tool.call_count == 2
    mock_tools.execute_tool.assert_has_calls([
        call("search_priorities", {"question": "q1"}),
        call("lookup_cve_details", {"cve_id": "CVE-2024-1"}),
    ])
    assert result["tools_called"] == ["search_priorities", "lookup_cve_details"]
    assert result["tool_outputs"] == ["search result", "cve result"]

    second_call_input = captured_inputs[1]
    function_call_outputs = [
        item for item in second_call_input
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    ]
    assert function_call_outputs == [
        {"type": "function_call_output", "call_id": "call_1", "output": "search result"},
        {"type": "function_call_output", "call_id": "call_2", "output": "cve result"},
    ]


def test_run_agent_max_iterations_exhausted(agent_loop, mock_openai_client, mock_tools):
    mock_openai_client.responses.create.side_effect = lambda *args, **kwargs: make_response(
        output=[make_function_call("search_priorities", {"question": "q"}, call_id="call_x")]
    )
    mock_tools.execute_tool.return_value = "tool result"

    result = agent_loop.run_agent("Keep going forever")

    assert mock_openai_client.responses.create.call_count == 5
    assert result == {
        "answer": "Max iterations reached without a final answer.",
        "tools_called": ["search_priorities"] * 5,
        "tool_outputs": ["tool result"] * 5,
    }
