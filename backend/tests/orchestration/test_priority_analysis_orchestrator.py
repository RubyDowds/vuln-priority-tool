"""
PriorityAnalysisOrchestrator is confirmed dead code (docstring: "OLD orchestrator (since
replaced with Agent loop)") - no live route calls it. Tests here are a lighter pass, kept
only because the class was explicitly named for coverage.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.orchestration.priority_analysis_orchestrator import PriorityAnalysisOrchestrator


@pytest.fixture
def mock_chat_openai_client(mocker):
    client = MagicMock()
    mocker.patch("app.orchestration.priority_analysis_orchestrator.OpenAI", return_value=client)
    return client


@pytest.fixture
def orchestrator(mock_chat_openai_client, mock_priority_repository, mock_priority_retrieval_service):
    return PriorityAnalysisOrchestrator(mock_priority_repository, mock_priority_retrieval_service)


def test_analyse_happy_path_calls_search_then_context_then_llm(orchestrator, mock_priority_retrieval_service,
                                                                 mock_chat_openai_client):
    search_results = [{"asset_id": "a1", "cve_id": "CVE-1"}]
    mock_priority_retrieval_service.priority_semantic_search.return_value = search_results
    mock_priority_retrieval_service.build_priority_context_from_metadata.return_value = "some context"
    mock_chat_openai_client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="the answer"))]
    )

    result = orchestrator.analyse("What should I patch?")

    mock_priority_retrieval_service.priority_semantic_search.assert_called_once_with("What should I patch?")
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_called_once_with(search_results)
    _, kwargs = mock_chat_openai_client.chat.completions.create.call_args
    assert kwargs["model"] == PriorityAnalysisOrchestrator.MODEL
    assert result == "the answer"


def test_analyse_prompt_includes_context_and_question(orchestrator, mock_priority_retrieval_service,
                                                        mock_chat_openai_client):
    mock_priority_retrieval_service.build_priority_context_from_metadata.return_value = "unique-context-marker"
    mock_chat_openai_client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="answer"))]
    )

    orchestrator.analyse("unique-question-marker")

    _, kwargs = mock_chat_openai_client.chat.completions.create.call_args
    prompt = kwargs["messages"][0]["content"]
    assert "unique-context-marker" in prompt
    assert "unique-question-marker" in prompt


def test_call_llm_returns_message_content(orchestrator, mock_chat_openai_client):
    mock_chat_openai_client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="answer text"))]
    )

    result = orchestrator._call_llm("some prompt")

    assert result == "answer text"
