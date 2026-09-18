import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from app.orchestration.agent_loop import AgentLoop
from app.orchestration.tools import Tools
from app.repositories.priority_repository import PriorityRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService


@pytest.fixture(autouse=True)
def dummy_openai_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-for-unit-tests")


@pytest.fixture
def mock_priority_repository():
    return Mock(spec=PriorityRepository)


@pytest.fixture
def mock_vulnerability_repository():
    return Mock(spec=VulnerabilityRepository)


@pytest.fixture
def mock_priority_retrieval_service():
    # spec=PriorityRetrievalService never calls __init__, so the real SentenceTransformer/
    # ChromaDB construction it does is never triggered.
    return Mock(spec=PriorityRetrievalService)


@pytest.fixture
def tools(mock_priority_repository, mock_priority_retrieval_service, mock_vulnerability_repository):
    return Tools(mock_priority_repository, mock_priority_retrieval_service, mock_vulnerability_repository)


@pytest.fixture
def make_vulnerability():
    def _make(cve_id="CVE-2024-00001", description="A test vulnerability description.", **overrides):
        return SimpleNamespace(cve_id=cve_id, description=description, **overrides)
    return _make


@pytest.fixture
def make_remediation_priority():
    def _make(asset_id="asset-1", cve_id="CVE-2024-00001", ssvc_decision="immediate",
              remediation_days=3, automatable=True, technical_impact="total", **overrides):
        return SimpleNamespace(asset_id=asset_id, cve_id=cve_id, ssvc_decision=ssvc_decision,
                                remediation_days=remediation_days, automatable=automatable,
                                technical_impact=technical_impact, **overrides)
    return _make


@pytest.fixture
def mock_openai_client(mocker):
    client = MagicMock()
    mocker.patch("app.orchestration.agent_loop.OpenAI", return_value=client)
    return client


@pytest.fixture
def mock_tools():
    stub = Mock(spec=Tools)
    stub.tools = Tools.tools  # keep the real schema list so call-arg assertions can check it's passed through
    return stub


@pytest.fixture
def agent_loop(mock_openai_client, mock_tools):
    return AgentLoop(mock_tools)


def make_function_call(name: str, arguments: dict, call_id: str = "call_1"):
    return SimpleNamespace(type="function_call", name=name, arguments=json.dumps(arguments), call_id=call_id)


def make_message_output():
    return SimpleNamespace(type="message")


def make_response(output: list, output_text: str = ""):
    return SimpleNamespace(output=output, output_text=output_text)
