import pytest

from app.orchestration.tools import Tools


@pytest.mark.parametrize("tool_name", ["search_priorities", "lookup_cve_details"])
def test_dispatch_table_wired_to_own_methods(tools, tool_name):
    # Tools._dispatch captures bound methods at __init__ time, so this must be checked by
    # identity rather than by patching tools.<method> after construction (that patch would
    # never reach _dispatch, since it already holds a reference to the original bound method).
    assert tools._dispatch[tool_name] == getattr(tools, tool_name)


def test_execute_tool_unknown_tool_raises_value_error(tools):
    with pytest.raises(ValueError, match="Unknown tool: does_not_exist"):
        tools.execute_tool("does_not_exist", {})


@pytest.mark.parametrize("schema", Tools.tools, ids=lambda schema: schema["name"])
def test_tools_schema_entries_have_required_shape(tools, schema):
    assert schema["type"] == "function"
    assert "name" in schema
    assert "description" in schema
    assert "parameters" in schema
    assert schema["name"] in tools._dispatch


def test_execute_tool_search_priorities_happy_path(tools, mock_priority_retrieval_service):
    search_results = [{"asset_id": "a1", "cve_id": "CVE-1", "ssvc_decision": "immediate"}]
    mock_priority_retrieval_service.priority_semantic_search.return_value = search_results
    mock_priority_retrieval_service.build_priority_context_from_metadata.return_value = "formatted context"

    result = tools.execute_tool("search_priorities", {"question": "What should I patch?"})

    assert result == "formatted context"
    mock_priority_retrieval_service.priority_semantic_search.assert_called_once_with("What should I patch?")
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_called_once_with(search_results)


def test_execute_tool_search_priorities_no_results(tools, mock_priority_retrieval_service):
    mock_priority_retrieval_service.priority_semantic_search.return_value = []
    mock_priority_retrieval_service.build_priority_context_from_metadata.return_value = (
        "No prioritisation data available."
    )

    result = tools.execute_tool("search_priorities", {"question": "Anything urgent?"})

    assert result == "No prioritisation data available."
    mock_priority_retrieval_service.priority_semantic_search.assert_called_once_with("Anything urgent?")
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_called_once_with([])


def test_lookup_cve_details_not_found(tools, mock_vulnerability_repository, mock_priority_repository,
                                       mock_priority_retrieval_service):
    mock_vulnerability_repository.get_by_cve_id.return_value = None

    result = tools.execute_tool("lookup_cve_details", {"cve_id": "CVE-9999-0001"})

    assert result == "CVE-9999-0001 was not found in the vulnerability database."
    mock_vulnerability_repository.get_by_cve_id.assert_called_once_with("CVE-9999-0001")
    mock_priority_repository.get_by_cve_id.assert_not_called()
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_not_called()


def test_lookup_cve_details_found_with_exposure(tools, mock_vulnerability_repository, mock_priority_repository,
                                                 mock_priority_retrieval_service, make_vulnerability,
                                                 make_remediation_priority):
    vulnerability = make_vulnerability(cve_id="CVE-2022-31199", description="Some RCE description")
    priorities = [
        make_remediation_priority(asset_id="asset-1", cve_id="CVE-2022-31199", ssvc_decision="immediate",
                                   remediation_days=3, automatable=True, technical_impact="total"),
        make_remediation_priority(asset_id="asset-2", cve_id="CVE-2022-31199", ssvc_decision="scheduled",
                                   remediation_days=60, automatable=False, technical_impact="partial"),
    ]
    mock_vulnerability_repository.get_by_cve_id.return_value = vulnerability
    mock_priority_repository.get_by_cve_id.return_value = priorities
    mock_priority_retrieval_service.build_priority_context_from_metadata.return_value = "formatted priority context"

    result = tools.execute_tool("lookup_cve_details", {"cve_id": "CVE-2022-31199"})

    mock_priority_repository.get_by_cve_id.assert_called_once_with("CVE-2022-31199")
    expected_dicts = [
        {"asset_id": "asset-1", "cve_id": "CVE-2022-31199", "ssvc_decision": "immediate",
         "remediation_days": 3, "automatable": True, "technical_impact": "total"},
        {"asset_id": "asset-2", "cve_id": "CVE-2022-31199", "ssvc_decision": "scheduled",
         "remediation_days": 60, "automatable": False, "technical_impact": "partial"},
    ]
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_called_once_with(expected_dicts)
    assert result == (
        "CVE: CVE-2022-31199\nDescription: Some RCE description\n\nformatted priority context"
    )


def test_lookup_cve_details_found_without_exposure(tools, mock_vulnerability_repository, mock_priority_repository,
                                                     mock_priority_retrieval_service, make_vulnerability):
    vulnerability = make_vulnerability(cve_id="CVE-2022-31199", description="Some RCE description")
    mock_vulnerability_repository.get_by_cve_id.return_value = vulnerability
    mock_priority_repository.get_by_cve_id.return_value = []

    result = tools.execute_tool("lookup_cve_details", {"cve_id": "CVE-2022-31199"})

    assert result == (
        "CVE: CVE-2022-31199\nDescription: Some RCE description\n\n"
        "No organisational exposure found — this CVE is not linked to any tracked assets."
    )
    mock_priority_retrieval_service.build_priority_context_from_metadata.assert_not_called()
