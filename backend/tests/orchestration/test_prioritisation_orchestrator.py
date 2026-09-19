from unittest.mock import call

from app.orchestration.prioritisation_orchestrator import PrioritisationOrchestrator


def _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                        mock_priority_repository):
    return PrioritisationOrchestrator(mock_asset_repository, mock_vulnerability_repository,
                                       mock_decision_engine, mock_priority_repository)


def test_run_prioritisation_happy_path_multiple_pairs(mock_asset_repository, mock_vulnerability_repository,
                                                        mock_decision_engine, mock_priority_repository,
                                                        make_asset_vulnerability, make_asset, make_vulnerability):
    pair1 = make_asset_vulnerability(asset_id="asset-1", cve_id="CVE-1")
    pair2 = make_asset_vulnerability(asset_id="asset-2", cve_id="CVE-2")
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = [pair1, pair2]

    asset1, asset2 = make_asset(asset_id="asset-1"), make_asset(asset_id="asset-2")
    vuln1, vuln2 = make_vulnerability(cve_id="CVE-1"), make_vulnerability(cve_id="CVE-2")
    mock_asset_repository.get_by_id.side_effect = [asset1, asset2]
    mock_vulnerability_repository.get_by_cve_id.side_effect = [vuln1, vuln2]

    priority1, priority2 = {"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}
    mock_decision_engine.compute.side_effect = [priority1, priority2]

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_decision_engine.compute.assert_has_calls([call(asset1, vuln1), call(asset2, vuln2)])
    mock_priority_repository.upsert.assert_has_calls([call(priority1), call(priority2)])


def test_run_prioritisation_upsert_receives_exact_compute_result(mock_asset_repository, mock_vulnerability_repository,
                                                                   mock_decision_engine, mock_priority_repository,
                                                                   make_asset_vulnerability, make_asset,
                                                                   make_vulnerability):
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = [make_asset_vulnerability()]
    mock_asset_repository.get_by_id.return_value = make_asset()
    mock_vulnerability_repository.get_by_cve_id.return_value = make_vulnerability()

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_priority_repository.upsert.assert_called_once_with(mock_decision_engine.compute.return_value)


def test_run_prioritisation_skips_when_asset_missing(mock_asset_repository, mock_vulnerability_repository,
                                                       mock_decision_engine, mock_priority_repository,
                                                       make_asset_vulnerability, make_vulnerability):
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = [make_asset_vulnerability()]
    mock_asset_repository.get_by_id.return_value = None
    mock_vulnerability_repository.get_by_cve_id.return_value = make_vulnerability()

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_decision_engine.compute.assert_not_called()
    mock_priority_repository.upsert.assert_not_called()


def test_run_prioritisation_skips_when_vuln_missing(mock_asset_repository, mock_vulnerability_repository,
                                                      mock_decision_engine, mock_priority_repository,
                                                      make_asset_vulnerability, make_asset):
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = [make_asset_vulnerability()]
    mock_asset_repository.get_by_id.return_value = make_asset()
    mock_vulnerability_repository.get_by_cve_id.return_value = None

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_decision_engine.compute.assert_not_called()
    mock_priority_repository.upsert.assert_not_called()


def test_run_prioritisation_skips_when_both_missing(mock_asset_repository, mock_vulnerability_repository,
                                                      mock_decision_engine, mock_priority_repository,
                                                      make_asset_vulnerability):
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = [make_asset_vulnerability()]
    mock_asset_repository.get_by_id.return_value = None
    mock_vulnerability_repository.get_by_cve_id.return_value = None

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_decision_engine.compute.assert_not_called()
    mock_priority_repository.upsert.assert_not_called()


def test_run_prioritisation_empty_pairs_does_nothing(mock_asset_repository, mock_vulnerability_repository,
                                                       mock_decision_engine, mock_priority_repository):
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = []

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_asset_repository.get_by_id.assert_not_called()
    mock_vulnerability_repository.get_by_cve_id.assert_not_called()
    mock_decision_engine.compute.assert_not_called()
    mock_priority_repository.upsert.assert_not_called()


def test_run_prioritisation_mixed_valid_and_invalid_pairs(mock_asset_repository, mock_vulnerability_repository,
                                                            mock_decision_engine, mock_priority_repository,
                                                            make_asset_vulnerability, make_asset, make_vulnerability):
    pairs = [
        make_asset_vulnerability(asset_id="asset-valid", cve_id="CVE-valid"),
        make_asset_vulnerability(asset_id="asset-missing", cve_id="CVE-missing-asset"),
        make_asset_vulnerability(asset_id="asset-missing-vuln", cve_id="CVE-missing-vuln"),
    ]
    mock_asset_repository.get_all_asset_vulnerabilities.return_value = pairs

    valid_asset = make_asset(asset_id="asset-valid")
    valid_vuln = make_vulnerability(cve_id="CVE-valid")
    mock_asset_repository.get_by_id.side_effect = [valid_asset, None, valid_asset]
    mock_vulnerability_repository.get_by_cve_id.side_effect = [valid_vuln, valid_vuln, None]

    orchestrator = _make_orchestrator(mock_asset_repository, mock_vulnerability_repository, mock_decision_engine,
                                       mock_priority_repository)
    orchestrator.run_prioritisation()

    mock_decision_engine.compute.assert_called_once_with(valid_asset, valid_vuln)
    mock_priority_repository.upsert.assert_called_once()
