from datetime import datetime, timedelta
from unittest.mock import call

import pytest

from app.enrichment.enrichment_orchestrator import EnrichmentOrchestrator


@pytest.fixture
def frozen_utcnow(mocker):
    fixed_now = datetime(2026, 1, 15, 12, 0, 0)
    mock_datetime = mocker.patch("app.enrichment.enrichment_orchestrator.datetime")
    mock_datetime.utcnow.return_value = fixed_now
    return fixed_now


def test_get_pending_enrichment_queries_each_status_with_correct_cutoff(enrichment_orchestrator,
                                                                          mock_vulnerability_repository,
                                                                          frozen_utcnow):
    mock_vulnerability_repository.get_by_enrichment_status.return_value = []

    enrichment_orchestrator._get_pending_enrichment()

    assert mock_vulnerability_repository.get_by_enrichment_status.call_count == len(EnrichmentOrchestrator.RETRY_AFTER)
    for status, days in EnrichmentOrchestrator.RETRY_AFTER.items():
        mock_vulnerability_repository.get_by_enrichment_status.assert_any_call(
            status=status, attempted_before=frozen_utcnow - timedelta(days=days)
        )


def test_get_pending_enrichment_aggregates_across_statuses(enrichment_orchestrator, mock_vulnerability_repository,
                                                             frozen_utcnow, make_vulnerability):
    per_status_results = [[make_vulnerability(cve_id=f"CVE-{i}")] for i in range(len(EnrichmentOrchestrator.RETRY_AFTER))]
    mock_vulnerability_repository.get_by_enrichment_status.side_effect = per_status_results

    result = enrichment_orchestrator._get_pending_enrichment()

    expected = [v for group in per_status_results for v in group]
    assert result == expected


def test_run_skips_nvd_phase_when_pending_is_empty(enrichment_orchestrator, mock_vulnerability_repository,
                                                     mock_nvd_client, mock_enrichment_service, mock_epss_client,
                                                     mock_epss_enrichment_service, frozen_utcnow):
    mock_vulnerability_repository.get_by_enrichment_status.return_value = []
    mock_vulnerability_repository.get_all.return_value = []

    enrichment_orchestrator.run()

    mock_nvd_client.fetch_all.assert_not_called()
    mock_enrichment_service.enrich.assert_not_called()
    mock_epss_client.fetch_all.assert_called_once_with([])
    mock_epss_enrichment_service.enrich.assert_called_once()


def test_run_epss_phase_uses_all_cve_ids_not_pending_ids(enrichment_orchestrator, mock_vulnerability_repository,
                                                          mock_nvd_client, mock_epss_client, frozen_utcnow,
                                                          make_vulnerability):
    mock_vulnerability_repository.get_by_enrichment_status.side_effect = (
        lambda status, attempted_before: [make_vulnerability(cve_id="CVE-1")] if status == "pending" else []
    )
    mock_vulnerability_repository.get_all.return_value = [
        make_vulnerability(cve_id="CVE-1"), make_vulnerability(cve_id="CVE-2"), make_vulnerability(cve_id="CVE-3"),
    ]

    enrichment_orchestrator.run()

    mock_nvd_client.fetch_all.assert_called_once_with(["CVE-1"])
    mock_epss_client.fetch_all.assert_called_once_with(["CVE-1", "CVE-2", "CVE-3"])


def test_run_call_order_and_argument_wiring(enrichment_orchestrator, mock_vulnerability_repository, mock_nvd_client,
                                             mock_enrichment_service, mock_epss_client, mock_epss_enrichment_service,
                                             frozen_utcnow, make_vulnerability, mocker):
    pending_vuln = make_vulnerability(cve_id="CVE-1")
    mock_vulnerability_repository.get_by_enrichment_status.side_effect = (
        lambda status, attempted_before: [pending_vuln] if status == "pending" else []
    )
    mock_vulnerability_repository.get_all.return_value = [pending_vuln]
    mock_nvd_client.fetch_all.return_value = ["nvd-item"]
    mock_epss_client.fetch_all.return_value = ["epss-item"]

    manager = mocker.MagicMock()
    manager.attach_mock(mock_nvd_client.fetch_all, "nvd_fetch_all")
    manager.attach_mock(mock_enrichment_service.enrich, "nvd_enrich")
    manager.attach_mock(mock_vulnerability_repository.get_all, "get_all")
    manager.attach_mock(mock_epss_client.fetch_all, "epss_fetch_all")
    manager.attach_mock(mock_epss_enrichment_service.enrich, "epss_enrich")

    enrichment_orchestrator.run()

    assert [c[0] for c in manager.mock_calls] == [
        "nvd_fetch_all", "nvd_enrich", "get_all", "epss_fetch_all", "epss_enrich",
    ]
    mock_enrichment_service.enrich.assert_called_once_with(["nvd-item"])
    mock_epss_enrichment_service.enrich.assert_called_once_with(["epss-item"])


def test_run_no_exception_handling_propagates_client_errors(enrichment_orchestrator, mock_vulnerability_repository,
                                                              mock_nvd_client, mock_epss_client, frozen_utcnow,
                                                              make_vulnerability):
    mock_vulnerability_repository.get_by_enrichment_status.side_effect = (
        lambda status, attempted_before: [make_vulnerability()] if status == "pending" else []
    )
    mock_nvd_client.fetch_all.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        enrichment_orchestrator.run()

    mock_epss_client.fetch_all.assert_not_called()


def test_retry_after_includes_ssvc_only_key():
    assert "ssvc_only" in EnrichmentOrchestrator.RETRY_AFTER
    assert "ssv_only" not in EnrichmentOrchestrator.RETRY_AFTER


def test_get_pending_enrichment_queries_ssvc_only_status(enrichment_orchestrator, mock_vulnerability_repository,
                                                           frozen_utcnow):
    mock_vulnerability_repository.get_by_enrichment_status.return_value = []

    enrichment_orchestrator._get_pending_enrichment()

    mock_vulnerability_repository.get_by_enrichment_status.assert_any_call(
        status="ssvc_only", attempted_before=frozen_utcnow - timedelta(days=3)
    )
