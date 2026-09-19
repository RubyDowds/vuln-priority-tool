def test_enrich_happy_path_updates_score_and_percentile(epss_enrichment_service, mock_vulnerability_repository,
                                                          make_vulnerability):
    vuln = make_vulnerability()
    mock_vulnerability_repository.get_by_cve_id.return_value = vuln

    epss_enrichment_service.enrich([{"cve": "CVE-2024-1", "epss": 0.5, "percentile": 0.9}])

    assert vuln.epss_score == 0.5
    assert vuln.epss_percentile == 0.9
    mock_vulnerability_repository.save.assert_called_once_with(vuln)


def test_enrich_skips_when_cve_not_in_local_db(epss_enrichment_service, mock_vulnerability_repository):
    mock_vulnerability_repository.get_by_cve_id.return_value = None

    epss_enrichment_service.enrich([{"cve": "CVE-2024-1", "epss": 0.5, "percentile": 0.9}])

    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_falsy_cve_value_skips_before_db_lookup(epss_enrichment_service, mock_vulnerability_repository):
    epss_enrichment_service.enrich([{"cve": "", "epss": 0.1, "percentile": 0.1}])

    mock_vulnerability_repository.get_by_cve_id.assert_not_called()


def test_enrich_missing_cve_key_skips_item(epss_enrichment_service, mock_vulnerability_repository):
    epss_enrichment_service.enrich([{"epss": 0.1, "percentile": 0.1}])

    mock_vulnerability_repository.get_by_cve_id.assert_not_called()
    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_missing_epss_key_skips_and_logs_warning(epss_enrichment_service, mock_vulnerability_repository,
                                                          make_vulnerability):
    mock_vulnerability_repository.get_by_cve_id.return_value = make_vulnerability()

    epss_enrichment_service.enrich([{"cve": "CVE-2024-1", "percentile": 0.9}])

    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_missing_percentile_key_skips_and_logs_warning(epss_enrichment_service, mock_vulnerability_repository,
                                                                make_vulnerability):
    mock_vulnerability_repository.get_by_cve_id.return_value = make_vulnerability()

    epss_enrichment_service.enrich([{"cve": "CVE-2024-1", "epss": 0.5}])

    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_never_touches_enrichment_status_or_attempted_at(epss_enrichment_service, mock_vulnerability_repository,
                                                                   make_vulnerability):
    vuln = make_vulnerability(enrichment_status="sentinel-status", enrichment_attempted_at="sentinel-timestamp")
    mock_vulnerability_repository.get_by_cve_id.return_value = vuln

    epss_enrichment_service.enrich([{"cve": "CVE-2024-1", "epss": 0.5, "percentile": 0.9}])

    assert vuln.enrichment_status == "sentinel-status"
    assert vuln.enrichment_attempted_at == "sentinel-timestamp"
