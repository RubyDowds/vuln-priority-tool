from datetime import datetime

import pytest

from app.enrichment.nvd_enrichment_service import NVDEnrichmentService


@pytest.fixture
def frozen_utcnow(mocker):
    fixed_now = datetime(2026, 1, 15, 12, 0, 0)
    mock_datetime = mocker.patch("app.enrichment.nvd_enrichment_service.datetime")
    mock_datetime.utcnow.return_value = fixed_now
    return fixed_now


# --- enrich() top-level control flow ---

def test_enrich_skips_when_id_missing(nvd_enrichment_service, mock_vulnerability_repository):
    nvd_enrichment_service.enrich([{"metrics": {}}])

    mock_vulnerability_repository.get_by_cve_id.assert_not_called()
    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_skips_when_cve_not_in_local_db(nvd_enrichment_service, mock_vulnerability_repository):
    mock_vulnerability_repository.get_by_cve_id.return_value = None

    nvd_enrichment_service.enrich([{"id": "CVE-2024-1", "metrics": {}}])

    mock_vulnerability_repository.save.assert_not_called()


def test_enrich_happy_path_calls_update_and_derive(nvd_enrichment_service, mock_vulnerability_repository,
                                                     make_vulnerability, frozen_utcnow):
    vuln = make_vulnerability(technical_impact=None, cvss_vector=None, ssvc_source=None)
    mock_vulnerability_repository.get_by_cve_id.return_value = vuln
    cve_data = {
        "id": "CVE-2024-1",
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseSeverity": "CRITICAL",
            }}],
        },
    }

    nvd_enrichment_service.enrich([cve_data])

    assert vuln.base_score == 9.8
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vuln.technical_impact == "total"  # derived from the vector since NVD gave no SSVC data
    assert mock_vulnerability_repository.save.call_count == 2  # once from _update, once from _derive_missing_ssvc


# --- _extract_cvss ---

def test_extract_cvss_prefers_primary_over_secondary(nvd_enrichment_service):
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 1.0, "vectorString": "secondary-vector", "baseSeverity": "LOW"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.0, "vectorString": "primary-vector", "baseSeverity": "CRITICAL"}},
        ],
    }

    result = nvd_enrichment_service._extract_cvss(metrics)

    assert result == {"base_score": 9.0, "cvss_vector": "primary-vector", "cvss_severity": "CRITICAL"}


def test_extract_cvss_falls_back_to_secondary_when_no_primary(nvd_enrichment_service):
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0, "vectorString": "secondary-vector", "baseSeverity": "MEDIUM"}},
        ],
    }

    result = nvd_enrichment_service._extract_cvss(metrics)

    assert result == {"base_score": 5.0, "cvss_vector": "secondary-vector", "cvss_severity": "MEDIUM"}


def test_extract_cvss_checks_v31_then_v30_then_v40_order(nvd_enrichment_service):
    metrics = {
        "cvssMetricV31": [],
        "cvssMetricV30": [],
        "cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": 7.0, "vectorString": "v40-vector", "baseSeverity": "HIGH"}}],
    }

    result = nvd_enrichment_service._extract_cvss(metrics)

    assert result == {"base_score": 7.0, "cvss_vector": "v40-vector", "cvss_severity": "HIGH"}


def test_extract_cvss_returns_all_none_when_nothing_found(nvd_enrichment_service):
    result = nvd_enrichment_service._extract_cvss({})

    assert result == {"base_score": None, "cvss_vector": None, "cvss_severity": None}


def test_extract_cvss_returns_none_fields_when_matched_metric_missing_cvssdata(nvd_enrichment_service):
    metrics = {"cvssMetricV31": [{"type": "Primary"}]}  # no "cvssData" key at all

    result = nvd_enrichment_service._extract_cvss(metrics)

    assert result == {"base_score": None, "cvss_vector": None, "cvss_severity": None}


# --- _extract_ssvc ---

def test_extract_ssvc_happy_path_parses_options_into_flat_dict(nvd_enrichment_service):
    metrics = {
        "ssvcV203": [{
            "ssvcData": {
                "options": [
                    {"exploitation": "active"},
                    {"automatable": "yes"},
                    {"technicalImpact": "total"},
                ],
            },
        }],
    }

    result = nvd_enrichment_service._extract_ssvc(metrics)

    assert result == {
        "exploitation": "active", "automatable": "yes", "technical_impact": "total", "ssvc_source": "cisa",
    }


def test_extract_ssvc_empty_list_returns_all_none(nvd_enrichment_service):
    result = nvd_enrichment_service._extract_ssvc({})

    assert result == {"exploitation": None, "automatable": None, "technical_impact": None, "ssvc_source": None}


def test_extract_ssvc_returns_none_fields_when_ssvcdata_missing(nvd_enrichment_service):
    metrics = {"ssvcV203": [{}]}  # no "ssvcData" key at all

    result = nvd_enrichment_service._extract_ssvc(metrics)

    # ssvc_source is still "cisa" here (not None) because an ssvcV203 entry WAS present,
    # just malformed - distinct from the "no ssvcV203 key at all" branch above.
    assert result == {"exploitation": None, "automatable": None, "technical_impact": None, "ssvc_source": "cisa"}


# --- _determine_status (pure function, correct as-is) ---

@pytest.mark.parametrize("has_cvss,has_ssvc,expected", [
    (True, True, "enriched"),
    (True, False, "cvss_only"),
    (False, True, "ssvc_only"),
    (False, False, "not_enriched"),
])
def test_determine_status_truth_table(has_cvss, has_ssvc, expected):
    assert NVDEnrichmentService._determine_status(has_cvss, has_ssvc) == expected


# --- _update ---

def test_update_sets_all_fields_from_enriched_dict(nvd_enrichment_service, mock_vulnerability_repository,
                                                     make_vulnerability):
    vuln = make_vulnerability()
    enriched = {
        "base_score": 9.8, "cvss_vector": "vector-string", "cvss_severity": "CRITICAL",
        "automatable": "yes", "technical_impact": "total", "exploitation": "active",
        "ssvc_source": "cisa", "enrichment_attempted_at": datetime(2026, 1, 15),
    }

    nvd_enrichment_service._update(vuln, enriched)

    assert vuln.base_score == 9.8
    assert vuln.cvss_vector == "vector-string"
    assert vuln.cvss_severity == "CRITICAL"
    assert vuln.automatable == "yes"
    assert vuln.technical_impact == "total"
    assert vuln.exploitation == "active"
    assert vuln.ssvc_source == "cisa"
    assert vuln.enrichment_status == "enriched"
    assert vuln.enrichment_attempted_at == datetime(2026, 1, 15)
    mock_vulnerability_repository.save.assert_called_once_with(vuln)


def test_update_status_valid_cvss_present_yields_cvss_only(nvd_enrichment_service, make_vulnerability):
    vuln = make_vulnerability()
    enriched = {"base_score": 9.8, "cvss_vector": "vector-string", "cvss_severity": "CRITICAL",
                "automatable": None, "technical_impact": None, "exploitation": None,
                "ssvc_source": None, "enrichment_attempted_at": None}

    nvd_enrichment_service._update(vuln, enriched)

    assert vuln.enrichment_status == "cvss_only"


@pytest.mark.parametrize("enriched_extra,expected_status", [
    ({"cvss_vector": "v", "automatable": None}, "cvss_only"),
    ({"cvss_vector": None, "automatable": "yes"}, "ssvc_only"),
    ({"cvss_vector": "v", "automatable": "yes"}, "enriched"),
    ({"cvss_vector": None, "automatable": None}, "not_enriched"),
])
def test_update_status_all_four_outcomes_reachable(nvd_enrichment_service, make_vulnerability, enriched_extra,
                                                     expected_status):
    vuln = make_vulnerability()
    enriched = {"base_score": None, "cvss_severity": None, "technical_impact": None,
                "exploitation": None, "ssvc_source": None, "enrichment_attempted_at": None, **enriched_extra}

    nvd_enrichment_service._update(vuln, enriched)

    assert vuln.enrichment_status == expected_status


# --- _derive_missing_ssvc ---

def test_derive_missing_ssvc_noop_when_technical_impact_already_set(nvd_enrichment_service,
                                                                       mock_vulnerability_repository,
                                                                       make_vulnerability):
    vuln = make_vulnerability(technical_impact="partial", cvss_vector="some-vector", ssvc_source=None)

    nvd_enrichment_service._derive_missing_ssvc(vuln)

    assert vuln.technical_impact == "partial"
    mock_vulnerability_repository.save.assert_not_called()


def test_derive_missing_ssvc_noop_when_no_cvss_vector(nvd_enrichment_service, mock_vulnerability_repository,
                                                        make_vulnerability):
    vuln = make_vulnerability(technical_impact=None, cvss_vector=None, ssvc_source=None)

    nvd_enrichment_service._derive_missing_ssvc(vuln)

    assert vuln.technical_impact is None
    mock_vulnerability_repository.save.assert_not_called()


def test_derive_missing_ssvc_derives_and_sets_cvss_derived_when_source_none(nvd_enrichment_service,
                                                                              mock_vulnerability_repository,
                                                                              make_vulnerability):
    vuln = make_vulnerability(technical_impact=None,
                               cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ssvc_source=None)

    nvd_enrichment_service._derive_missing_ssvc(vuln)

    assert vuln.technical_impact == "total"
    assert vuln.ssvc_source == "cvss_derived"
    mock_vulnerability_repository.save.assert_called_once_with(vuln)


def test_derive_missing_ssvc_preserves_existing_ssvc_source(nvd_enrichment_service, mock_vulnerability_repository,
                                                               make_vulnerability):
    vuln = make_vulnerability(technical_impact=None,
                               cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ssvc_source="cisa")

    nvd_enrichment_service._derive_missing_ssvc(vuln)

    assert vuln.ssvc_source == "cisa"
    mock_vulnerability_repository.save.assert_called_once_with(vuln)


def test_enrich_calls_save_twice_when_derive_branch_taken(nvd_enrichment_service, mock_vulnerability_repository,
                                                            make_vulnerability, frozen_utcnow):
    vuln = make_vulnerability(technical_impact=None, cvss_vector=None, ssvc_source=None)
    mock_vulnerability_repository.get_by_cve_id.return_value = vuln
    cve_data = {"id": "CVE-2024-1", "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseSeverity": "CRITICAL",
    }}]}}

    nvd_enrichment_service.enrich([cve_data])

    assert mock_vulnerability_repository.save.call_count == 2


def test_enrich_calls_save_once_when_derive_is_noop(nvd_enrichment_service, mock_vulnerability_repository,
                                                      make_vulnerability, frozen_utcnow):
    vuln = make_vulnerability(technical_impact=None, cvss_vector=None, ssvc_source=None)
    mock_vulnerability_repository.get_by_cve_id.return_value = vuln
    cve_data = {"id": "CVE-2024-1", "metrics": {
        "cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseSeverity": "CRITICAL",
        }}],
        "ssvcV203": [{"ssvcData": {"options": [{"technicalImpact": "partial"}]}}],
    }}

    nvd_enrichment_service.enrich([cve_data])

    assert mock_vulnerability_repository.save.call_count == 1


# --- _derive_technical_impact_from_cvss ---

@pytest.mark.parametrize("cvss_vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "total"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "partial"),
    ("", None),
    (None, None),
])
def test_derive_technical_impact_from_cvss_truth_table(cvss_vector, expected):
    # Naive substring matching, not real CVSS AV/AC parsing - documented as-is, not fixed here.
    assert NVDEnrichmentService._derive_technical_impact_from_cvss(cvss_vector) == expected
