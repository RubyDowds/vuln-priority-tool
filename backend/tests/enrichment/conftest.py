from unittest.mock import Mock

import pytest

from app.clients.epss_client import EpssClient
from app.clients.nvd_client import NVDClient
from app.enrichment.enrichment_orchestrator import EnrichmentOrchestrator
from app.enrichment.epss_enrichment_service import EpssEnrichmentService
from app.enrichment.nvd_enrichment_service import NVDEnrichmentService


@pytest.fixture
def mock_nvd_client():
    return Mock(spec=NVDClient)


@pytest.fixture
def mock_epss_client():
    return Mock(spec=EpssClient)


@pytest.fixture
def mock_enrichment_service():
    return Mock(spec=NVDEnrichmentService)


@pytest.fixture
def mock_epss_enrichment_service():
    return Mock(spec=EpssEnrichmentService)


@pytest.fixture
def enrichment_orchestrator(mock_vulnerability_repository, mock_enrichment_service, mock_nvd_client,
                             mock_epss_client, mock_epss_enrichment_service):
    return EnrichmentOrchestrator(mock_vulnerability_repository, mock_enrichment_service, mock_nvd_client,
                                   mock_epss_client, mock_epss_enrichment_service)


@pytest.fixture
def nvd_enrichment_service(mock_vulnerability_repository):
    return NVDEnrichmentService(mock_vulnerability_repository)


@pytest.fixture
def epss_enrichment_service(mock_vulnerability_repository):
    return EpssEnrichmentService(mock_vulnerability_repository)
