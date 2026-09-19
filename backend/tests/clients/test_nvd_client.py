from unittest.mock import MagicMock

import httpx
import pytest

from app.clients.nvd_client import NVDClient


@pytest.fixture
def client():
    return NVDClient(api_key="test-api-key")


def _fake_response(json_data):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = json_data
    return response


def test_fetch_batch_happy_path_returns_cve_list(client, mocker):
    mocker.patch("app.clients.nvd_client.httpx.get",
                 return_value=_fake_response({"vulnerabilities": [{"cve": {"id": "CVE-1"}}]}))

    result = client._fetch_batch(["CVE-1"])

    assert result == [{"id": "CVE-1"}]


def test_get_headers_includes_api_key():
    client = NVDClient(api_key="abc123")

    assert client._get_headers() == {"apiKey": "abc123"}


def test_fetch_batch_http_error_returns_empty_list_no_raise(client, mocker):
    mocker.patch("app.clients.nvd_client.httpx.get", side_effect=httpx.HTTPError("boom"))

    result = client._fetch_batch(["CVE-1"])

    assert result == []


def test_fetch_all_single_batch_under_100_ids(client, mocker):
    mock_get = mocker.patch("app.clients.nvd_client.httpx.get", return_value=_fake_response({"vulnerabilities": []}))
    mock_sleep = mocker.patch("app.clients.nvd_client.time.sleep")

    client.fetch_all([f"CVE-{i}" for i in range(5)])

    assert mock_get.call_count == 1
    assert mock_sleep.call_count == 1


def test_fetch_all_chunks_across_multiple_batches(client, mocker):
    mock_get = mocker.patch("app.clients.nvd_client.httpx.get", return_value=_fake_response({"vulnerabilities": []}))
    mock_sleep = mocker.patch("app.clients.nvd_client.time.sleep")

    cve_ids = [f"CVE-{i}" for i in range(250)]
    client.fetch_all(cve_ids)

    assert mock_get.call_count == 3
    assert mock_sleep.call_count == 3
    call_params = [c.kwargs["params"]["cveIds"] for c in mock_get.call_args_list]
    assert call_params[0] == ",".join(cve_ids[0:100])
    assert call_params[1] == ",".join(cve_ids[100:200])
    assert call_params[2] == ",".join(cve_ids[200:250])
