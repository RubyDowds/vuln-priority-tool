from unittest.mock import MagicMock

import requests

from app.clients.epss_client import EpssClient


def _fake_response(json_data):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = json_data
    return response


def test_fetch_batch_happy_path_returns_data_list(mocker):
    mocker.patch("app.clients.epss_client.requests.get",
                 return_value=_fake_response({"data": [{"cve": "CVE-1", "epss": 0.5, "percentile": 0.9}]}))

    result = EpssClient()._fetch_batch(["CVE-1"])

    assert result == [{"cve": "CVE-1", "epss": 0.5, "percentile": 0.9}]


def test_fetch_batch_http_error_returns_empty_list_no_raise(mocker):
    mocker.patch("app.clients.epss_client.requests.get", side_effect=requests.exceptions.HTTPError("boom"))

    result = EpssClient()._fetch_batch(["CVE-1"])

    assert result == []


def test_fetch_all_single_batch_under_200_ids(mocker):
    mock_get = mocker.patch("app.clients.epss_client.requests.get", return_value=_fake_response({"data": []}))

    EpssClient().fetch_all([f"CVE-{i}" for i in range(50)])

    assert mock_get.call_count == 1


def test_fetch_all_chunks_across_multiple_batches(mocker):
    mock_get = mocker.patch("app.clients.epss_client.requests.get", return_value=_fake_response({"data": []}))

    cve_ids = [f"CVE-{i}" for i in range(450)]
    EpssClient().fetch_all(cve_ids)

    assert mock_get.call_count == 3
    call_params = [c.kwargs["params"]["cve"] for c in mock_get.call_args_list]
    assert call_params[0] == ",".join(cve_ids[0:200])
    assert call_params[1] == ",".join(cve_ids[200:400])
    assert call_params[2] == ",".join(cve_ids[400:450])
