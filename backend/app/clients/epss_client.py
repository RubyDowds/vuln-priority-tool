"""
Fetches EPSS data for each CVE, used downstream in vulnerability model for exploit prediction.
"""
import logging
import requests


class EpssClient:
    BASE_BATCH_URL = "https://api.first.org/data/v1/epss"
    LIMIT = 200

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _fetch_batch(self, cve_ids: list[str]) -> list[dict]:
        params = {"cve": ",".join(cve_ids)}
        try:
            response = requests.get(
                EpssClient.BASE_BATCH_URL,
                params=params,
                timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])  
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"Failed to fetch batch: {err}")
            return []

    def fetch_all(self, cve_ids: list) -> list[dict]:
        results = []
        total = len(cve_ids)
        batches = [
            cve_ids[i:i + self.LIMIT]
            for i in range(0, total, self.LIMIT)
        ]

        for i, batch in enumerate(batches):
            self.logger.info(f"Fetching batch {i+1}/{len(batches)} ({len(batch)} CVEs)")
            results.extend(self._fetch_batch(batch))

        return results
