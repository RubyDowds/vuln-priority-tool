"""
Fetches raw NVD data for each Cisa KEV CVE, stores in pydantic model for later enrichment.
"""
import logging
import time

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    BATCH_SIZE = 100
    RATE_LIMIT_DELAY = 0.1 # with API key

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)

    def _get_headers(self):
        return {"apiKey": self.api_key}

    def _fetch_batch(self, cve_ids: list[str])-> list[dict]:
        params = {"cveIds": ",".join(cve_ids)}
        try:
            response = httpx.get(
                self.BASE_URL,
                params=params,
                headers=self._get_headers(),
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            return [item["cve"] for item in data.get("vulnerabilities", [])]
        except httpx.HTTPError as err:
            self.logger.error(f"Failed to fetch batch: {err}")
            return []

    def fetch_all(self, cve_ids: list) -> list[dict]:
        results = []
        total = len(cve_ids)
        batches = [
            cve_ids[i:i + self.BATCH_SIZE]
            for i in range(0, total, self.BATCH_SIZE)
        ]

        for i, batch in enumerate(batches):
            self.logger.info(f"Fetching batch {i+1}/{len(batches)} ({len(batch)} CVEs)")
            results.extend(self._fetch_batch(batch))
            time.sleep(self.RATE_LIMIT_DELAY)

        return results
