"""
Fetches Cisa Kev data, stores in pydantic model
"""

import requests
import logging
from models.vulnerability import VulnerabilityInfo

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

class CisaKevClient:
    def __init__(self):
        self.cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.logger = logging.getLogger(__name__)

    def extract_vulnerabilities(self):
      try:
          response = requests.get(self.cisa_url, timeout=10)
          response.raise_for_status()
          vulnerabilities = response.json()
          return vulnerabilities
      except requests.exceptions.RequestException as e:
          raise RuntimeError(f"Failed to fetch vulnerabilities from {self.cisa_url}. Error: {e}")

    def format_vulns(self):
        formatted_vulnerabilities: list[VulnerabilityInfo] = []
        kev_data = self.extract_vulnerabilities()
        vulnerabilities = kev_data["vulnerabilities"]

        for vulnerability in vulnerabilities:
            new_vulnerability = VulnerabilityInfo(
                cve_id=vulnerability["cveID"],
                vendor=vulnerability["vendorProject"],
                product=vulnerability["product"],
                vuln_name=vulnerability["vulnerabilityName"],
                description=vulnerability["shortDescription"],
                date_added=vulnerability["dateAdded"],
                cwe=vulnerability["cwes"],
            )
            formatted_vulnerabilities.append(new_vulnerability)

        # self.logger.info(formatted_vulnerabilities)
        self.logger.info(f"Number: {len(formatted_vulnerabilities)}")
        return formatted_vulnerabilities












