"""
NVD Enrichment service parses the raw NVD response and enriches the Cisa KEV data
with CVSS, SSVC from NVD where available
"""
import logging
from datetime import datetime
from app.repositories.vulnerability_repository import VulnerabilityRepository


class NVDEnrichmentService:
    def __init__(self, repository: VulnerabilityRepository):
        self.repository = repository
        self.logger = logging.getLogger(__name__)

    def enrich(self, nvd_cves: list[dict]) -> None:
        for cve_data in nvd_cves:
            cve_id: str | None = cve_data.get("id")

            if not cve_id:
                self.logger.warning(f"CVE ID not found, skipping")
                continue

            vuln = self.repository.get_by_cve_id(cve_id)
            if not vuln:
                self.logger.info(f"{cve_id} not found in local DB, skipping")
                continue

            enriched = self._parse_nvd(cve_data)
            self._update(vuln, enriched)
            self._derive_missing_ssvc(vuln)


    def _parse_nvd(self, cve_data: dict) -> dict:
        """
        Parse the raw NVD response
        :param cve_data: Raw NVD response for CVE ID
        :return: Dictionary of parsed CVE data including CVSS vector and SSVC information
        """
        metrics = cve_data.get("metrics", {})
        return {
            **self._extract_cvss(metrics),
            **self._extract_ssvc(metrics),
            "enrichment_attempted_at": datetime.utcnow(),
        }

    def _extract_cvss(self, metrics: dict) -> dict | None:
        """
        Extract the CVSS V3 information - we want the primary (NVD scored) vector where possible, but
        fall-back to using the secondary if primary is not present. For instance, from April 2026 NVD
        will no longer routinely provide their own score when the CNA has already scored it.
        :param metrics: CVSS metrics from NVD
        :return: Dictionary of CVSS data, used for the prioritisation decision tree downstream.
        """
        # Try CVSS V31 & primary first
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]:
            cvss_list = metrics.get(version_key, [])
            for metric in cvss_list:
                if metric.get("type") == "Primary":
                    return self._parse_cvss(metric["cvssData"])

        # Fallback to secondary when necessary
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]:
            cvss_list = metrics.get(version_key, [])
            for metric in cvss_list:
                if metric.get("type") == "Secondary":
                    return self._parse_cvss(metric["cvssData"])


        return {"base_score": None, "cvss_vector": None, "cvss_severity": None}

    @staticmethod
    def _parse_cvss(cvss_metrics: dict) -> dict | None:
        return {
            "base_score": cvss_metrics.get("baseScore"),
            "cvss_vector": cvss_metrics.get("vectorString"),
            "cvss_severity": cvss_metrics.get("baseSeverity"),
        }

    def _extract_ssvc(self, metrics: dict) -> dict | None:
        """
        Extract SSVC information i.e., exploitation, automatable, technical_impact, ssvc_source.
        These metrics have been recently added to the NVD response within options field,
        SSVC is very important for prioritisation following BOD-26-04.
        :param metrics: CVE Metrics from NVD
        :return: Dictionary of SSVC data, used for the prioritisation decision tree downstream.
        """
        ssvc_list = metrics.get("ssvcV203", [])
        if not ssvc_list:
            self.logger.warning("No ssvc metrics found, returning default None for values")
            return {"exploitation": None, "automatable": None, "technical_impact": None, "ssvc_source": None}

        options = ssvc_list[0].get("ssvcData").get("options", [])
        ssvc = {list(o.keys())[0]: list(o.values())[0] for o in options}

        return {
            "exploitation": ssvc.get("exploitation"),
            "automatable": ssvc.get("automatable"),
            "technical_impact": ssvc.get("technicalImpact"),
            "ssvc_source": "cisa",
        }

    @staticmethod
    def _determine_status(has_cvss: bool, has_ssvc: bool) -> str:
        """
        Determines enrichment status of vulnerability by checking if cvss &/or ssvc is present.
        Returns the status which will be used to determine if we should keep trying to enrich the CVE.
        """
        if has_cvss and has_ssvc:
            return "enriched"
        if has_cvss and not has_ssvc:
            return "cvss_only"
        if has_ssvc and not has_cvss:
            return "ssvc_only"
        else:
            return "not_enriched"

    def _update(self, vuln, enriched: dict) -> None:
        """
        Takes the vuln SQLAlchemy object (fetched from the DB) and the enriched dict (parsed from
        NVD response), checks whether the fields have been enriched (ie if cvss/ssvc is present).
        Updates the SQLAlchemy object in memory with the enriched values, also setting the enriched
        status on the object in memory too.
        Finally, persists the updated object in memory to SQLite/
        :param vuln: Stored Vulnerability object from SQLAlchemy
        :param enriched: Enrichment dictionary from NVD
        """
        has_cvss = enriched.get("cvssVector") is not None
        has_ssvc = enriched.get("automatable") is not None

        vuln.base_score = enriched.get("base_score")
        vuln.cvss_vector = enriched.get("cvss_vector")
        vuln.cvss_severity = enriched.get("cvss_severity")
        vuln.automatable = enriched.get("automatable")
        vuln.technical_impact = enriched.get("technical_impact")
        vuln.exploitation = enriched.get("exploitation")
        vuln.ssvc_source = enriched.get("ssvc_source")
        vuln.enrichment_status = self._determine_status(has_cvss, has_ssvc)
        vuln.enrichment_attempted_at = enriched.get("enrichment_attempted_at")

        self.repository.save(vuln)

    def _derive_missing_ssvc(self, vuln) -> None:
        if vuln.technical_impact is not None:
            return  # already set from NVD, nothing to do

        if not vuln.cvss_vector:
            return  # no vector to derive from

        vuln.technical_impact = self._derive_technical_impact_from_cvss(vuln.cvss_vector)

        if vuln.ssvc_source is None:
            vuln.ssvc_source = "cvss_derived"

        self.repository.save(vuln)

    @staticmethod
    def _derive_technical_impact_from_cvss(cvss_vector: str) -> str | None:
        if not cvss_vector:
            return None
        # C:H/I:H/A:H in the vector = total impact
        if "C:H" in cvss_vector and "I:H" in cvss_vector:
            return "total"
        return "partial"

