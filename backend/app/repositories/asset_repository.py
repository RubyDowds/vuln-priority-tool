"""
Separation of persistent logic lives in the repository to persist the DB.
Should only know about the DB and nothing else, includes simple retrieval logic.
"""

from sqlalchemy.dialects.sqlite import insert
from app.models.db.asset import Asset
from app.models.db.asset_vulnerability import AssetVulnerability


class AssetRepository:
    def __init__(self, session):
        self.session = session

    def upsert_all(self, assets):
        for asset in assets:
            stmt = insert(Asset).values(
                asset_id=asset['asset_id'],
                hostname=asset['hostname'],
                ip_address=asset['ip_address'],
                internet_facing=asset['internet_facing'],
                asset_type=asset['asset_type'],
                business_criticality=asset['business_criticality'],
                owner=asset['owner'],
            )

            stmt.on_conflict_do_update(
                index_elements=['asset_id'],
                set_={
                    'hostname': asset['hostname'],
                    'ip_address': asset['ip_address'],
                    'internet_facing': asset['internet_facing'],
                    'asset_type': asset['asset_type'],
                    'business_criticality': asset['business_criticality'],
                    'owner': asset['owner'],
                }
            )
            self.session.execute(stmt)

        self.session.commit()


    def insert_scan_results(self, scan_results):
        """
        Method to insert scan results into DB - uses plain insert rather than upsert, as scan results
        are typically append-only (a new scan finding the same CVE on the same is a new detection event).
        So no replacing duplicates, like the upsert method.
        """
        for result in scan_results:
            stmt = insert(AssetVulnerability).values(
                asset_id=result['asset_id'],
                cve_id=result['cve_id'],
                detected_date=result['detected_date'],
                remediated=result.get('remediated', False),
            )
            self.session.execute(stmt)

        self.session.commit()

    def get_by_id(self, asset_id: str):
        return self.session.query(Asset).filter(Asset.asset_id == asset_id).first()

    # def get_vulnerabilities_for_asset(self, asset_id: str) -> list[AssetVulnerability]:
    #     return (
    #         self.session.query(AssetVulnerability)
    #         .filter(AssetVulnerability.asset_id == asset_id)
    #         .all()
    #     )

    # def get_assets_for_vulnerabilities(self, cve_id: str) -> list[AssetVulnerability]:
    #     return (
    #         self.session.query(AssetVulnerability)
    #         .filter(AssetVulnerability.cve_id == cve_id)
    #         .all()
    #     )

    def get_all_asset_vulnerabilities(self):
        return self.session.query(AssetVulnerability).all()