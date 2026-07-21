import random
from faker import Faker
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.asset_repository import AssetRepository


fake = Faker()

ASSET_TYPES = ["server", "workstation", "cloud_instance", "container", "network_device"]
CRITICALITY_LEVELS = ["critical", "high", "medium", "low"]
class MockAssetGenerator:

    def __init__(self, vuln_repository: VulnerabilityRepository, asset_repository: AssetRepository):
        self.vuln_repository = vuln_repository
        self.asset_repository = asset_repository


    def generate_assets(self, count: int = 50) -> list[dict]:
        assets = []
        for i in range(count):
            asset = {
                "asset_id": f"asset-{i + 1:04d}",
                "hostname": fake.hostname(),
                "ip_address": fake.ipv4_private(),
                "internet_facing": random.choice([True, False, False]),  # weighted ~33% exposed
                "asset_type": random.choice(ASSET_TYPES),
                "business_criticality": random.choices(
                    CRITICALITY_LEVELS, weights=[10, 25, 40, 25]
                )[0],
                "owner": fake.name(),
            }
            assets.append(asset)
        return assets

    def generate_scan_results(self, assets: list[dict], max_cves_per_asset: int = 5) -> list[dict]:
        all_vulns = self.vuln_repository.get_all()
        scan_results = []

        for asset in assets:
            num_cves = random.randint(0, max_cves_per_asset)
            assigned_cves = random.sample(all_vulns, min(num_cves, len(all_vulns)))

            for vuln in assigned_cves:
                scan_results.append({
                    "asset_id": asset["asset_id"],
                    "cve_id": vuln.cve_id,
                    "detected_date": fake.date_time_between(start_date="-90d", end_date="now"),
                })

        return scan_results

    def run(self, asset_count: int = 50):
        assets = self.generate_assets(asset_count)
        scan_results = self.generate_scan_results(assets)

        self.asset_repository.upsert_all(assets)
        self.asset_repository.insert_scan_results(scan_results)

        print(f"Generated {len(assets)} assets and {len(scan_results)} scan results")



