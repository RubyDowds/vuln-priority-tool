from app.db.database import SessionLocal, Base, engine
from app.ingestion.mock_asset_generator import MockAssetGenerator
from app.repositories.asset_repository import AssetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        vuln_repo = VulnerabilityRepository(session)
        asset_repo = AssetRepository(session)
        generator = MockAssetGenerator(vuln_repo, asset_repo)
        generator.run(asset_count=50)
    finally:
        session.close()
