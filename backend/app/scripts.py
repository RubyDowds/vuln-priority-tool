from db.database import engine, Base
from db.database import SessionLocal
# noqa: F401
from models.db.vulnerability import Vulnerability  # IMPORTANT: ensures model is registered
from ingestion.vulnerability_ingestion_service import VulnerabilityIngestionService


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        service = VulnerabilityIngestionService(session)
        service.ingest_cisa_kev()
    finally:
        session.close()
