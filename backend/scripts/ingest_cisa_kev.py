# main script to run db initialisation/update. Eventually will be a periodic script to update DB every eg day

from app.db.database import SessionLocal, Base, engine
from app.ingestion.vulnerability_ingestion_service import VulnerabilityIngestionService

if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        service = VulnerabilityIngestionService(session)
        service.ingest_cisa_kev()
        print("Ingestion complete")
    finally:
        session.close()