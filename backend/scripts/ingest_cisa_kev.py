# main script to run db initialisation/update. Eventually will be a periodic script to update DB every eg day

import logging

from app.db.database import SessionLocal, Base, engine
from app.ingestion.vulnerability_ingestion_service import VulnerabilityIngestionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        service = VulnerabilityIngestionService(session)
        service.ingest_cisa_kev()
        logger.info("Ingestion complete")
    finally:
        session.close()

if __name__ == "__main__":
   main()