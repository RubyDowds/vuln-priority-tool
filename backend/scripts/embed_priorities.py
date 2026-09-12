"""
Embeds all remediation priority records into ChromaDB, enabling semantic
search over prioritisation decisions (search_priorities tool).

Must be run after prioritisation, since it reads from RemediationPriority -
re-run whenever priority data changes, to keep embeddings in sync.
"""
import logging

from app.db.database import SessionLocal, Base, engine
from app.repositories.priority_repository import PriorityRepository
from app.embeddings.priority_embedding_service import PriorityEmbeddingService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        repository = PriorityRepository(session)
        embedding_service = PriorityEmbeddingService(repository)
        embedding_service.embed_all_priorities()
        logger.info("Priority embeddings complete.")
    finally:
        session.close()


if __name__ == "__main__":
    main()