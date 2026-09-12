from app.db.database import SessionLocal
from app.repositories.vulnerability_repository import VulnerabilityRepository



if __name__ == "__main__":
    session = SessionLocal()
    repo = VulnerabilityRepository(session)
    recent = repo.search(days=30)
