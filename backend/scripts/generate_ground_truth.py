from app.db.database import SessionLocal
from app.repositories.vulnerability_repository import VulnerabilityRepository



if __name__ == "__main__":
    session = SessionLocal()
    repo = VulnerabilityRepository(session)
    recent = repo.search(days=30)
    for v in recent:
        print(f"{v.cve_id} | {v.vendor} | {v.vuln_name} | {v.date_added.strftime('%Y-%m-%d')}")