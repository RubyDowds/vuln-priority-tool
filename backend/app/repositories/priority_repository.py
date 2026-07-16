"""
Persists the output of the Decision Engine into the RemediationPriority table.
"""
from sqlalchemy.dialects.sqlite import insert
from app.models.db.remediation_priority import RemediationPriority


class PriorityRepository:
    def __init__(self, session):
        self.session = session

    def upsert(self, priority_data: dict) -> None:
        stmt = insert(RemediationPriority).values(**priority_data)
        stmt = stmt.on_conflict_do_update(
            index_elements=["asset_id", "cve_id"],
            set_=priority_data,
        )
        self.session.execute(stmt)
        self.session.commit()

    def get_by_asset(self, asset_id: str) -> list[RemediationPriority]:
        return (
            self.session.query(RemediationPriority)
            .filter(RemediationPriority.asset_id == asset_id)
            .order_by(RemediationPriority.remediation_days.asc())
            .all()
        )

    def get_immediate(self) -> list[RemediationPriority]:
        return (
            self.session.query(RemediationPriority)
            .filter(RemediationPriority.ssvc_decision == "immediate")
            .all()
        )
