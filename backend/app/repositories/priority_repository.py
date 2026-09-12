"""
Queries RemediationPriority table which holds output of SSVC decision engine
(asset_id, cve_id) pairing, plus a decision (immediate, defer etc),
remediation timeline, technical impact rating.
The actual asset-specific prioritisation which the app depends on.
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

    def get_all(self) -> list[RemediationPriority]:
        return (
            self.session.query(RemediationPriority)
            .order_by(RemediationPriority.remediation_days.asc())
            .all()
        )

    def get_by_cve_id(self, cve_id: str) -> list[RemediationPriority]:
        return (
            self.session.query(RemediationPriority)
            .filter(RemediationPriority.cve_id == cve_id)
            .all()
        )
