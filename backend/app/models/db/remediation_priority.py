from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey

from app.db.database import Base
from datetime import datetime


class RemediationPriority(Base):
    __tablename__ = "remediation_priority"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(String, ForeignKey("assets.asset_id"))
    cve_id = Column(String, ForeignKey("vulnerabilities.cve_id"))

    # SSVC decision output
    ssvc_decision = Column(String)  # "immediate", "out-of-cycle", "scheduled", "defer"
    remediation_days = Column(Integer, nullable=True)  # 3, 14, 60, None

    # the four factors used to make the decision - stored for explainability
    publicly_exposed = Column(Boolean)
    in_kev = Column(Boolean)
    automatable = Column(Boolean)
    technical_impact = Column(String)

    # AI explanation
    reasoning = Column(String)
    calculated_at = Column(DateTime, default=datetime.utcnow)