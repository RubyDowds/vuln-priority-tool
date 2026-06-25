from sqlalchemy import Column, String, Boolean
from app.db.database import Base

class Asset(Base):
    __tablename__ = "assets"
    asset_id = Column(String, primary_key=True)
    hostname = Column(String)
    ip_address = Column(String)
    internet_facing = Column(Boolean)
    asset_type = Column(String)
    business_criticality = Column(String)
    owner = Column(String)