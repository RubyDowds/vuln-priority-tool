from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./kev.db"

# Creates DB connection layer
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}, # required for SQLite + threads
)

# Base is the declarative foundation that SQLAlchemy uses to know how to map Python classes to DB tables
# Define once in database.py and reuse everywhere
Base = declarative_base()

# Creates sessions from the DB connection layer engine
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)