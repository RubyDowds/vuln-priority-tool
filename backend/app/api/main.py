from fastapi import FastAPI
from app.api.routes.vulnerabilities import router
from app.db.database import Base, engine

app = FastAPI()
app.include_router(router)

@app.on_event("startup")
def start_up():
    Base.metadata.create_all(bind=engine)