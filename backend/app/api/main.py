import logging
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

from app.api.routes.vulnerabilities import router as vuln_router
from app.api.routes.priorities import router as priority_router

app = FastAPI()
app.include_router(vuln_router)
app.include_router(priority_router)