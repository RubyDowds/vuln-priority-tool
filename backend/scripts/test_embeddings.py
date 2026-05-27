import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.db.database import SessionLocal
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.ingestion.vulnerability_embedding_service import VulnerabilityEmbeddingService
from app.vector_store.chroma_client import get_collection
from sentence_transformers import SentenceTransformer

# 1. embed all vulns from sqlite into chromadb
session = SessionLocal()
repo = VulnerabilityRepository(session)
embedding_service = VulnerabilityEmbeddingService(repo)
embedding_service.embed_all_vulnerabilities()
print("Embedding complete")

# 2. query it
model = SentenceTransformer("all-MiniLM-L6-v2")
collection = get_collection()

question = "are there any samsung vulnerabilities?"
question_embedding = model.encode(question).tolist()

results = collection.query(
    query_embeddings=[question_embedding],
    n_results=3
)

for doc, distance, meta in zip(
    results["documents"][0],
    results["distances"][0],
    results["metadatas"][0]
):
    print(f"\nScore: {distance:.4f}")
    print(f"CVE: {meta['cve_id']}")
    print(f"Vendor: {meta['vendor']}")
    print(f"Match: {doc[:100]}...")
    