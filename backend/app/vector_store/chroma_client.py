# Keep simple, just initialise the ChromaDB client and get the collection

import chromadb

client = chromadb.PersistentClient(path="./chroma_db") # persists to disk like your kev.db

def get_collection():
    return client.get_or_create_collection(
        name="vulnerabilities",
        metadata={"hnsw:space": "cosine"}  # cosine similarity for text embeddings
    )
