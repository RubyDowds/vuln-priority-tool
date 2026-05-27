# Keep simple, just initialise the ChromaDB client and get the collection

import chromadb

client = chromadb.PersistentClient(path="./chroma_db") # persists to disk like your kev.db

# later i'll have an embedding service that uses this collection. But need to get the client set up first
# and try to manually add a couple of descriptors and querying them before building the service
def get_collection():
    return client.get_or_create_collection(
        name="vulnerabilities",
        metadata={"hnsw:space": "cosine"}  # cosine similarity for text embeddings
    )


def add_to_collection():
    descriptions = [
        "Microsoft Windows Shell contains a protection mechanism failure vulnerability that allows an unauthorized attacker to perform spoofing over a network.",
        "Samsung MagicINFO 9 Server contains a path traversal vulnerability that could allow an attacker to write arbitrary files as system authority."]

    collection = get_collection()
    # ChromaDB uses its own default embedding model to convert the text to vectors
    # and when querying, it embeds question by the same way and finds the closest vectors
    # by cosign similarity
    collection.add(
        documents=descriptions,
        ids=["vuln_0", "vuln_1"],  # meaningful IDs, later these will be your CVE IDs
        metadatas=[
            {"vendor": "microsoft", "cve_id": "CVE-2025-XXXX"},
            {"vendor": "samsung", "cve_id": "CVE-2025-YYYY"}
        ]
    )

    results = collection.query(
        query_texts=["Tell me about the Microsoft vulnerabilities"],
        n_results=1  # Number of results to return (ie the closest match if 1)
    )

    for doc, distance, meta in zip(
            results["documents"][0],
            results["distances"][0], # distance is similarity, lower means more similar
            results["metadatas"][0]
    ):
        print(f"Score: {distance:.4f}")
        print(f"CVE: {meta['cve_id']}")
        print(f"Match: {doc}\n")


if __name__ == "__main__":
    add_to_collection()