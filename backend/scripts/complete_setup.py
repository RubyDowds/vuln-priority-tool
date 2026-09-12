"""
First time setup - run this once to initialise the full pipeline.
After this, run ingest + enrichment + prioritisation + embedding daily.
"""
from scripts.ingest_cisa_kev import main as ingest_cisa_kev
from scripts.generate_mock_assets import main as generate_mock_assets
from scripts.run_enrichment import main as run_enrichment
from scripts.run_prioritisation import main as run_prioritisation
from scripts.embed_priorities import main as embed_priorities

steps = [
    ("Ingesting CISA KEV data", ingest_cisa_kev),
    ("Generating mock assets", generate_mock_assets),
    ("Running enrichment", run_enrichment),
    ("Running prioritisation", run_prioritisation),
    ("Embedding priorities", embed_priorities),
]

if __name__ == "__main__":
    for label, step in steps:
        print(f"\n{label}...")
        step()
        print(f"Completed: {label}")