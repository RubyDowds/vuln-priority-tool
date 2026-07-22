# scripts/setup.py
"""
First time setup - run this once to initialise the full pipeline.
After this, run ingest + enrichment + prioritisation daily.
"""
import subprocess
import sys

scripts = [
    "scripts.ingest_cisa_kev_script",
    "scripts.generate_mock_assets",
    "scripts.run_enrichment",
    "scripts.run_prioritisation",
]

for script in scripts:
    print(f"\nRunning {script}...")
    result = subprocess.run([sys.executable, "-m", script], check=True)
    print(f"Completed {script}")