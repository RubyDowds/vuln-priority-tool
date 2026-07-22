import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")
st.title("📊 Vulnerability Priority Dashboard")

# fetch all priorities
@st.cache_data(ttl=60)  # cache for 60 seconds
def fetch_priorities():
    response = requests.get(f"{API_URL}/priorities/")
    response.raise_for_status()
    return response.json()

try:
    priorities = fetch_priorities()
except requests.exceptions.RequestException as e:
    st.error(f"Could not connect to backend: {e}")
    st.stop()

# --- Summary Cards ---
immediate = [p for p in priorities if p["ssvc_decision"] == "immediate"]
out_of_cycle = [p for p in priorities if p["ssvc_decision"] == "out-of-cycle"]
scheduled = [p for p in priorities if p["ssvc_decision"] == "scheduled"]
defer = [p for p in priorities if p["ssvc_decision"] == "defer"]

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🔴 Immediate", len(immediate), help="Patch within 3 days")
with col2:
    st.metric("🟠 Out of Cycle", len(out_of_cycle), help="Patch within 14 days")
with col3:
    st.metric("🟡 Scheduled", len(scheduled), help="Patch within 60 days")
with col4:
    st.metric("🟢 Defer", len(defer), help="Next upgrade cycle")

st.divider()

# --- Filters ---
st.subheader("Prioritisation Table")

col1, col2 = st.columns(2)
with col1:
    decision_filter = st.selectbox(
        "Filter by decision",
        options=["All", "immediate", "out-of-cycle", "scheduled", "defer"]
    )
with col2:
    asset_filter = st.text_input("Filter by asset ID", placeholder="e.g. asset-0001")

# apply filters
filtered = priorities
if decision_filter != "All":
    filtered = [p for p in filtered if p["ssvc_decision"] == decision_filter]
if asset_filter:
    filtered = [p for p in filtered if asset_filter.lower() in p["asset_id"].lower()]

# --- Table ---
if filtered:
    import pandas as pd
    df = pd.DataFrame(filtered)
    df = df[[
        "asset_id", "cve_id", "ssvc_decision",
        "remediation_days", "automatable",
        "technical_impact", "reasoning"
    ]]
    df.columns = [
        "Asset", "CVE", "Decision",
        "Days", "Automatable",
        "Technical Impact", "Reasoning"
    ]
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(filtered)} of {len(priorities)} total findings")
else:
    st.info("No results match your filters.")