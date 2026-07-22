import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(page_title="Vuln Prioritisation", page_icon="🛡️", layout="wide")
st.title("🛡️ Vulnerability Prioritisation Tool")
st.caption("Ask questions about your vulnerability data and remediation priorities")

# initialise chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# chat input
if prompt := st.chat_input("Ask about your vulnerabilities..."):
    # add user message to history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # call your FastAPI backend 
    with st.chat_message("assistant"):
        with st.spinner("Analysing..."):
            try:
                response = requests.post(
                    f"{API_URL}/priorities/analyse",
                    json={"question": prompt},
                    timeout=60
                )
                response.raise_for_status()
                answer = response.json()["answer"]
            except requests.exceptions.RequestException as e:
                answer = f"Error connecting to backend: {e}"

        st.markdown(answer)
        st.session_state.messages.append({"role": "assistant", "content": answer})