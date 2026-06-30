import os

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(page_title="AI SOC Agent", layout="wide")
st.title("AI Cybersecurity SOC Agent")

with st.sidebar:
    st.header("Ingest Event")
    source = st.text_input("Source", "auth.log")
    host = st.text_input("Host", "web-01")
    username = st.text_input("Username", "admin")
    src_ip = st.text_input("Source IP", "185.220.101.1")
    event_type = st.selectbox("Event Type", ["login_failed", "privilege_escalation", "malware", "data_exfiltration"])
    severity = st.selectbox("Severity", ["low", "medium", "high", "critical"], index=1)
    message = st.text_area("Message", "Failed password for admin from 185.220.101.1 port 4444 ssh2")

    if st.button("Analyze Event", type="primary"):
        payload = {
            "source": source,
            "host": host,
            "username": username or None,
            "src_ip": src_ip or None,
            "event_type": event_type,
            "severity": severity,
            "message": message,
        }
        response = requests.post(f"{API_BASE_URL}/events", json=payload, timeout=30)
        response.raise_for_status()
        st.session_state["last_result"] = response.json()

if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    st.subheader("Latest Analysis")
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk Score", f"{result['event']['risk_score']:.0f}/100")
    c2.metric("Host", result["event"]["host"])
    c3.metric("Incident", "Created" if result["incident"] else "Not created")

    if result["incident"]:
        st.markdown(result["incident"]["summary"])
        st.markdown("### Recommended Actions")
        st.markdown(result["incident"]["recommended_actions"])

tab_events, tab_incidents = st.tabs(["Events", "Incidents"])

with tab_events:
    events = requests.get(f"{API_BASE_URL}/events", timeout=30).json()
    st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)

with tab_incidents:
    incidents = requests.get(f"{API_BASE_URL}/incidents", timeout=30).json()
    st.dataframe(pd.DataFrame(incidents), use_container_width=True, hide_index=True)
    incident_id = st.number_input("Incident report ID", min_value=1, step=1)
    if st.button("Load Report"):
        report = requests.get(f"{API_BASE_URL}/incidents/{incident_id}/report", timeout=30).json()["report"]
        st.markdown(report)
