import os

import httpx
import streamlit as st

API = os.getenv("SENTINEL_URL", "http://127.0.0.1:9000").rstrip("/")
ADMIN_TOKEN = os.getenv("SENTINEL_ADMIN_TOKEN", "")

st.set_page_config(page_title="Campus Sentinel", layout="wide")
st.title("Campus Sentinel")
st.caption("Rule-based protection for the fictional Results and Library portals.")

if st.button("Refresh dashboard"):
    st.rerun()

try:
    with httpx.Client(
        timeout=4.0,
        headers={"X-Admin-Token": ADMIN_TOKEN},
    ) as client:
        alerts = client.get(f"{API}/alerts").raise_for_status()
        blocked = client.get(f"{API}/blocked").raise_for_status()
        pending = client.get(f"{API}/pending").raise_for_status()
    left, middle, right = st.columns(3)
    left.metric("Alerts", len(alerts.json()))
    middle.metric("Blocked IPs", len(blocked.json()))
    right.metric("Pending approvals", len(pending.json()))

    st.subheader("Recent alerts")
    st.dataframe(alerts.json(), use_container_width=True, hide_index=True)

    st.subheader("Blocked addresses")
    for item in blocked.json():
        st.write(f"{item['ip']} · until {item['until'] or 'permanent'} · {item['reason']}")
        if st.button("Unblock", key=f"unblock-{item['ip']}"):
            client.post(f"{API}/unblock", json={"ip": item["ip"]}).raise_for_status()
            st.rerun()

    st.subheader("Human approval")
    for item in pending.json():
        st.write(f"#{item['id']} · {item['action']} · {item['ip']} · {item['reason']}")
        if st.button("Approve permanent block", key=f"approve-{item['id']}"):
            client.post(f"{API}/approve/{item['id']}").raise_for_status()
            st.rerun()
except httpx.HTTPError as exc:
    st.error(f"Sentinel API unavailable: {exc}")
