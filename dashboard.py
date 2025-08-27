import streamlit as st

# Has to be the first Streamlit call
st.set_page_config(page_title="Anomalyze.io Dashboard", layout="centered")

import pandas as pd
import altair as alt
from streamlit_autorefresh import st_autorefresh
import os

# Auto-refresh every 10s
st_autorefresh(interval=10000, limit=None, key="refresh_dashboard")

st.title("📡 Anomalyze.io: AI-Powered Network Threat Dashboard")
st.caption("Self-learning real-time packet analysis and anomaly detection")

# Define the columns
columns = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_len", "timestamp_unix", "total_bytes", "score", "anomaly"
]

if not os.path.exists("anomaly_log.csv"):
    st.warning("⚠️ No anomaly data found. Waiting for agent to log packets...")
    st.stop()

try:
    df = pd.read_csv("anomaly_log.csv", names=columns, header=None)
except Exception as e:
    st.error(f"Failed to load log: {e}")
    st.stop()

# Filters - Sidebar
st.sidebar.header("🔍 Filter Anomalies")
srcs = st.sidebar.multiselect("Source IP", df["src_ip"].unique(), default=df["src_ip"].unique())
dsts = st.sidebar.multiselect("Destination IP", df["dst_ip"].unique(), default=df["dst_ip"].unique())

filtered_df = df[df["src_ip"].isin(srcs) & df["dst_ip"].isin(dsts)]

st.subheader("📋 Detected Anomalies")
st.dataframe(filtered_df)

# Convert the timestamps and then sort
try:
    filtered_df["timestamp"] = pd.to_datetime(filtered_df["timestamp"], errors="coerce")
    filtered_df = filtered_df.dropna(subset=["timestamp"]).set_index("timestamp").sort_index()

    st.subheader("📈 Packet Length Over Time")
    st.line_chart(filtered_df["packet_len"])
except Exception as e:
    st.error(f"Could not plot time series: {e}")

# Packet sum by IP - BAR CHART
st.subheader("📊 Total Packet Size by Source IP")
try:
    bar_data = filtered_df.groupby("src_ip")["packet_len"].sum().reset_index()
    bar = alt.Chart(bar_data).mark_bar().encode(
        x=alt.X("src_ip", sort="-y"),
        y="packet_len",
        tooltip=["src_ip", "packet_len"]
    ).properties(height=400)
    st.altair_chart(bar, use_container_width=True)
except:
    st.warning("Not enough data for bar chart.")

# Alerts
st.subheader("🚨 High Packet Alerts (> 500 bytes)")
try:
    alerts = filtered_df[filtered_df["packet_len"] > 500]
    if not alerts.empty:
        st.warning(f"{len(alerts)} high-packet anomalies found!")
        st.dataframe(alerts)
    else:
        st.success("No high packet anomalies detected.")
except:
    st.info("Packet data not available.")
