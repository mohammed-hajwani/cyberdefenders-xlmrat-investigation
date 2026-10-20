"""Streamlit incident dashboard for the XLMRat / AsyncRAT investigation.

Reads ONLY the benign exported tables in ../data/processed and the figures in
../visualizations. No malware bytes are touched.

    streamlit run dashboard/app.py
"""
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
VIS = ROOT / "visualizations"

st.set_page_config(page_title="XLMRat Incident Dashboard", layout="wide")

packets = pd.read_csv(PROC / "packets.csv", parse_dates=["time_utc"])
http = pd.read_csv(PROC / "http.csv")
dns = pd.read_csv(PROC / "dns.csv")

ATTACKER, VICTIM = "45.126.209.4", "10.1.9.101"
c2 = packets[(packets.dport == 8808) | (packets.sport == 8808)]

st.title("🛡️ Cybersecurity Incident Dashboard — CyberDefenders XLMRat")
st.caption("Multi-stage AsyncRAT delivery · Evidence: 236-XLMRat.pcap")

col = st.columns(4)
col[0].metric("Incident", "CONFIRMED")
col[1].metric("Severity", "HIGH")
col[2].metric("Suspicious IPs", "1", help=ATTACKER)
col[3].metric("Hosts affected", "1", help=VICTIM)

k = st.columns(4)
k[0].metric("Total packets", f"{len(packets):,}")
k[1].metric("C2 packets (8808)", f"{len(c2):,}")
k[2].metric("HTTP downloads", int((http.kind == "request").sum()))
k[3].metric("Capture (s)", round(packets.rel_time.max(), 0))

st.subheader("Key indicators (IOCs)")
st.table(pd.DataFrame({
    "Indicator": ["45.126.209.4", "madmrx.duckdns.org", "ports 222 / 8808",
                  "1eb7b02e…81d798", "C:\\Users\\Public\\Conted.{ps1,bat,vbs}",
                  "RegSvcs.exe"],
    "Meaning": ["Staging + C2 (ReliableSite.Net LLC)", "DuckDNS C2 hostname",
                "HTTP staging / AsyncRAT C2", "AsyncRAT SHA256", "Dropped files",
                "LOLBin injection target"],
}))

left, right = st.columns(2)
with left:
    st.subheader("Activity over time")
    if (VIS / "timeline.png").exists():
        st.image(str(VIS / "timeline.png"))
    st.subheader("Destination ports")
    if (VIS / "ports.png").exists():
        st.image(str(VIS / "ports.png"))
with right:
    st.subheader("HTTP delivery stages")
    st.dataframe(http[http.kind == "request"][["rel_time", "method", "uri", "dport"]],
                 use_container_width=True)
    st.subheader("DNS")
    st.dataframe(dns[["time_utc", "src", "qname"]], use_container_width=True)

st.subheader("Answers to the 7 lab questions")
st.table(pd.DataFrame({
    "#": list(range(1, 8)),
    "Answer": [
        "http://45.126.209.4:222/xlm.txt", "ReliableSite.Net LLC",
        "1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798",
        "Backdoor:MSIL/AsyncRat.A2786761 (AsyncRAT)", "2023-10-30 15:08",
        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe",
        "Conted.ps1, Conted.bat, Conted.vbs",
    ],
}))
