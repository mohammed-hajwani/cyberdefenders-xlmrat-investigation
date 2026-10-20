# Tools & Techniques Used

Each tool had a specific investigative purpose (no tool-count padding).

| Tool | Purpose in this investigation |
|---|---|
| **Wireshark** | Manual review of the pcap: Protocol Hierarchy, Conversations, Follow TCP Stream for the two HTTP objects, and inspecting the port-8808 C2 channel. |
| **scapy** (Python) | Scriptable, admin-free pcap parsing used for the whole automated pipeline — triage, in-memory HTTP reassembly, CSV export. Pure-Python fallback where `tshark` was unavailable. |
| **tshark** | Named in the brief as the CLI companion to Wireshark; equivalent field extraction is reproduced here via scapy → `data/processed/*.csv`. |
| **CyberChef** | Deobfuscating the VBScript array and the `#`-padded PowerShell strings; verifying the underscore-hex → PE conversion. |
| **PowerShell (read-only)** | Understanding (not executing) the stage-2 script logic; checking Defender detections (`Get-MpThreatDetection`). |
| **VirusTotal** | Classifying the reconstructed AsyncRAT client hash and reading the Alibaba label. |
| **Python / pandas / NumPy** | Structured analysis of the exported tables (flows, HTTP, DNS) in the notebooks. |
| **matplotlib** | Incident visualizations (timeline, protocol/port mix, C2 volume). |
| **Streamlit** (optional) | Interactive incident dashboard (`dashboard/app.py`). |

## Analysis scripts (`scripts/`)

| Script | Role |
|---|---|
| `extract_evidence.py` | Unzip the AES-protected lab archive (pyzipper). |
| `recon_pcap.py` | First-pass triage: protocols, talkers, conversations, DNS, HTTP. |
| `inspect_scripts.py` | In-memory view of the two carved HTTP payloads. |
| `extract_pe_and_iocs.py` | Rebuild embedded PEs in memory; hash + PE header; IOC scan. |
| `search_loader.py` / `find_drops.py` | Locate the LOLBin path and dropped files. |
| `pcap_to_csv.py` | Export benign flow/HTTP/DNS tables for the notebooks. |
| `plots.py` | Render the figures in `visualizations/`. |

> **Safe handling:** malicious bytes are reconstructed only in memory. Scripts are
> kept outside the evidence directory and run with `python -P` so no planted module
> in the evidence folder can be imported.
