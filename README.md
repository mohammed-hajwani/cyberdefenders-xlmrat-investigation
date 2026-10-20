# CyberDefenders Security Analysis — XLMRat (AsyncRAT) Investigation

A **CyberDefenders-first** cybersecurity incident investigation with a supporting
data-analysis layer. We take the single PCAP from the CyberDefenders **XLMRat**
Network Forensics lab, reconstruct a multi-stage **AsyncRAT** intrusion, map it to
MITRE ATT&CK, extract IOCs, and answer the lab's 7 graded questions — then add a
Python/pandas pipeline and visualizations on top.

> **Authorized educational investigation.** All work is defensive, static, and
> performed on evidence provided by CyberDefenders. No systems were attacked.
> Live-malware bytes are reconstructed **in memory only** and never written to disk
> (host AV quarantines them); see [`evidence/README.md`](evidence/README.md).

## The incident in one paragraph

Victim `10.1.9.101` fetched `http://45.126.209.4:222/xlm.txt` — an obfuscated
VBScript that launched hidden PowerShell to download `/mdm.jpg` (a PowerShell
script masquerading as a JPEG). That script carried two hex-encoded .NET PEs and
used a `NewPE2` RunPE loader to **hollow AsyncRAT into `RegSvcs.exe`** (a signed
LOLBin), dropped `Conted.ps1/.bat/.vbs` to `C:\Users\Public\`, persisted via the
scheduled task **"Update Edge"**, and beaconed to `45.126.209.4:8808`
(`madmrx.duckdns.org`).

## Answers to the 7 lab questions

| # | Question | Answer |
|---|---|---|
| 1 | First-stage URL | `http://45.126.209.4:222/xlm.txt` |
| 2 | Hosting provider | ReliableSite.Net LLC |
| 3 | SHA256 of malware | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| 4 | Family (Alibaba) | `Backdoor:MSIL/AsyncRat.A2786761` (AsyncRAT) |
| 5 | PE compile time | 2023-10-30 15:08 |
| 6 | LOLBin path | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| 7 | Dropped files | `Conted.ps1`, `Conted.bat`, `Conted.vbs` |

Evidence for each: [`cybersecurity/questions-answers.md`](cybersecurity/questions-answers.md).

## Repository layout

```text
case-study/        case overview + investigation objectives
evidence/          where to get the pcap (not committed) + safe-handling
cybersecurity/     investigation.md, tools.md, iocs.md, timeline.md, questions-answers.md
data/
  processed/       benign CSV tables exported from the pcap (safe to commit)
notebooks/         01 data-prep · 02 EDA · 03 timeline (executed, with outputs)
scripts/           pcap analysis + CSV export + plotting (static, in-memory)
visualizations/    rendered incident figures (PNG)
dashboard/         optional Streamlit dashboard (app.py)
report/            final-report.md (full write-up)
screenshots/       (add Wireshark/CyberChef evidence screenshots here)
```

## Quick start

```bash
pip install -r requirements.txt

# 1) Obtain the pcap (see evidence/README.md), then export benign tables:
python -P scripts/pcap_to_csv.py evidence/xlmrat/236-XLMRat.pcap data/processed

# 2) Run the analysis:
jupyter notebook notebooks/          # 01 -> 02 -> 03
python scripts/plots.py              # (re)render visualizations/
streamlit run dashboard/app.py       # optional dashboard
```

The analysis notebooks run on the committed `data/processed/*.csv`, so they work
even before you download the pcap. Re-deriving the malware hashes requires the pcap:
`python -P scripts/extract_pe_and_iocs.py evidence/xlmrat/236-XLMRat.pcap`.

## 4-member work division (per project brief)

| Member | Module | Main artifacts |
|---|---|---|
| 1 — Incident Response | case understanding, timeline, narrative | [`case-study/`](case-study/), [`cybersecurity/timeline.md`](cybersecurity/timeline.md), [`report/`](report/) |
| 2 — Forensic/Network | Wireshark + payload analysis, IOCs | [`cybersecurity/investigation.md`](cybersecurity/investigation.md), [`cybersecurity/iocs.md`](cybersecurity/iocs.md), [`scripts/`](scripts/) |
| 3 — Data Analysis | cleaning, EDA, temporal analysis | [`notebooks/`](notebooks/), [`data/processed/`](data/processed/) |
| 4 — Visualization/Reporting | figures, dashboard, final report | [`visualizations/`](visualizations/), [`dashboard/`](dashboard/), [`report/`](report/) |

## Tools

Wireshark/tshark · scapy · CyberChef · PowerShell (read-only) · VirusTotal ·
Python (pandas, NumPy, matplotlib, Jupyter) · Streamlit. Rationale per tool:
[`cybersecurity/tools.md`](cybersecurity/tools.md).
