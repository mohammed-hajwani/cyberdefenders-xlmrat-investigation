# Final Report — Cybersecurity Incident Investigation (CyberDefenders: XLMRat)

**Project:** Data-Assisted Cybersecurity Incident Investigation and Threat Analysis
using CyberDefenders Case Studies
**Case:** CyberDefenders "XLMRat" (Network Forensics)
**Evidence:** `236-XLMRat.pcap`

---

## 1. Introduction

Security incidents generate large volumes of network and system telemetry. This
project executes a real-world-style investigation from the CyberDefenders platform,
using forensic and data-analysis tooling to reconstruct an intrusion, identify the
malware and infrastructure, and recommend mitigations. Cybersecurity investigation
is the core; a Python/pandas data-analysis layer adds structure and visualization.

## 2. Problem Statement

A company endpoint was flagged for suspicious outbound traffic on a non-standard
port. Only a single packet capture is available. We must determine **how the host
was compromised, what malware was delivered, how it executed and persisted, and
how it communicates** — then extract indicators and mitigations.

## 3. Objectives

See `case-study/investigation-objectives.md`. In short: reconstruct the attack
chain, identify payloads/infrastructure, build a timeline, map to MITRE ATT&CK,
extract IOCs, and answer the lab's 7 graded questions with evidence.

## 4. Case Study

- Platform: **CyberDefenders** · Lab: **XLMRat** · Category: Network Forensics · Easy.
- Scenario: analyze the provided PCAP to determine the attack method, identify
  payloads, and trace the timeline. (`case-study/case-overview.md`.)

## 5. Tools & Technologies

Wireshark/tshark, scapy, CyberChef, PowerShell (read-only), VirusTotal, and
Python (pandas, NumPy, matplotlib, Jupyter); optional Streamlit dashboard. Each
tool's role is documented in `cybersecurity/tools.md`.

## 6. Investigation Methodology

`pcap → triage (scapy) → in-memory payload reconstruction → CSV export (benign
metadata) → pandas EDA → timeline → IOCs → ATT&CK → risk/mitigation`. All malware
bytes are handled **in memory only**; see the safe-handling note (§13).

## 7. Evidence Collection

One PCAP, `236-XLMRat.pcap` (~600 KB, 1,550 packets, 2024-01-09 17:27–17:40 UTC).
Benign derived tables are exported to `data/processed/{packets,http,dns}.csv`.

## 8. Security Investigation

Three hosts: victim `10.1.9.101`, gateway `10.1.9.1`, adversary `45.126.209.4`.
Two HTTP downloads on port 222 and a long-lived channel on port 8808 dominate the
capture; the victim resolves `madmrx.duckdns.org`. Full technical walkthrough:
`cybersecurity/investigation.md`.

## 9. Attack / Incident Reconstruction

Multi-stage **AsyncRAT** delivery:

1. **Stage 1** — `GET http://45.126.209.4:222/xlm.txt`: an obfuscated **VBScript**
   that launches hidden PowerShell.
2. **Stage 2** — `GET http://45.126.209.4:222/mdm.jpg`: a 431 KB **PowerShell**
   script (masqueraded as JPEG) carrying two hex-encoded .NET PEs.
3. **Execution** — reflective `NewPE2.PE.Execute` **process-hollows** the AsyncRAT
   client into `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` (LOLBin).
4. **Persistence** — drops `Conted.ps1/.bat/.vbs` to `C:\Users\Public\` and creates
   scheduled task **"Update Edge"**.
5. **C2** — beacons to `45.126.209.4:8808` and resolves `madmrx.duckdns.org`.

Ordered timeline: `cybersecurity/timeline.md`.

### MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Execution | T1059.005 (VBScript), T1059.001 (PowerShell) |
| Defense Evasion | T1027 (obfuscation), T1036 (masquerading .jpg), T1620 (reflective loading), T1055.012 (process hollowing), T1218 (signed-binary/LOLBin) |
| Persistence | T1053.005 (scheduled task) |
| Command & Control | T1105 (ingress tool transfer), T1571 (non-standard port), T1568.002 (dynamic DNS), T1219/T1071 |

## 10. Data Analysis

`notebooks/01_data_preparation.ipynb` cleans and types the exported tables;
`02_security_eda.ipynb` profiles conversations, ports, the C2 channel, HTTP and
DNS; `03_timeline_analysis.ipynb` reconstructs the event sequence and renders the
figures. Findings: a single hostile peer, two non-standard ports, two-stage HTTP
delivery, and DuckDNS C2.

## 11. Indicators of Compromise

Full table in `cybersecurity/iocs.md`. Headline indicators: IP `45.126.209.4`;
domain `madmrx.duckdns.org`; ports 222/8808; malware SHA256
`1eb7b02e…81d798` (AsyncRAT); dropped `C:\Users\Public\Conted.{ps1,bat,vbs}`;
LOLBin `RegSvcs.exe`.

## 12. Dashboard / Visualization

Figures in `visualizations/` (HTTP stages, packets-over-time with C2 overlay, port
profile, byte volume). Optional interactive view: `streamlit run dashboard/app.py`.

## 13. Risk Assessment

- **Severity: HIGH / Critical.** Confirmed RAT execution with interactive C2 and
  persistence = full endpoint compromise; AsyncRAT supports keylogging, screen
  capture, file transfer and further tooling.
- **Likelihood: High.** Commodity AsyncRAT + LOLBin injection + dynamic DNS is a
  common, low-cost pattern that evades signature-only controls.
- **Impact:** potential credential theft, data exfiltration, and lateral movement
  from the compromised host.

**Safe-handling note.** Writing carved HTTP objects to disk triggered immediate
Windows Defender quarantine (genuine AsyncRAT). The investigation therefore
reconstructs payloads in memory and records only hashes, metadata, and deobfuscated
text; exported CSVs contain benign flow metadata only.

## 14. Mitigation

- Block/monitor `45.126.209.4` and `*.duckdns.org`; alert on outbound traffic to
  non-standard ports (222, 8808).
- Alert on `RegSvcs.exe` / `RegAsm.exe` / `InstallUtil.exe` making network
  connections or spawning from script hosts (LOLBin abuse).
- Constrain script hosts: PowerShell Constrained Language Mode + ScriptBlock
  logging, disable/limit `wscript`/`cscript`, enable AMSI.
- Block Office/XLM macro execution; use ASR rules for script-spawned child processes.
- Hunt for `C:\Users\Public\Conted.*` and the scheduled task **"Update Edge"**;
  remediate the host and rotate any credentials used on it.

## 15. Results

All 7 lab questions answered and cross-validated (`cybersecurity/questions-answers.md`):

| # | Answer |
|---|---|
| 1 | `http://45.126.209.4:222/xlm.txt` |
| 2 | ReliableSite.Net LLC |
| 3 | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| 4 | `Backdoor:MSIL/AsyncRat.A2786761` (AsyncRAT) |
| 5 | 2023-10-30 15:08 |
| 6 | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| 7 | Conted.ps1, Conted.bat, Conted.vbs |

## 16. Conclusion

From a single PCAP we reconstructed a complete AsyncRAT intrusion — delivery,
in-memory injection via a signed LOLBin, scheduled-task persistence, and DuckDNS
C2 — mapped it to MITRE ATT&CK, extracted IOCs, and produced actionable detections.
The data-analysis layer made the evidence reproducible and visual without ever
handling live malware unsafely.

## 17. References

- CyberDefenders — XLMRat lab: https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/
- MITRE ATT&CK: https://attack.mitre.org/
- AsyncRAT background and community write-ups (reference only).

## 18. GitHub Repository

This repository. The pcap itself is **not** committed (malware + redistribution);
see `evidence/README.md` to obtain it.
