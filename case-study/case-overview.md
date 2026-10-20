# Case Overview — CyberDefenders "XLMRat"

- **Platform:** CyberDefenders — Blue Team CTF Challenges
- **Lab:** XLMRat (`https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/`)
- **Category:** Network Forensics · **Difficulty:** Easy · **Status:** Retired
- **Primary tool (per lab):** Wireshark · **Supporting:** CyberChef, PowerShell, VirusTotal, Python3
- **Evidence provided:** one PCAP — `236-XLMRat.pcap` (≈600 KB)

## Scenario (as given by the lab)

> A compromised machine has been flagged due to suspicious network traffic. Your
> task is to analyze the PCAP file to determine the attack method, identify any
> malicious payloads, and trace the timeline of events. Focus on how the attacker
> gained access, what tools or techniques were used, and how the malware operated
> post-compromise.

## Environment observed in the evidence

| Element | Value |
|---|---|
| Victim endpoint | `10.1.9.101` |
| Local DNS/gateway | `10.1.9.1` |
| Adversary server | `45.126.209.4` (ReliableSite.Net LLC) |
| C2 hostname | `madmrx.duckdns.org` |
| Capture start | 2024-01-09 17:27:27 UTC |

## One-line summary

A multi-stage **AsyncRAT** delivery: an XLM/VBScript loader pulls an obfuscated
PowerShell "image", which reflectively injects AsyncRAT into `RegSvcs.exe` and
persists via a scheduled task, then beacons to a DuckDNS C2.

See `../cybersecurity/` for the full investigation, IOCs, timeline, and the 7
lab-question answers; `../report/final-report.md` for the complete write-up.
