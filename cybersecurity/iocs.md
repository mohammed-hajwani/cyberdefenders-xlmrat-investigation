# Indicators of Compromise (IOCs) — XLMRat / AsyncRAT

Case: CyberDefenders **XLMRat** (Network Forensics). Evidence: `236-XLMRat.pcap`.
Capture window: **2024-01-09 17:27–17:40 UTC**.

## Network

| Type | Indicator | Context |
|---|---|---|
| IPv4 | `45.126.209.4` | Staging + C2 server (ReliableSite.Net LLC) |
| Domain | `madmrx.duckdns.org` | DuckDNS dynamic-DNS C2 hostname (resolved by victim) |
| TCP port | `222` | HTTP staging (stage-1 and stage-2 download) |
| TCP port | `8808` | AsyncRAT C2 channel (long-lived, 1199 packets) |
| URL | `http://45.126.209.4:222/xlm.txt` | **Stage 1** — VBScript loader |
| URL | `http://45.126.209.4:222/mdm.jpg` | **Stage 2** — PowerShell (image/jpeg masquerade) carrying the RAT |
| Victim host | `10.1.9.101` | Compromised internal endpoint |

## Host / endpoint

| Type | Indicator | Context |
|---|---|---|
| File | `C:\Users\Public\Conted.ps1` | Dropped by stage-2 script |
| File | `C:\Users\Public\Conted.bat` | Dropped by stage-2 script |
| File | `C:\Users\Public\Conted.vbs` | Dropped by stage-2 script (persistence launcher) |
| Scheduled task | `Update Edge` | Persistence — runs `Conted.vbs` → `.bat` → `.ps1` |
| LOLBin abused | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | Process-hollowing target for in-memory AsyncRAT |
| Technique | `NewPE2.PE.Execute` (RunPE) | .NET reflective loader injecting the RAT |

## File hashes

| Artifact | SHA256 | MD5 | Size | PE compile (UTC) |
|---|---|---|---|---|
| AsyncRAT client (**the malware executable**) | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` | `88e8cee71f454bc1fa6b3a7741a3bd7d` | 66,560 B | 2023-10-30 15:08 |
| NewPE2 RunPE loader | `2c6c4cd045537e2586eab73072d790af362e37e6d4112b1d01f15574491296b8` | `a0dd62074640e1997c6422aff8becf2f` | 76,288 B | (timestamp stomped) |

## Classification

- **Family:** AsyncRAT (.NET MSIL remote-access trojan)
- **Alibaba (VirusTotal) label:** `Backdoor:MSIL/AsyncRat.A2786761`
- **Delivery theme:** XLM (Excel 4.0) macro → VBScript → PowerShell → reflective .NET injection

> Hashes were computed by reconstructing the embedded PEs **in memory** from the
> pcap; the malicious bytes were never written to disk (host AV quarantines them).
> See `../scripts/extract_pe_and_iocs.py`.
