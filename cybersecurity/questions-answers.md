# CyberDefenders XLMRat — Answers to the 7 Lab Questions

Each answer is backed by the evidence in `236-XLMRat.pcap` and cross-checked
against a published community write-up (used only as reference).

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | URL the first malware stage was installed from | `http://45.126.209.4:222/xlm.txt` | `http.csv` frame 4 (first HTTP GET) |
| 2 | Hosting provider owning the IP | **ReliableSite.Net LLC** | WHOIS of `45.126.209.4` |
| 3 | SHA256 of the malware executable | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` | PE rebuilt from `$hexString_bbb` |
| 4 | Malware family label (Alibaba) | `Backdoor:MSIL/AsyncRat.A2786761` (**AsyncRAT**) | VirusTotal / Alibaba engine |
| 5 | PE compile (creation) timestamp of the malware | `2023-10-30 15:08` | PE COFF `TimeDateStamp` = `0x653FC6FC` |
| 6 | LOLBin leveraged for stealthy execution (full path) | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | Deobfuscated stage-2 script |
| 7 | Files dropped by the script | `Conted.ps1, Conted.bat, Conted.vbs` | `WriteAllText` → `C:\Users\Public\` |

## Supporting notes

- **Q1 — first vs second stage.** The capture shows `GET /xlm.txt` (frame 4) *before*
  `GET /mdm.jpg` (frame 12). `xlm.txt` is the VBScript that downloads `mdm.jpg`, so
  `xlm.txt` is the first stage.
- **Q3 / Q5 — which PE.** Two PEs are embedded. `$hexString_bbb` is the AsyncRAT
  client (real compile date 2023-10-30); `$hexString_pe` is the NewPE2 RunPE loader
  (timestamp stomped). The *malware executable* is the AsyncRAT client.
- **Q6 — obfuscation.** The path was stored as `'C:\W#######indow…s\Mi####cr'` etc.
  with `-replace '#',''`, reassembling to the RegSvcs.exe path.
