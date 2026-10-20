# Evidence

This folder holds the case evidence used by the investigation.

## File

| File | Description |
|---|---|
| `xlmrat/236-XLMRat.pcap` | The single PCAP provided by the CyberDefenders XLMRat lab |

## How to obtain it

The pcap is **not committed** to this repository (it contains live malware
traffic, and redistributing CyberDefenders lab files is discouraged). To get it:

1. Sign in to CyberDefenders and open the lab:
   `https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/`
2. Click **Download Lab Files**.
3. Unzip with the password: `cyberdefenders.org`
4. Place `236-XLMRat.pcap` at `evidence/xlmrat/236-XLMRat.pcap`.

Helper for the AES-protected zip:

```bash
python -P scripts/extract_evidence.py path/to/XLMRat.zip evidence/xlmrat
```

## ⚠️ Safe-handling

The pcap carries a real **AsyncRAT** payload. **Do not** carve HTTP objects to
disk and open them — host AV will (correctly) quarantine them, and executing them
is dangerous. All scripts here analyze the payloads **in memory** and emit only
metadata, hashes, and deobfuscated text. Work in an isolated VM if you need to go
deeper.

## Derived (safe) data

`../data/processed/*.csv` are benign flow/HTTP/DNS tables exported from the pcap
(no payload bytes) and are safe to commit and analyze.
