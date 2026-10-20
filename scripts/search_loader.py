"""Substring search over the in-memory loader script (no heavy regex, no disk).

Prints ascii-safe context around keywords so we can read the LOLBin path,
injection target, and dropped-file logic. Static inspection only.

    python -P scripts/search_loader.py <pcap>
"""
import sys
from scapy.all import rdpcap, IP, TCP, Raw

SERVER_PORT = 222
KEYWORDS = ["aspnet_compiler", "aspnet", "RegSvcs", "RegAsm", "InstallUtil", "MSBuild",
            "Framework", "v4.0.30319", "Startup", "schtasks", "CurrentVersion",
            "AppData", "\\Temp", ".exe", ".bat", ".vbs", ".lnk", "DownloadFile",
            "WriteAllBytes", "Set-Content", "Out-File", "Copy", "CreateObject",
            "GetMethod", "Reflection", "EntryPoint", "duckdns", "Invoke"]


def ascii_ctx(text, idx, pre=60, post=90):
    s = text[max(0, idx - pre): idx + post]
    return s.encode("ascii", "replace").decode("ascii").replace("\n", " ").replace("\r", " ")


def main():
    streams = {}
    for p in rdpcap(sys.argv[1]):
        if IP in p and TCP in p and p[TCP].sport == SERVER_PORT and p.haslayer(Raw):
            streams.setdefault(p[TCP].dport, {})[int(p[TCP].seq)] = bytes(p[Raw].load)
    body = b""
    for segs in streams.values():
        data = b"".join(segs[s] for s in sorted(segs))
        if b"\r\n\r\n" in data:
            _, b = data.split(b"\r\n\r\n", 1)
            if len(b) > len(body):
                body = b
    text = body.decode("utf-8", errors="replace")
    print(f"script length: {len(text)}")
    for kw in KEYWORDS:
        idx, hits = -1, []
        while True:
            idx = text.find(kw, idx + 1)
            if idx == -1:
                break
            hits.append(idx)
            if len(hits) >= 4:
                break
        if hits:
            print(f"\n### {kw}  ({len(hits)}+ hits)")
            for h in hits[:3]:
                print("   ...", ascii_ctx(text, h), "...")


if __name__ == "__main__":
    main()
