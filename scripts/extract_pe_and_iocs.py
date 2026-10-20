"""Reconstruct the embedded PE in memory and scan the loader script for IOCs.

Static only: it rebuilds the executable bytes in RAM to hash + read the PE
header, and never writes those bytes to disk or executes anything. Output is
ascii-safe so it prints on a cp1252 console.

    python -P scripts/extract_pe_and_iocs.py <pcap>
"""
import datetime
import hashlib
import re
import struct
import sys

from scapy.all import rdpcap, IP, TCP, Raw

SERVER_PORT = 222


def reassemble_largest(pkts):
    streams = {}
    for p in pkts:
        if IP in p and TCP in p and p[TCP].sport == SERVER_PORT and p.haslayer(Raw):
            streams.setdefault(p[TCP].dport, {})[int(p[TCP].seq)] = bytes(p[Raw].load)
    best = b""
    for segs in streams.values():
        data = b"".join(segs[s] for s in sorted(segs))
        if b"\r\n\r\n" in data:
            _, body = data.split(b"\r\n\r\n", 1)
            if len(body) > len(best):
                best = body
    return best.decode("utf-8", errors="replace").lstrip("﻿")


def pe_info(pe: bytes):
    out = {}
    out["size"] = len(pe)
    out["sha256"] = hashlib.sha256(pe).hexdigest()
    out["md5"] = hashlib.md5(pe).hexdigest()
    if pe[:2] == b"MZ":
        e = struct.unpack_from("<I", pe, 0x3C)[0]
        if pe[e:e + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", pe, e + 4)[0]
            ts = struct.unpack_from("<I", pe, e + 8)[0]
            out["machine"] = hex(machine)
            out["timedatestamp_raw"] = ts
            out["compile_utc"] = datetime.datetime.fromtimestamp(
                ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
    return out


def main():
    text = reassemble_largest(rdpcap(sys.argv[1]))
    print(f"loader script length: {len(text)} chars")

    # 1) reconstruct every underscore-separated hex blob that starts at MZ (4D5A)
    print("\n== embedded PE reconstruction ==")
    for m in re.finditer(r'"([0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){50,})"', text):
        hexstr = m.group(1).replace("_", "")
        try:
            raw = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if raw[:2] == b"MZ":
            info = pe_info(raw)
            print(f"  variable blob near offset {m.start()}:")
            for k, v in info.items():
                print(f"    {k:18}: {v}")

    # 2) hex variable names present (helps describe loader structure)
    print("\n== hex/byte variable assignments ==")
    for v in sorted(set(re.findall(r"\$hexString_\w+|\$[A-Za-z0-9_]*(?=\s*=\s*\"4D[_ ]?5A)", text))):
        print("   ", v)

    # 3) referenced filenames (dropped files / stages)
    print("\n== filenames referenced ==")
    for fn in sorted(set(re.findall(r"[\w\-]+\.(?:exe|dll|bat|vbs|ps1|txt|jpg|scr|lnk|cmd|url)", text, re.I))):
        print("   ", fn)

    # 4) full windows paths / LOLBins
    print("\n== windows paths (.NET framework / LOLBins) ==")
    for pth in sorted(set(re.findall(r"[A-Za-z]:\\[\\\w\.\-\(\) ]+\.(?:exe|dll)", text))):
        print("   ", pth)
    for frag in sorted(set(re.findall(r"(?:Microsoft\.NET|Framework64?|v\d\.\d\.\d+|aspnet_\w+|RegAsm|RegSvcs|InstallUtil|MSBuild|csc)\w*", text, re.I))):
        print("    frag:", frag)

    # 5) persistence / drop locations
    print("\n== persistence / drop indicators ==")
    for kw in ["Startup", "schtasks", "Registry", "CurrentVersion\\Run", "AppData", "Temp",
               "WriteAllBytes", "WriteAllText", "Set-Content", "Out-File", "CopyHere",
               "InstallUtil", "aspnet", "RegAsm", "RegSvcs", "MSBuild", "VirtualAllocEx",
               "GetMethod", "Invoke", "duckdns", "Reflection.Assembly"]:
        hits = [mm.start() for mm in re.finditer(re.escape(kw), text, re.I)]
        if hits:
            print(f"   {kw}: {len(hits)}x (first@{hits[0]})")


if __name__ == "__main__":
    main()
