"""Fast, in-memory structural look at the two HTTP payloads. Prints to stdout
only (never writes payload bytes to disk). Static inspection; no execution.

    python -P scripts/inspect_scripts.py <pcap>
"""
import sys
from scapy.all import rdpcap, IP, TCP, Raw

SERVER_PORT = 222


def reassemble(pkts):
    streams = {}
    for p in pkts:
        if IP in p and TCP in p and p[TCP].sport == SERVER_PORT and p.haslayer(Raw):
            streams.setdefault(p[TCP].dport, {})[int(p[TCP].seq)] = bytes(p[Raw].load)
    objs = {}
    for cport, segs in streams.items():
        data = b"".join(segs[s] for s in sorted(segs))
        if b"\r\n\r\n" in data:
            hdr, body = data.split(b"\r\n\r\n", 1)
            clen = None
            for line in hdr.decode(errors="replace").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    clen = int(line.split(":", 1)[1].strip())
            if clen is not None:
                body = body[:clen]
            objs[cport] = body
    return objs


def main():
    print("reading pcap...", flush=True)
    objs = reassemble(rdpcap(sys.argv[1]))
    for cport, body in sorted(objs.items(), key=lambda kv: len(kv[1])):
        text = body.decode("utf-8", errors="replace").lstrip("﻿")
        print("\n" + "=" * 70, flush=True)
        print(f"OBJECT cport {cport} | {len(body)} bytes", flush=True)
        print("=" * 70, flush=True)
        if len(text) <= 2200:
            print(text, flush=True)
        else:
            print("----- HEAD 1800 -----", flush=True)
            print(text[:1800], flush=True)
            print("\n----- TAIL 1200 -----", flush=True)
            print(text[-1200:], flush=True)


if __name__ == "__main__":
    main()
