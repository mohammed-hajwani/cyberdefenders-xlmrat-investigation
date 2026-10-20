"""First-pass recon of the XLMRat pcap with scapy (read-only).

Prints: packet/protocol overview, endpoints & conversations, DNS queries,
and all HTTP requests (host + method + path) and responses. No file is
executed; only packet fields are read.

    python -P scripts/recon_pcap.py <pcap>
"""
import sys
from collections import Counter

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


def main():
    pcap = sys.argv[1]
    pkts = rdpcap(pcap)
    print(f"total packets: {len(pkts)}")
    t0, t1 = float(pkts[0].time), float(pkts[-1].time)
    print(f"capture span : {t1 - t0:.1f}s")

    protos = Counter()
    endpoints = Counter()
    convos = Counter()
    dns_q = Counter()
    http_reqs = []
    http_resps = []

    for p in pkts:
        if IP in p:
            src, dst = p[IP].src, p[IP].dst
            endpoints[src] += 1
            if TCP in p:
                protos[f"TCP/{p[TCP].dport}"] += 1
                key = tuple(sorted([f"{src}:{p[TCP].sport}", f"{dst}:{p[TCP].dport}"]))
                convos[key] += 1
            elif UDP in p:
                protos[f"UDP/{p[UDP].dport}"] += 1
        if p.haslayer(DNSQR):
            dns_q[p[DNSQR].qname.decode(errors="replace")] += 1
        if p.haslayer(Raw) and TCP in p:
            payload = bytes(p[Raw].load)
            if payload[:3] in (b"GET", b"POS", b"HEA", b"PUT") or payload[:4] == b"POST":
                line = payload.split(b"\r\n")[0].decode(errors="replace")
                host = ""
                for h in payload.split(b"\r\n"):
                    if h.lower().startswith(b"host:"):
                        host = h.decode(errors="replace").split(":", 1)[1].strip()
                http_reqs.append((p[IP].src, p[IP].dst, p[TCP].dport, host, line))
            elif payload[:5] == b"HTTP/":
                line = payload.split(b"\r\n")[0].decode(errors="replace")
                ctype = ""
                for h in payload.split(b"\r\n"):
                    if h.lower().startswith(b"content-type:"):
                        ctype = h.decode(errors="replace").split(":", 1)[1].strip()
                http_resps.append((p[IP].src, p[IP].dst, line, ctype))

    print("\n== top protocols (by dst port) ==")
    for k, v in protos.most_common(12):
        print(f"  {k}: {v}")
    print("\n== top talkers (src ip) ==")
    for k, v in endpoints.most_common(10):
        print(f"  {k}: {v}")
    print("\n== conversations ==")
    for k, v in convos.most_common(10):
        print(f"  {k[0]} <-> {k[1]} : {v} pkts")
    print("\n== DNS queries ==")
    for k, v in dns_q.most_common(20):
        print(f"  {k} ({v})")
    print("\n== HTTP requests ==")
    for src, dst, dport, host, line in http_reqs:
        print(f"  {src} -> {dst}:{dport}  Host:{host}  {line}")
    print("\n== HTTP responses ==")
    for src, dst, line, ctype in http_resps:
        print(f"  {src} -> {dst}  {line}  [{ctype}]")


if __name__ == "__main__":
    main()
