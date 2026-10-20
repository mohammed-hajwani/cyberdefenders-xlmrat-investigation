"""Export the pcap to structured CSV tables for the data-analysis notebooks.

Writes ONLY benign flow/metadata (timestamps, IPs, ports, sizes, HTTP request
lines, DNS names, TCP flags) -- never packet payloads -- so the output is safe
on disk and host AV does not quarantine it. This is the bridge from the network
evidence to the pandas EDA layer.

    python -P scripts/pcap_to_csv.py <pcap> <out_dir>
"""
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


def iso(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def main():
    pcap, out = sys.argv[1], Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    pkts = rdpcap(pcap)
    t0 = float(pkts[0].time)

    packets, https, dns_rows = [], [], []
    for i, p in enumerate(pkts, 1):
        if IP not in p:
            continue
        row = {
            "frame": i,
            "time_utc": iso(p.time),
            "rel_time": round(float(p.time) - t0, 6),
            "src": p[IP].src,
            "dst": p[IP].dst,
            "proto": "TCP" if TCP in p else ("UDP" if UDP in p else p[IP].proto),
            "sport": p[TCP].sport if TCP in p else (p[UDP].sport if UDP in p else ""),
            "dport": p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else ""),
            "length": len(p),
            "tcp_flags": str(p[TCP].flags) if TCP in p else "",
        }
        packets.append(row)

        if p.haslayer(Raw) and TCP in p:
            pl = bytes(p[Raw].load)
            if pl[:3] in (b"GET", b"POS", b"HEA", b"PUT", b"DEL") or pl[:4] == b"HTTP":
                first = pl.split(b"\r\n")[0].decode(errors="replace")
                host = ""
                for h in pl.split(b"\r\n"):
                    if h.lower().startswith(b"host:"):
                        host = h.split(b":", 1)[1].strip().decode(errors="replace")
                kind = "response" if pl[:4] == b"HTTP" else "request"
                method = first.split(" ")[0] if kind == "request" else ""
                uri = first.split(" ")[1] if kind == "request" and len(first.split(" ")) > 1 else ""
                status = first.split(" ")[1] if kind == "response" and len(first.split(" ")) > 1 else ""
                https.append({
                    "frame": i, "time_utc": iso(p.time), "rel_time": round(float(p.time) - t0, 6),
                    "src": p[IP].src, "dst": p[IP].dst, "dport": p[TCP].dport,
                    "kind": kind, "method": method, "host": host, "uri": uri,
                    "status": status, "first_line": first,
                })

        if p.haslayer(DNSQR):
            dns_rows.append({
                "frame": i, "time_utc": iso(p.time), "src": p[IP].src, "dst": p[IP].dst,
                "qname": p[DNSQR].qname.decode(errors="replace").rstrip("."),
                "qtype": p[DNSQR].qtype,
                "is_response": int(p.haslayer(DNS) and p[DNS].qr == 1),
            })

    def write(name, rows, fields):
        with (out / name).open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print(f"  wrote {out / name}  ({len(rows)} rows)")

    write("packets.csv", packets,
          ["frame", "time_utc", "rel_time", "src", "dst", "proto", "sport", "dport", "length", "tcp_flags"])
    write("http.csv", https,
          ["frame", "time_utc", "rel_time", "src", "dst", "dport", "kind", "method", "host", "uri", "status", "first_line"])
    write("dns.csv", dns_rows,
          ["frame", "time_utc", "src", "dst", "qname", "qtype", "is_response"])
    print("done.")


if __name__ == "__main__":
    main()
