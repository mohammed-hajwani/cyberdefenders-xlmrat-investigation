"""List all dropped-file paths and the scheduled-task name from the loader."""
import re
import sys
from scapy.all import rdpcap, IP, TCP, Raw

streams = {}
for p in rdpcap(sys.argv[1]):
    if IP in p and TCP in p and p[TCP].sport == 222 and p.haslayer(Raw):
        streams.setdefault(p[TCP].dport, {})[int(p[TCP].seq)] = bytes(p[Raw].load)
body = b""
for segs in streams.values():
    d = b"".join(segs[s] for s in sorted(segs))
    if b"\r\n\r\n" in d:
        _, b = d.split(b"\r\n\r\n", 1)
        if len(b) > len(body):
            body = b
t = body.decode("utf-8", "replace")

print("--- WriteAllText / WriteAllBytes targets ---")
for m in re.finditer(r'WriteAll(?:Text|Bytes)\("([^"]+)"', t):
    print("   ", m.group(1))

pub = "C:" + chr(92) + "Users" + chr(92) + "Public" + chr(92)
print("--- all C:\\Users\\Public\\ paths ---")
seen = set()
idx = -1
while True:
    idx = t.find(pub, idx + 1)
    if idx == -1:
        break
    tail = t[idx:idx + 40]
    name = re.match(r"[\w:\\.]+", tail).group(0)
    if name not in seen:
        seen.add(name)
        print("   ", name)

i = t.find("RegisterTaskDefinition")
print("--- scheduled task ---")
if i >= 0:
    print("   ctx:", t[i - 40:i + 60].encode("ascii", "replace").decode().replace("\n", " ").replace("\r", " "))
for m in re.finditer(r'"(Upda\w*)"', t):
    print("   taskname:", m.group(1))
