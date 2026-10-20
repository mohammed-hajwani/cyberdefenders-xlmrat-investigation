"""Render incident visualizations from the exported CSV tables.

    python scripts/plots.py          # -> visualizations/*.png

Uses only the benign metadata in data/processed/, never the pcap payloads.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
OUT = ROOT / "visualizations"

ATTACKER = "45.126.209.4"
VICTIM = "10.1.9.101"

# consistent palette
C_BENIGN, C_BAD, C_C2 = "#4C78A8", "#E45756", "#B23A48"


def load():
    pk = pd.read_csv(PROC / "packets.csv", parse_dates=["time_utc"])
    http = pd.read_csv(PROC / "http.csv")
    return pk, http


def fig_ports(pk):
    tcp = pk[pk["proto"] == "TCP"].copy()
    top = tcp["dport"].value_counts().head(8).sort_values()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh([str(int(p)) for p in top.index], top.values, color=C_C2)
    ax.set_title("Traffic by destination TCP port")
    ax.set_xlabel("packets"); ax.set_ylabel("dst port")
    plt.tight_layout(); plt.savefig(OUT / "ports.png", dpi=120); plt.close()


def fig_timeline(pk):
    pk = pk.copy()
    pk["sec"] = pk["rel_time"].astype(float).astype(int)
    pk["is_c2"] = ((pk["dport"] == 8808) | (pk["sport"] == 8808))
    grp = pk.groupby([pk["sec"] // 10 * 10, "is_c2"]).size().unstack(fill_value=0)
    grp = grp.rename(columns={False: "other", True: "C2 (8808)"})
    ax = grp.plot(kind="area", stacked=True, figsize=(12, 4.5),
                  color={"other": C_BENIGN, "C2 (8808)": C_BAD}, alpha=.85)
    ax.set_title("Packets over time (10-second bins) — C2 vs other")
    ax.set_xlabel("seconds since capture start"); ax.set_ylabel("packets")
    plt.tight_layout(); plt.savefig(OUT / "timeline.png", dpi=120); plt.close()


def fig_bytes_dir(pk):
    sub = pk[(pk["src"].isin([ATTACKER, VICTIM])) & (pk["dst"].isin([ATTACKER, VICTIM]))].copy()
    sub["direction"] = sub["src"].map({VICTIM: "victim -> server", ATTACKER: "server -> victim"})
    by = sub.groupby("direction")["length"].sum() / 1024
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(by.index, by.values, color=[C_BENIGN, C_BAD])
    ax.set_title("Bytes exchanged with 45.126.209.4")
    ax.set_ylabel("KiB")
    for i, v in enumerate(by.values):
        ax.text(i, v, f"{v:.0f}", ha="center", va="bottom")
    plt.tight_layout(); plt.savefig(OUT / "bytes_direction.png", dpi=120); plt.close()


def fig_stages(http):
    reqs = http[http["kind"] == "request"]
    fig, ax = plt.subplots(figsize=(9, 2.6))
    ax.axis("off")
    ax.set_title("HTTP download stages (port 222)", loc="left")
    y = 0.6
    for _, r in reqs.iterrows():
        ax.annotate(f"{r['rel_time']:.2f}s  {r['method']} {r['uri']}",
                    xy=(0.02, y), fontsize=12, family="monospace")
        y -= 0.3
    plt.tight_layout(); plt.savefig(OUT / "http_stages.png", dpi=120); plt.close()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pk, http = load()
    fig_ports(pk)
    fig_timeline(pk)
    fig_bytes_dir(pk)
    fig_stages(http)
    print(f"figures -> {OUT}")


if __name__ == "__main__":
    main()
