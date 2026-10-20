# Investigation Objectives

Derived from the lab scenario and the brief's core investigation questions.

## Primary questions to answer

1. **Initial access / delivery** — How did the malware arrive? What was the first
   stage and where was it hosted?
2. **Attacker infrastructure** — Which external IP/domain/ports are involved, and
   who owns them?
3. **Payload identification** — What malware is this? Hashes, family, compile time.
4. **Execution technique** — How does it run stealthily (injection, LOLBins)?
5. **Persistence** — What is dropped to disk and how does it survive reboot?
6. **Command & control** — How does the implant communicate post-compromise?
7. **Timeline** — Reconstruct the ordered sequence of events from the capture.

## Mapped to the lab's 7 graded questions

| Objective | Lab question |
|---|---|
| Delivery / first stage | Q1 (first-stage URL) |
| Attacker infrastructure | Q2 (hosting provider) |
| Payload identification | Q3 (SHA256), Q4 (family), Q5 (compile time) |
| Execution technique | Q6 (LOLBin path) |
| Persistence | Q7 (dropped files) |
| C2 + timeline | supported by the network/EDA analysis |

## Success criteria

- All 7 questions answered with evidence references.
- Attack chain reconstructed end-to-end and mapped to MITRE ATT&CK.
- IOCs extracted and risk/mitigations documented.
- Reproducible data pipeline (pcap → CSV → EDA → visualizations).
