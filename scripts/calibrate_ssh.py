#!/usr/bin/env python3
"""
Simple calibration script: read a pcap and run the backend SSH decoder
for each TCP payload on port 22/2222, printing results for manual inspection.
"""
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP
except Exception as e:
    print("scapy is required. Install with: pip install scapy", file=sys.stderr)
    raise

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "src" / "backend"
sys.path.insert(0, str(BACKEND))

try:
    import decoders.ssh as ssh_decoder
except Exception as e:
    print("Failed to import decoders.ssh:", e, file=sys.stderr)
    raise


def extract_tcp_payload(pkt):
    if not pkt.haslayer(TCP):
        return None, None, None
    t = pkt[TCP]
    payload = bytes(t.payload) if t.payload else b""
    sport = int(t.sport)
    dport = int(t.dport)
    return payload, sport, dport


def main(pcap_path):
    p = Path(pcap_path)
    if not p.exists():
        print("PCAP not found:", p, file=sys.stderr)
        sys.exit(2)

    pkts = rdpcap(str(p))
    print(f"Read {len(pkts)} packets from {p}")

    for i, pkt in enumerate(pkts, start=1):
        try:
            payload, sport, dport = extract_tcp_payload(pkt)
            if payload is None or len(payload) == 0:
                continue
            # Only examine SSH candidate ports to reduce noise
            if sport not in (22, 2222) and dport not in (22, 2222):
                # still try: if payload starts with SSH- treat it
                if not payload.startswith(b"SSH-"):
                    continue

            res = ssh_decoder.decodeSSH(payload, srcPort=sport, dstPort=dport)
            if res:
                print("--- Packet", i, f"sport={sport} dport={dport}")
                for k, v in res.items():
                    print(f"{k}: {v}")
                print()
        except Exception as e:
            print(f"Error processing packet {i}: {e}", file=sys.stderr)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", default=str(Path(__file__).resolve().parents[1] / "ssh-session-oxasploits.com.pcap"))
    args = ap.parse_args()
    main(args.pcap)
