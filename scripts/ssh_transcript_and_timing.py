#!/usr/bin/env python3
"""
Produce a JSON transcript of SSH packets from a pcap and compute inter-packet
delay statistics per direction for timing-model calibration.

Outputs:
 - scripts/ssh_transcript.json
 - scripts/ssh_timing_stats.json

"""
import sys
import json
from pathlib import Path
from statistics import mean, pstdev

try:
    from scapy.all import rdpcap, TCP, IP
except Exception:
    print("scapy required: pip install scapy", file=sys.stderr)
    raise

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "src" / "backend"
sys.path.insert(0, str(BACKEND))

try:
    import decoders.ssh as ssh_decoder
except Exception as e:
    print("Failed to import decoders.ssh:", e, file=sys.stderr)
    raise


def preview_payload(b):
    if not b:
        return ""
    try:
        text = b.decode("utf-8", errors="ignore")
        # If it contains mostly printable, return text snippet
        printable = sum(1 for ch in text if 32 <= ord(ch) <= 126)
        if printable / max(1, len(text)) > 0.6:
            return text[:200]
    except Exception:
        pass
    return b.hex()[:200]


def find_ssh_flow(pkts):
    # Prefer identification banner to pick client/server.
    for pkt in pkts:
        if not pkt.haslayer(TCP):
            continue
        payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
        res = ssh_decoder.decodeSSH(payload, srcPort=int(pkt[TCP].sport), dstPort=int(pkt[TCP].dport))
        if res and res.get("ssh.type") == "Identification":
            # If direction string mentions Client/Server use that mapping
            direction = res.get("ssh.direction", "Unknown")
            if direction.startswith("Client"):
                return (pkt[IP].src, int(pkt[TCP].sport)), (pkt[IP].dst, int(pkt[TCP].dport))
            if direction.startswith("Server"):
                return (pkt[IP].dst, int(pkt[TCP].dport)), (pkt[IP].src, int(pkt[TCP].sport))
    # Fallback: find first packet with port 22
    for pkt in pkts:
        if not pkt.haslayer(TCP):
            continue
        s = int(pkt[TCP].sport); d = int(pkt[TCP].dport)
        if s == 22 or d == 22 or s == 2222 or d == 2222:
            if d in (22, 2222):
                return (pkt[IP].src, s), (pkt[IP].dst, d)
            return (pkt[IP].dst, d), (pkt[IP].src, s)
    return None, None


def main(pcap_path):
    p = Path(pcap_path)
    if not p.exists():
        print("PCAP not found:", p, file=sys.stderr)
        sys.exit(2)

    pkts = rdpcap(str(p))
    print(f"Read {len(pkts)} packets")

    client, server = find_ssh_flow(pkts)
    if not client or not server:
        print("Failed to identify SSH flow (no port 22/2222 or banners found)")
        sys.exit(3)

    client_ip, client_port = client
    server_ip, server_port = server
    print(f"Identified flow: client={client_ip}:{client_port} server={server_ip}:{server_port}")

    entries = []
    for i, pkt in enumerate(pkts, start=1):
        if not pkt.haslayer(TCP):
            continue
        t = pkt[TCP]
        payload = bytes(t.payload) if t.payload else b""
        if not payload:
            continue
        src = pkt[IP].src; dst = pkt[IP].dst
        sport = int(t.sport); dport = int(t.dport)
        dirstr = None
        if (src, sport) == (client_ip, client_port) and (dst, dport) == (server_ip, server_port):
            dirstr = "C->S"
        elif (src, sport) == (server_ip, server_port) and (dst, dport) == (client_ip, client_port):
            dirstr = "S->C"
        else:
            continue

        decoded = ssh_decoder.decodeSSH(payload, srcPort=sport, dstPort=dport) or {}
        entries.append({
            "index": i,
            "time": float(pkt.time),
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "direction": dirstr,
            "len": len(payload),
            "payload_preview": preview_payload(payload),
            "decoded": decoded,
        })

    # Compute inter-packet delays per direction for packets that likely carry keystrokes
    def compute_delays(entries, direction_filter):
        times = [e["time"] for e in entries if e["direction"] == direction_filter]
        if len(times) < 2:
            return {"count": len(times), "mean_ms": None, "std_ms": None}
        deltas_ms = [ (times[i+1]-times[i]) * 1000.0 for i in range(len(times)-1) ]
        return {"count": len(deltas_ms), "mean_ms": mean(deltas_ms), "std_ms": pstdev(deltas_ms) if len(deltas_ms)>1 else 0.0, "deltas_ms": deltas_ms}

    stats = {
        "client_to_server": compute_delays(entries, "C->S"),
        "server_to_client": compute_delays(entries, "S->C"),
        "total_packets": len(entries),
    }

    out_transcript = ROOT / "scripts" / "ssh_transcript.json"
    out_stats = ROOT / "scripts" / "ssh_timing_stats.json"
    out_transcript.write_text(json.dumps({"flow": {"client": {"ip": client_ip, "port": client_port}, "server": {"ip": server_ip, "port": server_port}}, "packets": entries}, indent=2))
    # Don't dump giant delta arrays into stats file's top-level; keep them but okay
    out_stats.write_text(json.dumps(stats, indent=2))

    print(f"Wrote {out_transcript} and {out_stats}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", default=str(Path(__file__).resolve().parents[1] / "ssh-session-oxasploits.com.pcap"))
    args = ap.parse_args()
    main(args.pcap)
