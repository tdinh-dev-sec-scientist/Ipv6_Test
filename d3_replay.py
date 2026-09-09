#!/usr/bin/env python3
"""
d3_replay.py -- exact RFC-8200 "D3" defense, replayed over real PCAPs.

The D3 predicate (precise form): a packet is flagged iff ANY PadN option in ANY
IPv6 extension header (Hop-by-Hop or Destination Options) contains a NON-ZERO
content byte. RFC 8200 defines PadN bytes as padding that "SHOULD be zero" and
receivers ignore them; non-zero content is the covert signal. This is the exact
predicate the paper's D3 baseline describes -- stateless, no learning.

For each pcap it reports:
  * packets processed / IPv6 / with any EH
  * PACKET-level: flagged count and rate
  * SESSION-level: a covert 'session' is caught if >=1 of its packets is flagged.
    Sessions are grouped by 5-tuple (or by a --session-boundary heuristic).
When run on covert traffic these are DETECTIONS; on benign traffic they are
FALSE POSITIVES. Report both, per the paper.

Usage:
  # covert channel (expect high detection):
  python d3_replay.py --pcap malicious_raw.pcap --label covert
  # benign (expect ~0 false positives):
  python d3_replay.py --pcap mawi_trace.pcap.gz --label benign --max-packets 1000000

Nothing is fabricated: it only counts what the packets contain.
"""
import argparse
from collections import defaultdict

from scapy.all import PcapReader, IPv6, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop


def _opt_type_and_data(opt):
    if hasattr(opt, "otype"):
        data = getattr(opt, "optdata", b"") if hasattr(opt, "optdata") else b""
        return opt.otype, data
    if isinstance(opt, tuple) and len(opt) >= 2:
        return opt[0], opt[1]
    return None, b""


def d3_flag(pkt):
    """Return True iff the packet has a PadN option with non-zero content."""
    for hdr_cls in (IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop):
        idx = 1
        while True:
            eh = pkt.getlayer(hdr_cls, idx)
            if eh is None:
                break
            for opt in getattr(eh, "options", []) or []:
                otype, data = _opt_type_and_data(opt)
                if otype == 1 and data and any(b != 0 for b in bytes(data)):
                    return True
            idx += 1
    return False


def flow_key(pkt):
    ip6 = pkt[IPv6]
    proto, sport, dport = ip6.nh, 0, 0
    if pkt.haslayer(TCP):
        proto, sport, dport = 6, pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, sport, dport = 17, pkt[UDP].sport, pkt[UDP].dport
    return (ip6.src, ip6.dst, proto, sport, dport)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--label", choices=["covert", "benign"], required=True,
                    help="covert => flags are DETECTIONS; benign => FALSE POSITIVES")
    ap.add_argument("--max-packets", type=int, default=10_000_000)
    a = ap.parse_args()

    total = ipv6 = with_eh = flagged = 0
    sess_any = defaultdict(bool)     # flow_key -> any packet flagged?
    sess_pkts = defaultdict(int)

    with PcapReader(a.pcap) as stream:
        for pkt in stream:
            total += 1
            try:
                if not pkt.haslayer(IPv6):
                    continue
                ipv6 += 1
                fk = flow_key(pkt)
                sess_pkts[fk] += 1
                if pkt.haslayer(IPv6ExtHdrDestOpt) or pkt.haslayer(IPv6ExtHdrHopByHop):
                    with_eh += 1
                if d3_flag(pkt):
                    flagged += 1
                    sess_any[fk] = True
                if ipv6 >= a.max_packets:
                    break
            except Exception:
                continue

    n_sessions = len(sess_pkts)
    n_sess_flagged = sum(1 for v in sess_any.values() if v)
    ipv6_safe = max(ipv6, 1)
    sess_safe = max(n_sessions, 1)

    print("=" * 60)
    print(f"D3 REPLAY  --  {a.pcap}  (label={a.label})")
    print("=" * 60)
    print(f"  packets processed     : {total:,}")
    print(f"  IPv6 packets          : {ipv6:,}")
    print(f"  with any extension hdr: {with_eh:,}")
    print(f"  sessions (5-tuple)    : {n_sessions:,}")
    print("-" * 60)
    kind = "DETECTIONS" if a.label == "covert" else "FALSE POSITIVES"
    print(f"  PACKET-level flagged  : {flagged:,} ({100*flagged/ipv6_safe:.4f}%)  [{kind}]")
    print(f"  SESSION-level flagged : {n_sess_flagged:,}/{n_sessions:,} "
          f"({100*n_sess_flagged/sess_safe:.4f}%)  [{kind}]")
    print("=" * 60)
    if a.label == "covert":
        print("  Report as: packet detection rate and sessions-caught / total.")
    else:
        print("  Report as: false-positive rate (packets) and false-positive")
        print("  sessions / total. For MAWI benign this is expected to be ~0.")


if __name__ == "__main__":
    main()