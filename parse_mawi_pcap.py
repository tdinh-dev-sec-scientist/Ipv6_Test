#!/usr/bin/env python3
"""
parse_mawi_pcap.py  (corrected) -- extract IPv6 covert-channel features from a
real MAWI pcap, honestly.

Fixes over the original:
  * IAT keyed on the real 5-tuple flow id (src,dst,proto,sport,dport), NOT the
    Flow Label. Keying on Flow Label is wrong on MAWI, where huge numbers of
    unrelated packets share fl=0. Negative IATs (out-of-order timestamps) are
    clamped to 0 and counted.
  * PadN/Pad1 scanned in BOTH Hop-by-Hop AND Destination Options headers, in
    both Scapy object-form and tuple-form options. The original only looked at
    Destination Options + object-form PadN, so it silently under-counted real
    extension-header usage.
  * Two PadN columns are emitted:
        PadN_Length          = total bytes of PadN option data (padding length)
        PadN_NonzeroContent  = number of NON-ZERO bytes inside PadN data
    This distinction is the whole ballgame: legitimate benign PadN padding is
    all-zero (Length>0 but NonzeroContent==0), whereas the covert channel writes
    encrypted bytes (NonzeroContent>0). Reporting only "Length>0" would conflate
    the two.
  * Drops are COUNTED and categorised, not silently swallowed, so you can report
    exactly what fraction of traffic was discarded and why.
  * A Session_ID (per 5-tuple flow) is emitted for session-safe splitting.

At the end it prints the single diagnostic that settles the paper's framing:
the fraction of IPv6 packets carrying non-zero PadN CONTENT in real traffic.

Output columns: Flow_Label_Value, PadN_Length, PadN_NonzeroContent, IAT, Session_ID

Usage:
    python parse_mawi_pcap.py --pcap 202604301400.pcap.gz --out normal_mawi.csv \
        --max-packets 1000000
"""
import argparse
import csv
from collections import Counter

from scapy.all import PcapReader, IPv6, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop
from scapy.packet import Packet


def scan_padn(pkt):
    """Return (padn_len, padn_nonzero, saw_pad1, saw_destopt, saw_hbh) across
    every Hop-by-Hop and Destination Options header in the packet."""
    padn_len = 0
    padn_nonzero = 0
    saw_pad1 = False
    saw_destopt = False
    saw_hbh = False

    for hdr_cls in (IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop):
        idx = 1                                    # Scapy getlayer() is 1-indexed
        while True:
            eh = pkt.getlayer(hdr_cls, idx)
            if eh is None:
                break
            if hdr_cls is IPv6ExtHdrDestOpt:
                saw_destopt = True
            else:
                saw_hbh = True
            for opt in getattr(eh, "options", []) or []:
                otype, data = _opt_type_and_data(opt)
                if otype == 1:                     # PadN
                    if data:
                        padn_len += len(data)
                        padn_nonzero += sum(1 for b in bytes(data) if b != 0)
                elif otype == 0:                   # Pad1 (single zero octet)
                    saw_pad1 = True
            idx += 1
    return padn_len, padn_nonzero, saw_pad1, saw_destopt, saw_hbh


def _opt_type_and_data(opt):
    """Normalise object-form and tuple-form Scapy options to (otype, data)."""
    # object form (PadN, Pad1, HBHOptUnknown, ...)
    if hasattr(opt, "otype"):
        data = getattr(opt, "optdata", b"") if hasattr(opt, "optdata") else b""
        return opt.otype, data
    # tuple form: (otype, value) as seen in some Scapy versions
    if isinstance(opt, tuple) and len(opt) >= 2:
        return opt[0], opt[1]
    return None, b""


def flow_key(pkt):
    """5-tuple flow id; falls back to (src,dst,proto) for portless packets."""
    ip6 = pkt[IPv6]
    proto = ip6.nh
    sport = dport = 0
    if pkt.haslayer(TCP):
        proto, sport, dport = 6, pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, sport, dport = 17, pkt[UDP].sport, pkt[UDP].dport
    return (ip6.src, ip6.dst, proto, sport, dport)


def parse(pcap_path, out_csv, max_packets):
    last_ts = {}          # flow_key -> last timestamp
    session_ids = {}      # flow_key -> integer session id
    next_sid = 0

    counts = Counter()
    drop_types = Counter()

    with open(out_csv, "w", newline="") as f, PcapReader(pcap_path) as stream:
        w = csv.writer(f)
        w.writerow(["Flow_Label_Value", "PadN_Length",
                    "PadN_NonzeroContent", "IAT", "Session_ID"])
        for pkt in stream:
            counts["total"] += 1
            try:
                if not pkt.haslayer(IPv6):
                    counts["non_ipv6"] += 1
                    continue
                counts["ipv6"] += 1

                fl = pkt[IPv6].fl
                fk = flow_key(pkt)

                if fk not in session_ids:
                    session_ids[fk] = next_sid
                    next_sid += 1
                sid = session_ids[fk]

                t = float(pkt.time)
                if fk in last_ts:
                    iat = t - last_ts[fk]
                    if iat < 0:
                        iat = 0.0
                        counts["neg_iat_clamped"] += 1
                else:
                    iat = 0.0
                last_ts[fk] = t

                padn_len, padn_nz, pad1, destopt, hbh = scan_padn(pkt)
                if destopt or hbh:
                    counts["with_any_eh"] += 1
                if destopt:
                    counts["with_destopt"] += 1
                if hbh:
                    counts["with_hbh"] += 1
                if padn_len > 0:
                    counts["padn_len_gt0"] += 1
                if padn_nz > 0:
                    counts["padn_nonzero_content"] += 1
                if pad1:
                    counts["with_pad1"] += 1

                w.writerow([fl, padn_len, padn_nz, f"{iat:.6f}", sid])
                counts["written"] += 1

                if counts["written"] % 50000 == 0:
                    print(f"[+] wrote {counts['written']:,} IPv6 rows ...", flush=True)
                if counts["written"] >= max_packets:
                    print("[*] reached --max-packets cap")
                    break
            except Exception as e:              # count, don't silently swallow
                counts["dropped"] += 1
                drop_types[type(e).__name__] += 1
                continue

    _report(out_csv, counts, drop_types)


def _report(out_csv, counts, drop_types):
    ipv6 = max(counts["ipv6"], 1)
    print("\n" + "=" * 64)
    print("EXTRACTION SUMMARY")
    print("=" * 64)
    print(f"  packets read           : {counts['total']:,}")
    print(f"  non-IPv6 skipped        : {counts['non_ipv6']:,}")
    print(f"  IPv6 packets            : {counts['ipv6']:,}")
    print(f"  rows written            : {counts['written']:,}")
    print(f"  dropped (errors)        : {counts['dropped']:,}")
    if drop_types:
        for k, v in drop_types.most_common():
            print(f"      {k}: {v:,}")
    print(f"  negative IAT clamped    : {counts['neg_iat_clamped']:,}")
    print("-" * 64)
    print("  EXTENSION-HEADER / PadN USAGE IN REAL IPv6:")
    print(f"    any extension header  : {counts['with_any_eh']:,} "
          f"({100*counts['with_any_eh']/ipv6:.4f}%)")
    print(f"    Destination Options   : {counts['with_destopt']:,} "
          f"({100*counts['with_destopt']/ipv6:.4f}%)")
    print(f"    Hop-by-Hop Options    : {counts['with_hbh']:,} "
          f"({100*counts['with_hbh']/ipv6:.4f}%)")
    print(f"    Pad1 present          : {counts['with_pad1']:,} "
          f"({100*counts['with_pad1']/ipv6:.4f}%)")
    print(f"    PadN length > 0       : {counts['padn_len_gt0']:,} "
          f"({100*counts['padn_len_gt0']/ipv6:.4f}%)")
    print(f"  >> PadN NON-ZERO content: {counts['padn_nonzero_content']:,} "
          f"({100*counts['padn_nonzero_content']/ipv6:.6f}%)  <-- key diagnostic")
    print("=" * 64)
    print("Interpretation:")
    print("  * PadN non-zero content ~0%  => covert non-zero PadN is genuinely")
    print("    anomalous in real traffic (trivial-separability point, now PROVEN")
    print("    on real data rather than assumed).")
    print("  * PadN non-zero content >0%  => real benign uses non-zero PadN too;")
    print("    the naive channel is NOT trivially separable and the result is")
    print("    materially stronger. Either way, report this number in the paper.")
    print(f"\n[✓] saved -> {out_csv}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="MAWI .pcap or .pcap.gz")
    ap.add_argument("--out", default="normal_mawi.csv")
    ap.add_argument("--max-packets", type=int, default=1_000_000)
    a = ap.parse_args()
    parse(a.pcap, a.out, a.max_packets)