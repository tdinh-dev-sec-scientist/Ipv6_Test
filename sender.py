#!/usr/bin/env python3
"""
sender.py — Invisible Tunnel C2 sender + covert-dataset generator.

TWO MODES
=========
(1) LIVE C2 DEMO  (default): interactive sender that transmits a command over
    the PadN / Flow-Label covert channel to receiver.py. Requires scapy + root.
    The live demo re-seeds the PRNG per message so receiver.py can
    resynchronise. That re-seed is a DEMONSTRATION artifact and MUST NOT be used
    to build the research dataset: because every message replays the same
    sequence from SEED_VAL, the captured Flow Labels collapse to only a few
    dozen unique values across the whole run (the artifact the reviewers can
    fingerprint).

(2) DATASET GENERATION  (--generate): writes a covert-traffic CSV directly with
      * a PER-SESSION PRNG seeded from (seed, session_id) that advances per
        packet and is NEVER re-seeded mid-session  -> Flow Labels are diverse
        and non-repeating within a session and differ across sessions;
      * a Session_ID column so train/val/test splits can be session-safe;
      * --padn-mode {on,off}: carry the byte in PadN, or abandon PadN and hide
        only in Flow Label + timing (the channel used by the adaptive study);
      * --mimic-alpha F: optionally replace a fraction of covert (Flow_Label,IAT)
        pairs with real benign samples (needs --normal). Use 0.0 for the
        un-adapted base — the alpha SWEEP itself lives in
        experiment3_adaptive.py, so do not bake alpha in here for that study.

    This CSV path is decoupled from receiver.py on purpose (so we don't silently
    desynchronise the live decoder), and it is the scientifically controlled
    artifact used by gen_final.py / experiment3_adaptive.py.

All randomness is seeded from --seed (default 1114) for reproducibility.
Columns written by --generate: Flow_Label_Value, PadN_Length, IAT, Session_ID
"""
import argparse
import csv
import random

# --- Protocol constants (shared with receiver.py) ---
TARGET_IP      = "::1"
ENCRYPTION_KEY = 0x55
TRIGGER_CHAR   = ";"
SEED_VAL       = 1114
SYNC_ID        = 0xFFFFF          # reserved 20-bit Flow-Label value for burst-sync
FL_MAX         = 0xFFFFE          # covert Flow Labels drawn from [0, FL_MAX]
INTER_PACKET   = 0.02             # live-demo send cadence (seconds)


# ===========================================================================
# (1) LIVE C2 DEMO  — unchanged protocol; scapy imported lazily
# ===========================================================================
def craft_stealth_packet(char_byte, flow_label_magic):
    from scapy.all import IPv6, TCP, PadN, IPv6ExtHdrDestOpt
    encrypted_byte  = bytes([char_byte ^ ENCRYPTION_KEY])
    covert_padn     = PadN(optdata=encrypted_byte)
    dest_opt_header = IPv6ExtHdrDestOpt(options=[covert_padn])
    return (IPv6(dst=TARGET_IP, fl=flow_label_magic) /
            dest_opt_header /
            TCP(dport=443, flags="S"))


def send_covert_traffic(cmd):
    import time
    from scapy.all import send
    full_message = cmd + TRIGGER_CHAR
    print(f"[*] Target: {TARGET_IP}")
    print("[*] Initiating Burst-Sync sequence...")
    for _ in range(3):
        send(craft_stealth_packet(0x00, SYNC_ID), verbose=False)
        time.sleep(INTER_PACKET)
    time.sleep(0.05)

    # NOTE: demo-only re-seed so receiver.py resynchronises. This is exactly the
    # step that must NOT be used for the dataset (see module docstring / --generate).
    random.seed(SEED_VAL)

    print(f"[*] Transmitting Payload: '{cmd}' ...")
    for char in full_message:
        expected_magic = random.randint(0, FL_MAX)
        send(craft_stealth_packet(ord(char), expected_magic), verbose=False)
        time.sleep(INTER_PACKET)
    print("[+] Transmission complete.\n")


def live_repl():
    print("==================================================")
    print("  Academic Sender: Distributed Steganography (LIVE DEMO)")
    print("==================================================")
    print("Type your command. Type 'exit' to quit.\n")
    while True:
        try:
            user_input = input("C2> ")
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break
            send_covert_traffic(user_input)
        except KeyboardInterrupt:
            print("\nExiting...")
            break


# ===========================================================================
# (2) DATASET GENERATION  — the reproducible, session-tagged covert base
# ===========================================================================
def _load_benign_pool(normal_path):
    import pandas as pd
    df = pd.read_csv(normal_path)
    df.columns = [c.strip() for c in df.columns]
    fl  = df["Flow_Label_Value"].to_numpy()
    iat = df["IAT"].to_numpy() if "IAT" in df.columns else None
    return fl, iat


def generate_dataset(out_path, sessions, seed=SEED_VAL, padn_mode="on",
                     mimic_alpha=0.0, normal_path=None,
                     iat_mean=0.02, min_len=4, max_len=40):
    rng_len = random.Random(f"{seed}:lengths")     # message lengths only
    ben_fl = ben_iat = None
    if mimic_alpha > 0.0:
        if not normal_path:
            raise SystemExit("--mimic-alpha > 0 requires --normal <benign csv>")
        ben_fl, ben_iat = _load_benign_pool(normal_path)

    n_rows, uniq = 0, set()
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Flow_Label_Value", "PadN_Length", "IAT", "Session_ID"])
        for sid in range(sessions):
            srng = random.Random(f"{seed}:{sid}")       # independent per-session stream
            msg_len = rng_len.randint(min_len, max_len)
            for i in range(msg_len):
                fl = srng.randint(0, FL_MAX)         # advances every packet
                padn_len = 1 if padn_mode == "on" else 0
                iat = 0.0 if i == 0 else srng.expovariate(1.0 / iat_mean)
                # optional benign mimicry (used only if a fixed-alpha set is wanted)
                if ben_fl is not None and srng.random() < mimic_alpha:
                    j = srng.randrange(len(ben_fl))
                    fl = int(ben_fl[j])
                    if ben_iat is not None:
                        iat = float(ben_iat[j])
                w.writerow([fl, padn_len, f"{iat:.6f}", sid])
                uniq.add(fl)
                n_rows += 1
    print(f"[+] wrote {out_path}")
    print(f"    rows={n_rows}  sessions={sessions}  unique_flow_labels={len(uniq)}")
    print(f"    padn_mode={padn_mode}  mimic_alpha={mimic_alpha}  seed={seed}")


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--generate", action="store_true",
                    help="dataset-generation mode (writes CSV, no scapy/root needed)")
    ap.add_argument("--out", default="malicious.csv")
    ap.add_argument("--sessions", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=SEED_VAL)
    ap.add_argument("--padn-mode", choices=["on", "off"], default="on")
    ap.add_argument("--mimic-alpha", type=float, default=0.0)
    ap.add_argument("--normal", default=None, help="benign csv for --mimic-alpha")
    ap.add_argument("--iat-mean", type=float, default=0.02)
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=40)
    a = ap.parse_args()

    if a.generate:
        generate_dataset(a.out, a.sessions, seed=a.seed, padn_mode=a.padn_mode,
                         mimic_alpha=a.mimic_alpha, normal_path=a.normal,
                         iat_mean=a.iat_mean, min_len=a.min_len, max_len=a.max_len)
    else:
        live_repl()


if __name__ == "__main__":
    main()
