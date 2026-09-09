#!/usr/bin/env python3
"""
gen_covert.py -- generate covert Flow-Label/IAT bases for two reviewer experiments:

  (A) GENERATOR COMPARISON (reviewer M1/T4): --prng {mt,csprng}
      * mt     : Python's Mersenne Twister (what sender.py actually uses; the
                 paper's "LCG" claim is incorrect and should be fixed).
      * csprng : a keyed SHA-256 counter stream (cryptographic-quality,
                 unpredictable without the key), reproducible from --seed.
      Both draw Flow Labels ~uniform on [0,2^20). Hypothesis: per-covert-packet
      detectability is ~identical, because detection comes from the marginal
      MISMATCH with benign (uniform vs. benign's zero-heavy distribution), not
      from any generator-specific low-bit structure that per-packet features
      cannot see. If confirmed, the defensive result is NOT a generator artifact.

  (B) REAL MARGINAL-MATCHING ADVERSARY (stronger than the duty-cycle model):
      --mimic-mode marginal --mimic-bits k --normal <benign csv>
      Instead of copying whole benign packets (duty-cycle), EVERY covert packet
      carries k bits while its Flow Label is drawn to MATCH the benign empirical
      marginal: benign Flow-Label values are split into 2^k equal-mass quantile
      bins; the k payload bits select a bin; a benign value is sampled from it.
      IAT is likewise sampled from the benign empirical distribution. Each packet
      is thus individually benign-plausible yet carries covert bits. This lets us
      test whether per-covert-packet detectability drops (genuine per-packet
      evasion) and at what capacity cost (effective capacity <= H(benign FL)).

Output columns: Flow_Label_Value, PadN_Length(=0), IAT, Session_ID
"""
import argparse, csv, hashlib, random
import numpy as np
import pandas as pd

FL_BITS = 20
FL_MOD = 1 << FL_BITS      # 2^20


def csprng_fl(key, sid, i):
    h = hashlib.sha256(f"{key}:{sid}:{i}".encode()).digest()
    return int.from_bytes(h[:4], "big") % FL_MOD


def load_benign(path):
    df = pd.read_csv(path); df.columns = [c.strip() for c in df.columns]
    return (df["Flow_Label_Value"].to_numpy(),
            df["IAT"].to_numpy() if "IAT" in df.columns else None)


def build_marginal_bins(benign_fl, k):
    """2^k contiguous equal-mass quantile bins of benign Flow-Label values."""
    vals = np.sort(benign_fl)
    return [b for b in np.array_split(vals, 2 ** k) if len(b) > 0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions", type=int, default=1200)
    ap.add_argument("--seed", type=int, default=1114)
    ap.add_argument("--prng", choices=["mt", "csprng"], default="mt")
    ap.add_argument("--mimic-mode", choices=["none", "marginal"], default="none")
    ap.add_argument("--mimic-bits", type=int, default=4)
    ap.add_argument("--normal", default=None, help="benign csv (marginal mode)")
    ap.add_argument("--iat-mean", type=float, default=0.02)
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=40)
    a = ap.parse_args()

    rng_len = random.Random(f"{a.seed}:lengths")
    ben_fl = ben_iat = bins = None
    if a.mimic_mode == "marginal":
        if not a.normal:
            raise SystemExit("--mimic-mode marginal requires --normal")
        ben_fl, ben_iat = load_benign(a.normal)
        bins = build_marginal_bins(ben_fl, a.mimic_bits)

    n_rows, uniq = 0, set()
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Flow_Label_Value", "PadN_Length", "IAT", "Session_ID"])
        for sid in range(a.sessions):
            srng = random.Random(f"{a.seed}:{sid}")           # MT stream
            nrng = np.random.default_rng(abs(hash((a.seed, sid))) % (2**32))
            L = rng_len.randint(a.min_len, a.max_len)
            for i in range(L):
                if a.mimic_mode == "marginal":
                    sym = srng.randrange(len(bins))            # k payload bits
                    fl = int(nrng.choice(bins[sym]))           # benign-like value
                    iat = float(nrng.choice(ben_iat)) if ben_iat is not None \
                        else srng.expovariate(1.0 / a.iat_mean)
                else:
                    fl = (csprng_fl(a.seed, sid, i) if a.prng == "csprng"
                          else srng.randint(0, FL_MOD - 2))
                    iat = 0.0 if i == 0 else srng.expovariate(1.0 / a.iat_mean)
                w.writerow([fl, 0, f"{iat:.6f}", sid])
                uniq.add(fl); n_rows += 1

    print(f"[+] wrote {a.out}")
    print(f"    rows={n_rows} sessions={a.sessions} unique_FL={len(uniq)}")
    print(f"    prng={a.prng} mimic_mode={a.mimic_mode}"
          + (f" mimic_bits={a.mimic_bits}" if a.mimic_mode == "marginal" else ""))
    if a.mimic_mode == "marginal":
        # effective capacity is bounded by benign FL entropy; report emitted entropy
        emitted = pd.read_csv(a.out)["Flow_Label_Value"].to_numpy()
        vals, cnts = np.unique(emitted, return_counts=True)
        p = cnts / cnts.sum(); ent = float(-(p * np.log2(p)).sum())
        print(f"    nominal bits/packet={a.mimic_bits}; emitted FL entropy"
              f"={ent:.2f} bits (effective capacity upper bound)")


if __name__ == "__main__":
    main()