#!/usr/bin/env python3
"""
experiment3_deconfounded.py -- fixes the reviewer's C1 (alpha-tautology) and
C2 (missing capacity axis).

THE PROBLEM (reviewer C1): in the duty-cycle model, with probability alpha a
"covert" packet is replaced by a verbatim benign (Flow-Label, IAT) sample that
carries NO covert bits. The original harness still labels those packets positive,
so as alpha->1 the positive class becomes benign and AUC->0.5 is a DEFINITIONAL
artifact, not a detection result.

THE FIX:
  (1) PER-COVERT-PACKET AUC. Evaluate detection ONLY on packets that actually
      carry covert content (the (1-alpha) fraction), vs. benign. This isolates
      "how detectable is a genuinely-covert packet" from "how many packets are
      covert". Expectation: roughly flat in alpha (the covert packets are drawn
      the same way regardless of alpha) -- if so, the honest message is
      "mimicry reduces the NUMBER of detectable packets, not per-packet
      detectability."
  (2) AGGREGATE AUC (as before) reported alongside, so the confound is visible.
  (3) CAPACITY axis (C2): covert packets per session = (1-alpha)*L; bits/packet
      from the channel mode; goodput = bits/packet * covert-packet-rate. At
      alpha=1 capacity=0 -- which is the real reason the aggregate curve falls.

Nothing is fabricated: all AUCs are computed from real scores; capacity is a
closed-form property of the channel (stated, not measured detectability).

Usage (same inputs as before):
  python experiment3_deconfounded.py --normal normal_mawi.csv \
      --malicious malicious_flowlabel.csv --seeds 5 --max_fit 50000 \
      --bits-per-covert-packet 20 --out exp3_deconf
"""
import argparse, json, os, warnings
import numpy as np, pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import roc_auc_score, average_precision_score

FEATURES = ["PadN_norm", "PadN_nonzero", "FL_norm",
            "FL_entropy", "FL_bit_variance", "IAT_norm"]
ALPHAS = [0.0, 0.25, 0.5, 0.75, 0.9, 1.0]


def flow_bit_stats(vals):
    v = np.asarray(vals).astype(np.uint32)
    bits = np.unpackbits(v.view(np.uint8).reshape(-1, 4), axis=1)
    p = bits.sum(axis=1).astype(float) / 20.0
    with np.errstate(divide="ignore", invalid="ignore"):
        ent = -(p * np.log2(p) + (1 - p) * np.log2(1 - p))
    return np.nan_to_num(ent), p * (1 - p)


def feats(fl, padn, iat):
    ent, var = flow_bit_stats(fl)
    return np.column_stack([padn.astype(float), (padn > 0).astype(float),
                            fl.astype(float), ent, var, iat.astype(float)])


def youden(scores, y):
    P, N = y.sum(), len(y) - y.sum()
    if P == 0 or N == 0:
        return float(np.median(scores))
    order = np.argsort(scores); s, yy = scores[order], y[order]
    tp = np.cumsum(yy[::-1])[::-1]; fp = np.cumsum((1 - yy)[::-1])[::-1]
    return float(s[np.argmax(tp / P - fp / N)])


def split3(n, rng, fr=(0.8, 0.1, 0.1)):
    idx = rng.permutation(n); a = int(fr[0] * n); b = int((fr[0] + fr[1]) * n)
    return idx[:a], idx[a:b], idx[b:]


def auc_safe(y, sc):
    return float(roc_auc_score(y, sc)) if len(set(y)) > 1 else float("nan")


def run_seed(nb, cov, seed, max_fit):
    rng = np.random.default_rng(seed)
    ben_fl = nb["Flow_Label_Value"].to_numpy(); ben_iat = nb["IAT"].to_numpy()
    ben_pad = np.zeros(len(nb))
    cov_fl = cov["Flow_Label_Value"].to_numpy(); cov_iat = cov["IAT"].to_numpy()

    btr, bva, bte = split3(len(nb), rng)
    ctr, cva, cte = split3(len(cov), rng)

    # train on benign + alpha=0 covert (PadN abandoned -> pad=0)
    Xtr = np.vstack([feats(ben_fl[btr], ben_pad[btr], ben_iat[btr]),
                     feats(cov_fl[ctr], np.zeros(len(ctr)), cov_iat[ctr])])
    ytr = np.r_[np.zeros(len(btr)), np.ones(len(ctr))]
    scaler = MinMaxScaler().fit(Xtr); Xtr = scaler.transform(Xtr)

    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                random_state=seed, n_jobs=-1).fit(Xtr, ytr)
    bsub = rng.choice(len(btr), min(max_fit, len(btr)), replace=False)
    Xben = scaler.transform(feats(ben_fl[btr][bsub], ben_pad[btr][bsub],
                                  ben_iat[btr][bsub]))
    oc = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(Xben)
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(Xben)

    def score(model, X, kind):
        if kind == "rf":  return model.predict_proba(X)[:, 1]
        return -model.decision_function(X)   # OC-SVM / LOF: higher = more anomalous

    # benign test features (fixed)
    Xbte = scaler.transform(feats(ben_fl[bte], ben_pad[bte], ben_iat[bte]))
    yb = np.zeros(len(bte))

    out = {a: {} for a in ALPHAS}
    for a in ALPHAS:
        n = len(cte)
        is_mimic = rng.random(n) < a               # which covert packets are benign-copies
        bidx = rng.integers(0, len(ben_fl), n)
        fl = np.where(is_mimic, ben_fl[bidx], cov_fl[cte])
        iat = np.where(is_mimic, ben_iat[bidx], cov_iat[cte])
        Xco = scaler.transform(feats(fl, np.zeros(n), iat))

        for name, model, kind in [("RF", rf, "rf"), ("OCSVM", oc, "oc"),
                                  ("LOF", lof, "lof")]:
            sb = score(model, Xbte, kind); sc = score(model, Xco, kind)
            # (a) AGGREGATE: all covert (incl. mimic copies) as positive
            y_agg = np.r_[yb, np.ones(n)]; s_agg = np.r_[sb, sc]
            # (b) PER-COVERT-PACKET: only genuinely-covert packets as positive
            real = ~is_mimic
            y_real = np.r_[yb, np.ones(real.sum())]; s_real = np.r_[sb, sc[real]]
            out[a].setdefault(name, {})
            out[a][name]["AUC_aggregate"] = auc_safe(y_agg, s_agg)
            out[a][name]["AUC_per_covert_packet"] = auc_safe(y_real, s_real)
            out[a][name]["covert_fraction"] = float(real.mean())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", required=True)
    ap.add_argument("--malicious", required=True)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--max_fit", type=int, default=50000)
    ap.add_argument("--benign_cap", type=int, default=0)
    ap.add_argument("--bits-per-covert-packet", type=float, default=20.0,
                    help="covert bits carried by a genuinely-covert packet "
                         "(Flow-Label mode: <=20). Used for the capacity axis.")
    ap.add_argument("--out", default="exp3_deconf")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True); warnings.filterwarnings("ignore")

    nb = pd.read_csv(a.normal); nb.columns = [c.strip() for c in nb.columns]
    if a.benign_cap and a.benign_cap < len(nb):
        nb = nb.sample(a.benign_cap, random_state=0).reset_index(drop=True)
    mb = pd.read_csv(a.malicious); mb.columns = [c.strip() for c in mb.columns]
    cov = mb[["Flow_Label_Value", "IAT"]].drop_duplicates().reset_index(drop=True)

    print("=" * 72)
    print("EXPERIMENT 3 (DE-CONFOUNDED) -- per-covert-packet AUC + capacity")
    print("=" * 72)
    print(f"benign={len(nb):,}  covert-base={len(cov):,}  seeds={a.seeds}")
    print(f"bits/covert-packet (channel property) = {a.bits_per_covert_packet}")
    print("-" * 72)

    runs = [run_seed(nb, cov, s, a.max_fit) for s in range(a.seeds)]

    def agg(a_, model, metric):
        xs = [r[a_][model][metric] for r in runs
              if not np.isnan(r[a_][model][metric])]
        return (float(np.mean(xs)), float(np.std(xs))) if xs else (float("nan"), 0.0)

    result = {"alphas": ALPHAS, "per_seed": runs,
              "bits_per_covert_packet": a.bits_per_covert_packet, "config": vars(a),
              "summary": {}}
    for a_ in ALPHAS:
        result["summary"][str(a_)] = {}
        for m in ("RF", "OCSVM", "LOF"):
            agg_mean, agg_std = agg(a_, m, "AUC_aggregate")
            pcp_mean, pcp_std = agg(a_, m, "AUC_per_covert_packet")
            result["summary"][str(a_)][m] = {
                "AUC_aggregate": {"mean": agg_mean, "std": agg_std},
                "AUC_per_covert_packet": {"mean": pcp_mean, "std": pcp_std}}
        # capacity: expected covert bits per emitted covert-slot = (1-alpha)*bits
        result["summary"][str(a_)]["capacity_bits_per_covert_slot"] = \
            (1.0 - a_) * a.bits_per_covert_packet

    with open(os.path.join(a.out, "experiment3_deconfounded.json"), "w") as f:
        json.dump(result, f, indent=2)

    # print the key contrast for RF
    print(f"{'alpha':>6} {'RF AUC(aggregate)':>18} {'RF AUC(per-covert)':>20} "
          f"{'capacity bits/slot':>20}")
    for a_ in ALPHAS:
        agv = result["summary"][str(a_)]["RF"]["AUC_aggregate"]["mean"]
        pcp = result["summary"][str(a_)]["RF"]["AUC_per_covert_packet"]["mean"]
        cap = result["summary"][str(a_)]["capacity_bits_per_covert_slot"]
        print(f"{a_:>6.2f} {agv:>18.4f} {pcp:>20.4f} {cap:>20.2f}")
    print("\nINTERPRETATION TO VERIFY ON YOUR DATA:")
    print("  * If AUC(per-covert) stays ~flat while AUC(aggregate) falls to 0.5,")
    print("    the honest message is: mimicry lowers covert CAPACITY (bits->0),")
    print("    not per-packet detectability. That de-confounds the C1 critique.")
    print("  * If AUC(per-covert) ALSO falls, then mimicry genuinely hides each")
    print("    covert packet -- a stronger (and still honest) evasion result.")
    print(f"\nsaved -> {os.path.join(a.out,'experiment3_deconfounded.json')}")

if __name__ == "__main__":
    main()