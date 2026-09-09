#!/usr/bin/env python3
"""
ocsvm_diagnostic.py -- diagnose why One-Class SVM AUC < 0.5 (reviewer T7).

Context: in gen_final.py the OCSVM anomaly score uses -decision_function (higher
= more anomalous), the SAME convention as LOF, and LOF scores correctly (>0.5).
So AUC 0.228 is NOT a simple sign inversion. This script tests whether it is
CONFIG-FRAGILITY (RobustScaler + gamma='scale' wrapping covert points inside the
one-class boundary) or a GENUINE failure, by sweeping scaler x nu x gamma and
reporting AUC for each. AUC here is threshold-independent and computed with the
score oriented so higher = more anomalous (malicious = positive).

Honest use: report the measured AUC of the config you actually use. Do NOT invert
a sub-0.5 detector to fake a >0.5 number. If AUC stays <0.5 across configs, OCSVM
is unsuitable here (report as a negative result). If a config crosses >0.5, use it
and note the sensitivity.

Usage:
  python ocsvm_diagnostic.py --normal normal_mawi.csv --malicious malicious.csv \
      --max_fit 50000
Dependencies: numpy pandas scikit-learn
"""
import argparse, numpy as np, pandas as pd, warnings
from sklearn.preprocessing import RobustScaler, MinMaxScaler, StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

FEATURES = ["PadN_norm","PadN_nonzero","FL_norm","FL_entropy","FL_bit_variance","IAT_norm"]

def flow_bit_stats(vals):
    v=np.asarray(vals).astype(np.uint32)
    bits=np.unpackbits(v.view(np.uint8).reshape(-1,4),axis=1)
    p=bits.sum(axis=1).astype(float)/20.0
    with np.errstate(divide="ignore",invalid="ignore"):
        ent=-(p*np.log2(p)+(1-p)*np.log2(1-p))
    return np.nan_to_num(ent), p*(1-p)

def build(df):
    df.columns=[c.strip() for c in df.columns]
    fl=df["Flow_Label_Value"].to_numpy()
    padn=(df["PadN_Length"].to_numpy() if "PadN_Length" in df.columns
          else np.zeros(len(df)))
    iat=df["IAT"].to_numpy()
    ent,var=flow_bit_stats(fl)
    return np.column_stack([padn.astype(float),(padn>0).astype(float),
                            fl.astype(float),ent,var,iat.astype(float)])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--normal",required=True)
    ap.add_argument("--malicious",required=True)
    ap.add_argument("--max_fit",type=int,default=50000)
    ap.add_argument("--seed",type=int,default=42)
    a=ap.parse_args(); warnings.filterwarnings("ignore")

    Xb=build(pd.read_csv(a.normal)); Xm=build(pd.read_csv(a.malicious))
    rng=np.random.default_rng(a.seed)
    # benign train (fit) + held-out benign/malicious for AUC
    btr,bte=train_test_split(np.arange(len(Xb)),test_size=0.2,random_state=a.seed)
    fit_idx=rng.choice(btr,min(a.max_fit,len(btr)),replace=False)
    y=np.r_[np.zeros(len(bte)),np.ones(len(Xm))]

    scalers={"RobustScaler":RobustScaler,"MinMaxScaler":MinMaxScaler,
             "StandardScaler":StandardScaler}
    print(f"{'scaler':>14} {'nu':>6} {'gamma':>8} {'AUC(anomaly)':>13}")
    best=None
    for sname,S in scalers.items():
        sc=S().fit(Xb[fit_idx])
        Xfit=sc.transform(Xb[fit_idx])
        Xeval=np.vstack([sc.transform(Xb[bte]),sc.transform(Xm)])
        for nu in (0.01,0.05,0.1):
            for gamma in ("scale","auto",0.1,1.0):
                try:
                    oc=OneClassSVM(kernel="rbf",nu=nu,gamma=gamma).fit(Xfit)
                    s=-oc.decision_function(Xeval)   # higher=more anomalous
                    auc=roc_auc_score(y,s)
                except Exception as e:
                    auc=float("nan")
                print(f"{sname:>14} {nu:>6} {str(gamma):>8} {auc:>13.4f}")
                if not np.isnan(auc) and (best is None or auc>best[-1]):
                    best=(sname,nu,gamma,auc)
    print("\nBEST CONFIG:", best)
    print("Interpretation:")
    print("  * best AUC > 0.5  -> config-fragility; adopt this config, report it,")
    print("    and note OCSVM's sensitivity to scaling/gamma.")
    print("  * best AUC still < 0.5 across all -> OCSVM genuinely unsuitable on")
    print("    this feature space; report as an honest negative (do NOT invert).")

if __name__=="__main__":
    main()