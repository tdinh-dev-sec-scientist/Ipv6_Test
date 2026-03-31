"""
IPv6 Covert Channel Detection
=============================================================
Dataset  : normal.csv  /  malicious.csv
           Columns required: Flow_Label_Value, PadN_Length
           Optional column : IAT (inter-arrival time in seconds)

Split    : 80% train | 10% validation | 10% test  (no data leakage)

Models
------
Unsupervised  (train on normal only — anomaly detection)
  U1. Deep Autoencoder
  U2. Isolation Forest
  U3. One-Class SVM
  U4. Local Outlier Factor

Supervised    (train on labeled normal + malicious — classification)
  S1. Random Forest
  S2. Support Vector Machine (RBF kernel)

Outputs
-------
  confusion_matrices.png          — 2×3 grid of colour-coded CMs
  roc_curves.png                  — all 6 ROC curves on one axes
  reconstruction_error_dist.png   — autoencoder MSE histogram
  feature_importance.png          — RF feature importance bar chart
  results_summary.csv             — per-model metrics table
"""

# Imports 
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_curve, auc, confusion_matrix,
    classification_report, average_precision_score, ConfusionMatrixDisplay
)

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import random
import warnings
warnings.filterwarnings("ignore")

# Reproducibility
SEED = 42
np.random.seed(SEED)
tf.random.set_seed(SEED)
random.seed(SEED)

# 1. FEATURE ENGINEERING
def rolling_entropy(series: pd.Series, window: int = 10) -> pd.Series:
    """Shannon entropy over a rolling window of Flow Label values."""
    def _entropy(x):
        _, counts = np.unique(x, return_counts=True)
        p = counts / counts.sum()
        return -np.sum(p * np.log2(p + 1e-9))
    return series.rolling(window, min_periods=1).apply(_entropy, raw=True)


def build_features(df: pd.DataFrame) -> np.ndarray:
    """
    Build 5-feature matrix from raw CSV.
    Features:
      FL_norm      — Flow Label normalised to [0, 1]  (20-bit max = 1,048,575)
      PadN_norm    — PadN length normalised to [0, 1] (max = 255)
      FL_entropy   — Rolling Shannon entropy of Flow Label (window=10)
      IAT_norm     — log1p(IAT) if column exists, else 0.0
      PadN_nonzero — Binary flag: 1 if PadN > 0 (RFC 2460 violation indicator)
    """
    out = df.copy()
    out["FL_norm"]      = out["Flow_Label_Value"] / 1_048_575.0
    out["PadN_norm"]    = out["PadN_Length"]       / 255.0
    out["FL_entropy"]   = rolling_entropy(out["Flow_Label_Value"])
    out["IAT_norm"]     = np.log1p(out["IAT"]) if "IAT" in out.columns else 0.0
    out["PadN_nonzero"] = (out["PadN_Length"] > 0).astype(float)
    return out[["FL_norm", "PadN_norm", "FL_entropy",
                "IAT_norm", "PadN_nonzero"]].values

FEATURE_NAMES = ["FL_norm", "PadN_norm", "FL_entropy", "IAT_norm", "PadN_nonzero"]

# 2. DATA LOADING AND 80 / 10 / 10 SPLIT
print("=" * 62)
print("  IPv6 Covert Channel Detection — Multi-Model Evaluation")
print("=" * 62)

print("\n[*] Loading datasets...")
normal_df    = pd.read_csv("normal.csv")
malicious_df = pd.read_csv("malicious.csv")

X_normal_raw    = build_features(normal_df)
X_malicious_raw = build_features(malicious_df)

print("[*] Splitting 80 / 10 / 10 (train / val / test)...")

# Normal traffic split
X_norm_train, X_norm_temp = train_test_split(
    X_normal_raw, test_size=0.20, random_state=SEED)
X_norm_val, X_norm_test   = train_test_split(
    X_norm_temp,  test_size=0.50, random_state=SEED)

# Malicious traffic — never in training set
X_mal_val, X_mal_test = train_test_split(
    X_malicious_raw, test_size=0.50, random_state=SEED)

print(f"    Train : {len(X_norm_train):>6} normal")
print(f"    Val   : {len(X_norm_val):>6} normal  + {len(X_mal_val):>6} malicious")
print(f"    Test  : {len(X_norm_test):>6} normal  + {len(X_mal_test):>6} malicious")

# Scale — fit ONLY on training data (no leakage)
print("[*] Scaling features (RobustScaler — fit on train only)...")
scaler = RobustScaler()
X_train_sc   = scaler.fit_transform(X_norm_train)
X_val_norm   = scaler.transform(X_norm_val)
X_val_mal    = scaler.transform(X_mal_val)
X_test_norm  = scaler.transform(X_norm_test)
X_test_mal   = scaler.transform(X_mal_test)

# Assemble val and test sets
X_val_all  = np.vstack([X_val_norm,  X_val_mal])
y_val_all  = np.array([0]*len(X_val_norm)  + [1]*len(X_val_mal))

X_test_all = np.vstack([X_test_norm, X_test_mal])
y_test_all = np.array([0]*len(X_test_norm) + [1]*len(X_test_mal))

# Labelled train set for supervised models
X_sup_train = np.vstack([X_train_sc,
                          scaler.transform(X_malicious_raw[:len(X_norm_train)])])
y_sup_train = np.array([0]*len(X_train_sc) +
                        [1]*len(X_malicious_raw[:len(X_norm_train)]))

# 3. AUTOENCODER DEFINITION
def build_autoencoder(input_dim: int) -> tf.keras.Model:
    model = Sequential([
        Input(shape=(input_dim,)),
        Dense(64, activation="relu"),
        BatchNormalization(),
        Dropout(0.1),
        Dense(32, activation="relu"),
        Dense(16, activation="relu"),   # bottleneck
        Dense(32, activation="relu"),
        BatchNormalization(),
        Dense(64, activation="relu"),
        Dense(input_dim, activation="linear"),
    ], name="autoencoder")
    model.compile(optimizer="adam", loss="mse")
    return model

# 4. SHARED EVALUATION FUNCTION
def evaluate_model(name: str,
                   scores: np.ndarray,
                   labels: np.ndarray,
                   threshold: float) -> dict:
    """
    Compute and print all metrics given anomaly scores and a pre-set threshold.
    Returns a dict suitable for the summary table and plotting.
    """
    preds  = (scores > threshold).astype(int)
    cm     = confusion_matrix(labels, preds)
    report = classification_report(labels, preds, digits=4, output_dict=True)
    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc     = auc(fpr, tpr)
    pr_auc      = average_precision_score(labels, scores)

    print(f"\n{'─'*54}")
    print(f"  {name}")
    print(f"{'─'*54}")
    print(f"  AUC-ROC : {roc_auc:.4f}   AUC-PR : {pr_auc:.4f}")
    print(f"  Threshold used: {threshold:.6f}")
    print(classification_report(labels, preds, digits=4,
                                 target_names=["Normal", "Malicious"]))

    return dict(name=name, fpr=fpr, tpr=tpr,
                roc_auc=roc_auc, pr_auc=pr_auc,
                cm=cm, report=report, threshold=threshold)


def youden_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Find optimal threshold via Youden's J on the provided set."""
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    return float(thresholds[np.argmax(tpr - fpr)])

# 5. TRAIN & EVALUATE ALL MODELS
results = []

# U1. Deep Autoencoder
print("\n[*] [U1] Training Deep Autoencoder (unsupervised)...")
ae = build_autoencoder(X_train_sc.shape[1])
ae.fit(X_train_sc, X_train_sc,
       epochs=100, batch_size=32, validation_split=0.1,
       callbacks=[EarlyStopping(monitor="val_loss", patience=10,
                                restore_best_weights=True)],
       verbose=1)

ae_val_scores  = np.mean((X_val_all  - ae.predict(X_val_all,  verbose=0))**2, axis=1)
ae_test_scores = np.mean((X_test_all - ae.predict(X_test_all, verbose=0))**2, axis=1)
ae_thresh      = youden_threshold(y_val_all, ae_val_scores)
results.append(evaluate_model("Deep Autoencoder (U)",
                               ae_test_scores, y_test_all, ae_thresh))

# U2. Isolation Forest
print("\n[*] [U2] Training Isolation Forest (unsupervised)...")
iso = IsolationForest(n_estimators=200, contamination="auto",
                      random_state=SEED, n_jobs=-1)
iso.fit(X_train_sc)
iso_val  = -iso.decision_function(X_val_all)
iso_test = -iso.decision_function(X_test_all)
results.append(evaluate_model("Isolation Forest (U)",
                               iso_test, y_test_all,
                               youden_threshold(y_val_all, iso_val)))

# U3. One-Class SVM
print("\n[*] [U3] Training One-Class SVM (unsupervised)...")
ocsvm = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
ocsvm.fit(X_train_sc)
ocsvm_val  = -ocsvm.decision_function(X_val_all)
ocsvm_test = -ocsvm.decision_function(X_test_all)
results.append(evaluate_model("One-Class SVM (U)",
                               ocsvm_test, y_test_all,
                               youden_threshold(y_val_all, ocsvm_val)))

# U4. Local Outlier Factor
print("\n[*] [U4] Training Local Outlier Factor (unsupervised)...")
lof = LocalOutlierFactor(n_neighbors=20, novelty=True,
                         contamination=0.05, n_jobs=-1)
lof.fit(X_train_sc)
lof_val  = -lof.decision_function(X_val_all)
lof_test = -lof.decision_function(X_test_all)
results.append(evaluate_model("Local Outlier Factor (U)",
                               lof_test, y_test_all,
                               youden_threshold(y_val_all, lof_val)))

# S1. Random Forest
print("\n[*] [S1] Training Random Forest (supervised)...")
rf = RandomForestClassifier(n_estimators=200, max_depth=None,
                             random_state=SEED, n_jobs=-1)
rf.fit(X_sup_train, y_sup_train)
rf_val_proba  = rf.predict_proba(X_val_all)[:, 1]
rf_test_proba = rf.predict_proba(X_test_all)[:, 1]
results.append(evaluate_model("Random Forest (S)",
                               rf_test_proba, y_test_all,
                               youden_threshold(y_val_all, rf_val_proba)))

# S2. SVM (RBF)
print("\n[*] [S2] Training SVM — RBF kernel (supervised)...")
svm = SVC(kernel="rbf", C=1.0, gamma="scale",
          probability=True, random_state=SEED)
svm.fit(X_sup_train, y_sup_train)
svm_val_proba  = svm.predict_proba(X_val_all)[:, 1]
svm_test_proba = svm.predict_proba(X_test_all)[:, 1]
results.append(evaluate_model("SVM — RBF (S)",
                               svm_test_proba, y_test_all,
                               youden_threshold(y_val_all, svm_val_proba)))

# 6. SUMMARY TABLE + CSV

print("\n" + "=" * 62)
print("  RESULTS SUMMARY (test set)")
print("=" * 62)
header = f"  {'Model':<26} {'Type':<12} {'AUC-ROC':>8}  {'AUC-PR':>7}  {'F1':>7}  {'Recall':>7}  {'Prec':>7}"
print(header)
print("  " + "─" * 72)

rows = []
for r in results:
    t     = "Supervised" if "(S)" in r["name"] else "Unsupervised"
    f1    = r["report"]["macro avg"]["f1-score"]
    rec   = r["report"]["1"]["recall"]
    prec  = r["report"]["1"]["precision"]
    print(f"  {r['name']:<26} {t:<12} {r['roc_auc']:>8.4f}  "
          f"{r['pr_auc']:>7.4f}  {f1:>7.4f}  {rec:>7.4f}  {prec:>7.4f}")
    rows.append(dict(Model=r["name"], Type=t,
                     AUC_ROC=round(r["roc_auc"], 4),
                     AUC_PR=round(r["pr_auc"], 4),
                     F1_macro=round(f1, 4),
                     Recall_attack=round(rec, 4),
                     Precision_attack=round(prec, 4)))

pd.DataFrame(rows).to_csv("results_summary.csv", index=False)
print("\n[+] Saved: results_summary.csv")

# 7. FIGURE 1 — Confusion Matrices (2 × 3 grid)
print("\n[*] Generating confusion matrix figure...")

fig, axes = plt.subplots(2, 3, figsize=(14, 9))
axes = axes.flatten()
CMAPS = ["Blues", "Blues", "Blues", "Blues", "Greens", "Greens"]

for ax, r, cmap in zip(axes, results, CMAPS):
    disp = ConfusionMatrixDisplay(
        confusion_matrix=r["cm"],
        display_labels=["Normal", "Malicious"]
    )
    disp.plot(ax=ax, cmap=cmap, colorbar=False)

    # Style
    ax.set_title(r["name"], fontsize=11, fontweight="bold", pad=8)
    ax.set_xlabel("Predicted Label", fontsize=9)
    ax.set_ylabel("True Label", fontsize=9)
    ax.tick_params(labelsize=9)

    # Annotate with key metrics
    f1  = r["report"]["macro avg"]["f1-score"]
    rec = r["report"]["1"]["recall"]
    ax.text(0.98, 0.02,
            f"AUC={r['roc_auc']:.3f}  F1={f1:.3f}\nRecall(attack)={rec:.3f}",
            transform=ax.transAxes,
            ha="right", va="bottom", fontsize=8,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.7))

    # Label: U / S badge
    badge = "Supervised" if "(S)" in r["name"] else "Unsupervised"
    badge_color = "#d4edda" if "(S)" in r["name"] else "#cce5ff"
    ax.text(0.02, 0.98, badge,
            transform=ax.transAxes,
            ha="left", va="top", fontsize=8,
            bbox=dict(boxstyle="round,pad=0.3", fc=badge_color, alpha=0.9))

#plt.suptitle(
   # "Confusion Matrices — IPv6 Covert Channel Detection\n"
    #"(Test Set, 80/10/10 Split, Threshold via Youden's J on Validation Set)",
  #fontsize=13, fontweight="bold", y=1.01
#)
plt.tight_layout()
plt.savefig("confusion_matrices.png", dpi=150, bbox_inches="tight")
plt.show()
print("[+] Saved: confusion_matrices.png")

# 8. FIGURE 2 — ROC Curves (all models)
print("[*] Generating ROC curve figure...")

COLORS_U = ["#1565C0", "#0288D1", "#00838F", "#00695C"]   # blues/teals = unsupervised
COLORS_S = ["#2E7D32", "#558B2F"]                          # greens = supervised
COLORS   = COLORS_U + COLORS_S
STYLES   = ["-", "--", "-.", ":", "-", "--"]

fig, ax = plt.subplots(figsize=(7, 6))
for r, c, ls in zip(results, COLORS, STYLES):
    label = f"{r['name']}  (AUC={r['roc_auc']:.3f})"
    ax.plot(r["fpr"], r["tpr"], color=c, lw=2, linestyle=ls, label=label)

ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random classifier")
ax.set_xlabel("False Positive Rate", fontsize=11)
ax.set_ylabel("True Positive Rate", fontsize=11)
ax.set_title("ROC Curves — All Models\n(U = Unsupervised, S = Supervised)",
             fontsize=12, fontweight="bold")
ax.legend(fontsize=8.5, loc="lower right")
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("roc_curves.png", dpi=150)
plt.show()
print("[+] Saved: roc_curves.png")

# 9. FIGURE 3 — Autoencoder Reconstruction Error Distribution
print("[*] Generating reconstruction error distribution...")

norm_scores = ae_test_scores[y_test_all == 0]
mal_scores  = ae_test_scores[y_test_all == 1]

fig, ax = plt.subplots(figsize=(10, 5))
ax.set_yscale("log")
bins = np.linspace(0, ae_test_scores.max(), 60)
ax.hist([norm_scores, mal_scores], bins=bins, alpha=0.75,
        label=["Normal Traffic", "Covert PadN Traffic"],
        color=["#1565C0", "#C62828"])
ax.axvline(ae_thresh, color="black", linestyle="--", lw=2,
           label=f"Optimal Threshold = {ae_thresh:.5f}")
ax.set_xlabel("Reconstruction Error (MSE)", fontsize=11)
ax.set_ylabel("Packet Count (log scale)", fontsize=11)
ax.set_title("Deep Autoencoder: Reconstruction Error Distribution\n"
             "(Test Set — IPv6 Covert Channel)", fontsize=12, fontweight="bold")
ax.legend(fontsize=10)
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("reconstruction_error_dist.png", dpi=150)
plt.show()
print("[+] Saved: reconstruction_error_dist.png")

# 10. FIGURE 4 — Random Forest Feature Importance
print("[*] Generating feature importance chart...")

importances = rf.feature_importances_
sorted_idx  = np.argsort(importances)

fig, ax = plt.subplots(figsize=(7, 4))
bars = ax.barh(
    [FEATURE_NAMES[i] for i in sorted_idx],
    importances[sorted_idx],
    color="#2E7D32", alpha=0.82
)
ax.bar_label(bars, fmt="%.3f", padding=3, fontsize=9)
ax.set_xlabel("Feature Importance (Gini)", fontsize=11)
ax.set_title("Random Forest — Feature Importance\nfor IPv6 Covert Channel Detection",
             fontsize=12, fontweight="bold")
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig("feature_importance.png", dpi=150)
plt.show()
print("[+] Saved: feature_importance.png")


print("\n[✓] Evaluation complete.")
print("    Output files:")
print("      confusion_matrices.png")
print("      roc_curves.png")
print("      reconstruction_error_dist.png")
print("      feature_importance.png")
print("      results_summary.csv")