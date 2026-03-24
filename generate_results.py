import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (roc_curve, auc, confusion_matrix,
                             classification_report, average_precision_score)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import RobustScaler
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
        vals, counts = np.unique(x, return_counts=True)
        probs = counts / counts.sum()
        return -np.sum(probs * np.log2(probs + 1e-9))
    return series.rolling(window, min_periods=1).apply(_entropy, raw=True)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Constructs feature matrix from raw CSV columns.
    Expects at minimum: Flow_Label_Value, PadN_Length.
    IAT column is optional — synthesized from index if absent.
    """
    out = df.copy()

    # Normalise raw fields (protocol-aware bounds)
    out["FL_norm"]   = out["Flow_Label_Value"] / 1_048_575.0   # 2^20 - 1
    out["PadN_norm"] = out["PadN_Length"]       / 255.0

    # Entropy of Flow Label over a sliding window
    out["FL_entropy"] = rolling_entropy(out["Flow_Label_Value"])

    # Inter-arrival time (seconds); use synthetic 1 ms baseline if absent
    if "IAT" in out.columns:
        out["IAT_norm"] = np.log1p(out["IAT"])   # log-scale for heavy tail
    else:
        out["IAT_norm"] = 0.001   # placeholder

    # PadN anomaly flag: non-zero PadN is already suspicious per RFC 2460
    out["PadN_nonzero"] = (out["PadN_Length"] > 0).astype(float)

    features = ["FL_norm", "PadN_norm", "FL_entropy", "IAT_norm", "PadN_nonzero"]
    return out[features]


# 2. AUTOENCODER BUILDER

def build_autoencoder(input_dim: int) -> tf.keras.Model:
    model = Sequential([
        Input(shape=(input_dim,)),

        # Encoder
        Dense(64, activation="relu"),
        BatchNormalization(),
        Dropout(0.1),
        Dense(32, activation="relu"),
        Dense(16, activation="relu"),   # bottleneck

        # Decoder
        Dense(32, activation="relu"),
        BatchNormalization(),
        Dense(64, activation="relu"),
        Dense(input_dim, activation="linear"),
    ], name="autoencoder")

    model.compile(optimizer="adam", loss="mse")
    return model


# 3. EVALUATION

def youden_threshold(fpr, tpr, thresholds):
    """Optimal threshold via Youden's J statistic."""
    idx = np.argmax(tpr - fpr)
    return thresholds[idx]


def evaluate(name: str, scores: np.ndarray, labels: np.ndarray) -> dict:
    """Compute AUC-ROC, AUC-PR and classification metrics at optimal threshold."""
    fpr, tpr, thresholds = roc_curve(labels, scores)
    roc_auc  = auc(fpr, tpr)
    pr_auc   = average_precision_score(labels, scores)
    thresh   = youden_threshold(fpr, tpr, thresholds)
    preds    = (scores > thresh).astype(int)
    cm       = confusion_matrix(labels, preds)
    report   = classification_report(labels, preds, digits=4, output_dict=True)

    print(f"\n{'─'*50}")
    print(f"  {name}")
    print(f"{'─'*50}")
    print(f"  AUC-ROC : {roc_auc:.4f}  |  AUC-PR : {pr_auc:.4f}")
    print(f"  Threshold (Youden J) : {thresh:.6f}")
    print(f"  Confusion Matrix:\n{cm}")
    print(classification_report(labels, preds, digits=4))

    return dict(name=name, fpr=fpr, tpr=tpr, roc_auc=roc_auc,
                pr_auc=pr_auc, thresh=thresh, cm=cm, report=report)


# 4. CROSS-VALIDATION FOR AUTOENCODER
def cross_validate_autoencoder(X_normal: np.ndarray,
                                X_malicious: np.ndarray,
                                n_splits: int = 5) -> list:
    """
    Stratified k-fold CV: train on normal folds, test on held-out normal +
    all malicious samples. Returns per-fold AUC scores.
    """
    skf    = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=SEED)
    X_all  = np.vstack([X_normal, X_malicious])
    y_all  = np.array([0]*len(X_normal) + [1]*len(X_malicious))
    aucs   = []

    print(f"\n[*] Running {n_splits}-fold CV on Autoencoder...")
    for fold, (train_idx, test_idx) in enumerate(skf.split(X_all, y_all)):
        # Only train on normal samples within the training fold
        train_normal = X_all[train_idx][y_all[train_idx] == 0]

        model = build_autoencoder(X_normal.shape[1])
        es = EarlyStopping(monitor="val_loss", patience=5,
                           restore_best_weights=True, verbose=0)
        model.fit(train_normal, train_normal,
                  epochs=50, batch_size=32,
                  validation_split=0.1,
                  callbacks=[es], verbose=0)

        X_test  = X_all[test_idx]
        y_test  = y_all[test_idx]
        preds   = model.predict(X_test, verbose=0)
        mse     = np.mean((X_test - preds) ** 2, axis=1)
        fold_auc = auc(*roc_curve(y_test, mse)[:2])
        aucs.append(fold_auc)
        print(f"    Fold {fold+1}: AUC = {fold_auc:.4f}")

    print(f"  Mean AUC = {np.mean(aucs):.4f} ± {np.std(aucs):.4f}")
    return aucs


# ══════════════════════════════════════════════════════════════════════════════
# 5. MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 60)
print("  IPv6 Covert Channel Detection — Multi-Model Comparison")
print("=" * 60)

# ── Load data ─────────────────────────────────────────────────────────────────
print("\n[*] Loading datasets...")
normal_df    = pd.read_csv("normal.csv")
malicious_df = pd.read_csv("malicious.csv")

X_normal_raw    = build_features(normal_df)
X_malicious_raw = build_features(malicious_df)

# ── Scale: fit ONLY on training data to prevent leakage ───────────────────────
print("[*] Splitting 80 / 10 / 10 (train / val / test)...")

# Normal traffic: 80% train, 10% val, 10% test
X_norm_train, X_norm_temp = train_test_split(X_normal_raw.values,  test_size=0.20, random_state=SEED)
X_norm_val,   X_norm_test = train_test_split(X_norm_temp,          test_size=0.50, random_state=SEED)

# Malicious traffic: 50% val, 50% test  (never touches training)
X_mal_val, X_mal_test = train_test_split(X_malicious_raw.values,   test_size=0.50, random_state=SEED)

print(f"    Train  : {len(X_norm_train):>6} normal packets")
print(f"    Val    : {len(X_norm_val):>6} normal  +  {len(X_mal_val):>6} malicious")
print(f"    Test   : {len(X_norm_test):>6} normal  +  {len(X_mal_test):>6} malicious")

print("[*] Scaling features (RobustScaler — fit on train only)...")
scaler = RobustScaler()
X_train_scaled  = scaler.fit_transform(X_norm_train)   # ← fit here only
X_val_norm_sc   = scaler.transform(X_norm_val)
X_val_mal_sc    = scaler.transform(X_mal_val)
X_test_norm_sc  = scaler.transform(X_norm_test)
X_test_mal_sc   = scaler.transform(X_mal_test)

# Validation set (threshold selection)
X_val_all  = np.vstack([X_val_norm_sc, X_val_mal_sc])
y_val_all  = np.array([0]*len(X_val_norm_sc) + [1]*len(X_val_mal_sc))

# Test set (final report — opened once at the very end)
X_test_all = np.vstack([X_test_norm_sc, X_test_mal_sc])
y_test_all = np.array([0]*len(X_test_norm_sc) + [1]*len(X_test_mal_sc))

results = []

# ══════════════════════════════════════════════════════════════════════════════
# 5a. Deep Autoencoder
# ══════════════════════════════════════════════════════════════════════════════
print("\n[*] Training Deep Autoencoder (on train set only)...")
ae_model = build_autoencoder(X_train_scaled.shape[1])
es = EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True)
ae_model.fit(X_train_scaled, X_train_scaled,
             epochs=100, batch_size=32,
             validation_split=0.1,       # internal split within train
             callbacks=[es], verbose=1)

# Threshold selection on VALIDATION set
val_scores_ae = np.mean((X_val_all - ae_model.predict(X_val_all, verbose=0))**2, axis=1)
fpr_v, tpr_v, thr_v = roc_curve(y_val_all, val_scores_ae)
ae_thresh = thr_v[np.argmax(tpr_v - fpr_v)]   # Youden's J on val
print(f"[+] Autoencoder threshold (val set): {ae_thresh:.6f}")

# Final evaluation on TEST set (sealed envelope — opened once)
ae_scores = np.mean((X_test_all - ae_model.predict(X_test_all, verbose=0))**2, axis=1)
ae_preds  = (ae_scores > ae_thresh).astype(int)
results.append({
    **evaluate("Deep Autoencoder", ae_scores, y_test_all),
    "thresh": ae_thresh,
})

# Cross-validation (uses full normal+malicious scaled via scaler already fit)
X_normal_scaled    = scaler.transform(X_normal_raw.values)
X_malicious_scaled = scaler.transform(X_malicious_raw.values)
cv_aucs = cross_validate_autoencoder(X_normal_scaled, X_malicious_scaled)

# helper: select threshold on val, evaluate on test
def eval_baseline(name, model, X_val, y_val, X_test, y_test):
    val_sc  = -model.decision_function(X_val)
    fv, tv, thv = roc_curve(y_val, val_sc)
    thresh  = thv[np.argmax(tv - fv)]
    test_sc = -model.decision_function(X_test)
    return {**evaluate(name, test_sc, y_test), "thresh": thresh}

# 5b. Isolation Forest
print("\n[*] Training Isolation Forest...")
iso = IsolationForest(n_estimators=200, contamination="auto",
                      random_state=SEED, n_jobs=-1)
iso.fit(X_train_scaled)
results.append(eval_baseline("Isolation Forest", iso,
                              X_val_all, y_val_all, X_test_all, y_test_all))

# 5c. One-Class SVM
print("\n[*] Training One-Class SVM...")
ocsvm = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
ocsvm.fit(X_train_scaled)
results.append(eval_baseline("One-Class SVM", ocsvm,
                              X_val_all, y_val_all, X_test_all, y_test_all))

# 5d. Local Outlier Factor (novelty mode)
print("\n[*] Training Local Outlier Factor...")
lof = LocalOutlierFactor(n_neighbors=20, novelty=True,
                         contamination=0.05, n_jobs=-1)
lof.fit(X_train_scaled)
results.append(eval_baseline("Local Outlier Factor", lof,
                              X_val_all, y_val_all, X_test_all, y_test_all))


# 6. SUMMARY TABLE
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  {'Method':<25} {'AUC-ROC':>9}  {'AUC-PR':>7}  {'F1 (macro)':>10}")
print("  " + "-" * 55)
for r in results:
    f1 = r["report"]["macro avg"]["f1-score"]
    print(f"  {r['name']:<25} {r['roc_auc']:>9.4f}  {r['pr_auc']:>7.4f}  {f1:>10.4f}")

# 7. VISUALISATIONS
COLORS = ["#2196F3", "#FF5722", "#4CAF50", "#9C27B0"]

# ── 7a. ROC Curves ────────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

ax = axes[0]
for r, c in zip(results, COLORS):
    ax.plot(r["fpr"], r["tpr"], color=c, lw=2,
            label=f"{r['name']} (AUC={r['roc_auc']:.3f})")
ax.plot([0, 1], [0, 1], "k--", lw=1)
ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curves — All Models")
ax.legend(fontsize=9)
ax.grid(alpha=0.3)

# Cross-Validation AUC distribution
ax2 = axes[1]
ax2.boxplot(cv_aucs, vert=True, patch_artist=True,
            boxprops=dict(facecolor="#2196F3", alpha=0.6))
ax2.set_xticks([1])
ax2.set_xticklabels(["Deep Autoencoder"])
ax2.set_ylabel("AUC-ROC")
ax2.set_title(f"5-Fold CV — Autoencoder\n"
              f"Mean={np.mean(cv_aucs):.4f} ± {np.std(cv_aucs):.4f}")
ax2.grid(axis="y", alpha=0.3)

plt.tight_layout()
plt.savefig("roc_and_cv.png", dpi=150)
plt.show()
print("[+] Saved: roc_and_cv.png")

#  Reconstruction Error Distribution (Autoencoder only) 
ae_normal_scores    = ae_scores[y_test_all == 0]
ae_malicious_scores = ae_scores[y_test_all == 1]

plt.figure(figsize=(10, 5))
plt.yscale("log")
bins = np.linspace(0, ae_scores.max(), 60)
plt.hist([ae_normal_scores, ae_malicious_scores], bins=bins,
         label=["Normal Traffic", "Covert PadN Traffic"],
         color=["#4CAF50", "#F44336"], alpha=0.75)
thresh = results[0]["thresh"]
plt.axvline(thresh, color="black", linestyle="--", lw=2,
            label=f"Optimal Threshold = {thresh:.5f}")
plt.xlabel("Reconstruction Error (MSE)")
plt.ylabel("Packet Count (log scale)")
plt.title("Autoencoder: Reconstruction Error Distribution")
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("reconstruction_error.png", dpi=150)
plt.show()
print("[+] Saved: reconstruction_error.png")

# Feature Importance (proxy via Isolation Forest, trained on train set) 
feature_names = ["FL_norm", "PadN_norm", "FL_entropy", "IAT_norm", "PadN_nonzero"]
importances = np.mean([
    tree.feature_importances_ for tree in iso.estimators_
], axis=0)

plt.figure(figsize=(7, 4))
bars = plt.barh(feature_names, importances, color=COLORS[1], alpha=0.8)
plt.xlabel("Mean Feature Importance (Isolation Forest)")
plt.title("Feature Importance for Covert Channel Detection")
plt.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig("feature_importance.png", dpi=150)
plt.show()
print("[+] Saved: feature_importance.png")

print("\n[✓] All evaluations complete.")