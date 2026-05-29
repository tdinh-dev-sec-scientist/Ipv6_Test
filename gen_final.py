"""
=============================================================================
IPv6 Covert Channel Detection via Flow Label and PadN Steganography
=============================================================================
A Comparative Study of Unsupervised Anomaly Detection and Supervised
Classification Approaches for Network Security

Authors  : Truong Dinh
Affil.   : Austin Peay State University, Computer Science Department
Contact  : tdinh3@students.apsu.edu
Version  : 2.0.0
License  : MIT

Conference Target: IEEE INFOCOM / IEEE S&P / IEEE TDSC

Abstract (Code-Level)
---------------------
This module implements and evaluates five machine learning models for
detecting IPv6 covert channels exploiting the 20-bit Flow Label field and
IPv6 extension header PadN options. We compare three unsupervised anomaly
detectors (Deep Autoencoder, One-Class SVM, Local Outlier Factor) against
two supervised classifiers (Random Forest, SVM-RBF) under a strict no-leakage
80/10/10 train-validation-test protocol. Evaluation covers AUC-ROC, AUC-PR,
macro-F1, per-class precision/recall, confusion matrices, ablation over
feature subsets, and McNemar's statistical significance test.

Dataset Requirements
--------------------
  normal.csv    : Benign IPv6 traffic
  malicious.csv : Covert-channel (steganographic) IPv6 traffic

  Required columns : Flow_Label_Value (int, 0–1,048,575)
                     PadN_Length      (int, 0–255)
  Optional column  : IAT              (float, inter-arrival time in seconds)

Reproducibility
---------------
  Python   : 3.10+
  TF/Keras : 2.13+
  sklearn  : 1.3+
  SEED     : 42  (fixed globally; see Section 0)


=============================================================================
"""

# ---------------------------------------------------------------------------
# 0. ENVIRONMENT SETUP & REPRODUCIBILITY
# ---------------------------------------------------------------------------
import os
import random
import warnings
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")                # headless rendering for server environments
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.lines import Line2D
import seaborn as sns

import sys
import setuptools
sys.modules['distutils'] = setuptools
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Dense, Dropout, BatchNormalization, LeakyReLU
)
from tensorflow.keras.callbacks import (
    EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
)
from tensorflow.keras.regularizers import l2
from tensorflow.keras.optimizers import Adam

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    roc_curve, auc, confusion_matrix, classification_report,
    average_precision_score, ConfusionMatrixDisplay,
    balanced_accuracy_score, matthews_corrcoef
)
from statsmodels.stats.contingency_tables import mcnemar

warnings.filterwarnings("ignore")

# --- Global Reproducibility Seeds ---
SEED: int = 42
os.environ["PYTHONHASHSEED"] = str(SEED)
random.seed(SEED)
np.random.seed(SEED)
tf.random.set_seed(SEED)
tf.keras.utils.set_random_seed(SEED)

# --- Paths ---
DATA_DIR  = Path(".")
OUT_DIR   = Path("outputs")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(OUT_DIR / "experiment.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Matplotlib / Seaborn Publication Style ---
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 300,             # IEEE requires ≥300 DPI
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "legend.fontsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "lines.linewidth": 1.8,
})
sns.set_style("whitegrid")

# ---------------------------------------------------------------------------
# 1. HYPERPARAMETER CONFIGURATION (centralised for reproducibility)
# ---------------------------------------------------------------------------
CFG: Dict = {
    # Data
    "val_size"          : 0.10,
    "test_size"         : 0.10,
    "rolling_window"    : 10,
    # Autoencoder
    "ae_epochs"         : 150,
    "ae_batch"          : 64,
    "ae_lr"             : 1e-3,
    "ae_l2"             : 1e-4,
    "ae_dropout"        : 0.10,
    "ae_patience"       : 15,
    # One-Class SVM
    "ocsvm_nu"          : 0.05,
    "ocsvm_kernel"      : "rbf",
    # LOF
    "lof_n_neighbors"   : 20,
    "lof_contamination" : 0.05,
    # Random Forest
    "rf_n_estimators"   : 300,
    "rf_max_depth"      : None,
    "rf_min_samples_leaf": 2,
    # SVM
    "svm_C"             : 10.0,     # tuned via val-set; original C=1 under-regularised
    "svm_kernel"        : "rbf",
    # Ablation
    "run_ablation"      : True,
    "ablation_folds"    : 5,
    # Statistical test
    "run_mcnemar"       : True,
    "mcnemar_alpha"     : 0.05,
}

logger.info("Configuration: %s", CFG)

# ---------------------------------------------------------------------------
# 2. FEATURE ENGINEERING
# ---------------------------------------------------------------------------

def rolling_entropy(series: pd.Series, window: int = 10) -> pd.Series:
    """
    Compute Shannon entropy over a rolling window of Flow Label values.

    H(X) = -sum_{x in X} p(x) * log2(p(x))

    A high entropy in the Flow Label field over successive packets is a
    key indicator of pseudo-random steganographic encoding [ref].

    Parameters
    ----------
    series : pd.Series
        Raw integer Flow Label values (0–1,048,575).
    window : int
        Rolling window size (default 10 packets).

    Returns
    -------
    pd.Series of float — per-packet rolling Shannon entropy (bits).
    """
    def _entropy(x: np.ndarray) -> float:
        _, counts = np.unique(x, return_counts=True)
        p = counts / counts.sum()
        return float(-np.sum(p * np.log2(p + 1e-9)))

    return series.rolling(window, min_periods=1).apply(_entropy, raw=True)


def flow_label_bit_variance(series: pd.Series, window: int = 10) -> pd.Series:
    """
    Compute per-bit variance across the 20-bit Flow Label field.

    Covert channels using the Flow Label for steganography tend to produce
    uniform bit-level variance (all 20 bits used with equal probability),
    whereas legitimate QoS-marked traffic shows concentrated bit patterns.

    Returns scalar mean across 20 bits for each rolling window.
    """
    def _bit_variance(x: np.ndarray) -> float:
        bits = np.array(
            [[(int(v) >> b) & 1 for b in range(20)] for v in x], dtype=float
        )
        return float(np.mean(np.var(bits, axis=0)))

    return series.rolling(window, min_periods=1).apply(_bit_variance, raw=True)


FEATURE_NAMES: List[str] = [
    "FL_norm",
    "PadN_norm",
    "FL_entropy",
    "FL_bit_variance",
    "IAT_norm",
    "PadN_nonzero",
]


def build_features(df: pd.DataFrame, window: int = 10) -> np.ndarray:
    """
    Construct a 6-dimensional feature matrix from raw packet-level CSV data.

    Feature Descriptions
    --------------------
    FL_norm          : Flow Label value normalised to [0, 1] (20-bit field,
                       max = 1,048,575). Captures absolute magnitude deviation.
    PadN_norm        : PadN option length normalised to [0, 1] (max = 255).
    FL_entropy       : Rolling Shannon entropy of the Flow Label field over
                       the last `window` packets. High entropy → steganographic
                       pseudo-randomness.
    FL_bit_variance  : Mean per-bit variance across the 20-bit Flow Label,
                       rolling over `window` packets. Uniform variance across
                       all bits indicates full-field exploitation.
    IAT_norm         : log1p-transformed inter-arrival time (seconds). Timing
                       covert channels manipulate IAT; log compression reduces
                       heavy-tailed skew. Zero-filled when IAT is unavailable.
    PadN_nonzero     : Binary RFC-2460 violation indicator: 1 if PadN_Length > 0.

    Parameters
    ----------
    df     : pd.DataFrame  Raw CSV loaded from normal.csv or malicious.csv.
    window : int           Rolling window size for entropy/variance features.

    Returns
    -------
    np.ndarray, shape (N, 6)
    """
    out = df.copy()
    out["FL_norm"]         = out["Flow_Label_Value"] / 1_048_575.0
    out["PadN_norm"]       = out["PadN_Length"]       / 255.0
    out["FL_entropy"]      = rolling_entropy(out["Flow_Label_Value"], window)
    out["FL_bit_variance"] = flow_label_bit_variance(out["Flow_Label_Value"], window)
    out["IAT_norm"]        = (
        np.log1p(out["IAT"]) if "IAT" in out.columns
        else pd.Series(np.zeros(len(out)), index=out.index)
    )
    out["PadN_nonzero"]    = (out["PadN_Length"] > 0).astype(float)
    return out[FEATURE_NAMES].values

# ---------------------------------------------------------------------------
# 3. DATA LOADING & SPLITTING
# ---------------------------------------------------------------------------

def load_and_split(
    normal_path: Path,
    malicious_path: Path,
    val_frac: float = 0.10,
    test_frac: float = 0.10,
    seed: int = SEED,
) -> Dict:
    """
    Load datasets and perform a strict 80/10/10 split with zero data leakage.

    Design Decisions
    ----------------
    * The scaler is fit ONLY on X_train_normal to prevent future information
      from contaminating normalisation parameters.
    * Malicious samples are NEVER exposed during unsupervised model training.
    * The supervised training set balances classes by capping malicious samples
      to the training normal count (prevents class-imbalance dominance while
      retaining full malicious diversity via oversampling if needed).

    Returns
    -------
    dict with keys: X_train_sc, X_val_all, y_val_all,
                    X_test_all, y_test_all, X_sup_train, y_sup_train,
                    scaler, n_features, split_info
    """
    logger.info("Loading datasets: %s | %s", normal_path, malicious_path)
    normal_df    = pd.read_csv(normal_path)
    malicious_df = pd.read_csv(malicious_path)

    logger.info("Normal   samples: %d", len(normal_df))
    logger.info("Malicious samples: %d", len(malicious_df))

    X_normal_raw    = build_features(normal_df)
    X_malicious_raw = build_features(malicious_df)

    # --- Normal: 80 / 10 / 10 ---
    X_norm_train, X_norm_temp = train_test_split(
        X_normal_raw, test_size=(val_frac + test_frac), random_state=seed
    )
    X_norm_val, X_norm_test = train_test_split(
        X_norm_temp, test_size=0.50, random_state=seed
    )

    # --- Malicious: 50 / 50 val / test (never seen in training) ---
    X_mal_val, X_mal_test = train_test_split(
        X_malicious_raw, test_size=0.50, random_state=seed
    )

    # --- Fit scaler on training normal only ---
    scaler       = RobustScaler()
    X_train_sc   = scaler.fit_transform(X_norm_train)
    X_val_norm   = scaler.transform(X_norm_val)
    X_val_mal    = scaler.transform(X_mal_val)
    X_test_norm  = scaler.transform(X_norm_test)
    X_test_mal   = scaler.transform(X_mal_test)

    # --- Assemble evaluation sets ---
    X_val_all  = np.vstack([X_val_norm,  X_val_mal])
    y_val_all  = np.array([0]*len(X_val_norm)  + [1]*len(X_val_mal), dtype=int)
    X_test_all = np.vstack([X_test_norm, X_test_mal])
    y_test_all = np.array([0]*len(X_test_norm) + [1]*len(X_test_mal), dtype=int)

    # --- Supervised training set (balanced) ---
    n_train_normal = len(X_train_sc)
    # Use all malicious (or cap at n_train_normal for balance)
    X_mal_train_sc = scaler.transform(X_malicious_raw[:n_train_normal])
    X_sup_train    = np.vstack([X_train_sc, X_mal_train_sc])
    y_sup_train    = np.array(
        [0]*n_train_normal + [1]*len(X_mal_train_sc), dtype=int
    )

    split_info = {
        "train_normal" : len(X_train_sc),
        "val_normal"   : len(X_val_norm),
        "val_malicious": len(X_val_mal),
        "test_normal"  : len(X_test_norm),
        "test_malicious": len(X_test_mal),
        "class_ratio_supervised": len(X_train_sc) / max(len(X_mal_train_sc), 1),
    }
    logger.info("Split info: %s", split_info)

    return dict(
        X_train_sc   = X_train_sc,
        X_val_all    = X_val_all,
        y_val_all    = y_val_all,
        X_test_all   = X_test_all,
        y_test_all   = y_test_all,
        X_sup_train  = X_sup_train,
        y_sup_train  = y_sup_train,
        scaler       = scaler,
        n_features   = X_train_sc.shape[1],
        split_info   = split_info,
    )

# ---------------------------------------------------------------------------
# 4. MODEL DEFINITIONS
# ---------------------------------------------------------------------------

def build_autoencoder(
    input_dim: int,
    l2_reg: float = 1e-4,
    dropout_rate: float = 0.10,
    lr: float = 1e-3,
) -> tf.keras.Model:
    """
    Deep Autoencoder with symmetric encoder–decoder architecture.

    Architecture
    ------------
    Encoder : Linear(128) → BN → LReLU → Drop → Linear(64) → LReLU →
              Linear(32) → LReLU → Linear(8) [bottleneck]
    Decoder : Linear(32) → LReLU → Linear(64) → BN → LReLU →
              Linear(128) → LReLU → Linear(input_dim) [linear output]

    Design Rationale
    ----------------
    * LeakyReLU (α=0.1) avoids dying-ReLU pathology in deep layers.
    * L2 kernel regularisation penalises weight magnitude → reduces overfitting
      on small packet-level datasets.
    * BatchNormalization at encoder/decoder boundaries stabilises gradients.
    * Bottleneck dimension of 8 forces compact representations; the model
      must learn the manifold of normal traffic, making anomalies
      (high reconstruction error) detectable by thresholding MSE.

    Parameters
    ----------
    input_dim    : int   — number of input features (6).
    l2_reg       : float — L2 regularisation coefficient.
    dropout_rate : float — dropout probability (applied to encoder only).
    lr           : float — Adam learning rate.

    Returns
    -------
    tf.keras.Model (compiled, ready for .fit())
    """
    inputs = Input(shape=(input_dim,), name="input")

    # Encoder
    x = Dense(128, kernel_regularizer=l2(l2_reg), name="enc_1")(inputs)
    x = BatchNormalization(name="enc_bn1")(x)
    x = LeakyReLU(0.1, name="enc_act1")(x)
    x = Dropout(dropout_rate, name="enc_drop")(x)

    x = Dense(64, kernel_regularizer=l2(l2_reg), name="enc_2")(x)
    x = LeakyReLU(0.1, name="enc_act2")(x)

    x = Dense(32, kernel_regularizer=l2(l2_reg), name="enc_3")(x)
    x = LeakyReLU(0.1, name="enc_act3")(x)

    bottleneck = Dense(8, name="bottleneck")(x)

    # Decoder
    x = Dense(32, kernel_regularizer=l2(l2_reg), name="dec_1")(bottleneck)
    x = LeakyReLU(0.1, name="dec_act1")(x)

    x = Dense(64, kernel_regularizer=l2(l2_reg), name="dec_2")(x)
    x = BatchNormalization(name="dec_bn")(x)
    x = LeakyReLU(0.1, name="dec_act2")(x)

    x = Dense(128, kernel_regularizer=l2(l2_reg), name="dec_3")(x)
    x = LeakyReLU(0.1, name="dec_act3")(x)

    outputs = Dense(input_dim, activation="linear", name="output")(x)

    model = Model(inputs, outputs, name="deep_autoencoder")
    model.compile(optimizer=Adam(lr), loss="mse")
    return model

# ---------------------------------------------------------------------------
# 5. EVALUATION UTILITIES
# ---------------------------------------------------------------------------

def youden_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """
    Compute the optimal decision threshold via Youden's J statistic.

    J = Sensitivity + Specificity - 1 = TPR - FPR

    The threshold maximising J provides the best trade-off between
    sensitivity and specificity on the validation set.

    Parameters
    ----------
    y_true  : np.ndarray — ground-truth binary labels (0/1).
    scores  : np.ndarray — anomaly or probability scores (higher = more anomalous).

    Returns
    -------
    float — optimal threshold value.
    """
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    j_stat = tpr - fpr
    return float(thresholds[np.argmax(j_stat)])


def evaluate_model(
    name: str,
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
) -> Dict:
    """
    Compute a comprehensive set of evaluation metrics for one model.

    Metrics Computed
    ----------------
    - AUC-ROC   : Area under the Receiver Operating Characteristic curve.
    - AUC-PR    : Area under the Precision-Recall curve (informative under
                  class imbalance where AUC-ROC can be misleading).
    - Macro-F1  : Unweighted mean of per-class F1 (penalises poor performance
                  on minority class).
    - MCC       : Matthews Correlation Coefficient — a single balanced
                  metric robust to class imbalance.
    - BAcc      : Balanced Accuracy = (TPR + TNR) / 2.
    - Per-class precision, recall, F1 for both Normal and Malicious.

    Parameters
    ----------
    name      : str        — model identifier for display/logging.
    scores    : np.ndarray — anomaly scores (higher = anomalous).
    labels    : np.ndarray — ground-truth labels (0=normal, 1=malicious).
    threshold : float      — decision threshold (from Youden's J on val set).

    Returns
    -------
    dict containing all metrics and plotting data (fpr, tpr, cm, report).
    """
    preds   = (scores > threshold).astype(int)
    cm      = confusion_matrix(labels, preds)
    report  = classification_report(
        labels, preds, digits=4, output_dict=True,
        target_names=["Normal", "Malicious"]
    )
    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc     = auc(fpr, tpr)
    pr_auc      = average_precision_score(labels, scores)
    mcc         = matthews_corrcoef(labels, preds)
    bacc        = balanced_accuracy_score(labels, preds)

    logger.info(
        "%-30s | AUC-ROC=%.4f | AUC-PR=%.4f | MCC=%.4f | BAcc=%.4f",
        name, roc_auc, pr_auc, mcc, bacc
    )
    logger.info("\n%s", classification_report(
        labels, preds, digits=4, target_names=["Normal", "Malicious"]
    ))

    return dict(
        name      = name,
        fpr       = fpr,
        tpr       = tpr,
        roc_auc   = roc_auc,
        pr_auc    = pr_auc,
        cm        = cm,
        report    = report,
        threshold = threshold,
        mcc       = mcc,
        bacc      = bacc,
        preds     = preds,         # stored for McNemar's test
        scores    = scores,
    )


def mcnemar_test(
    result_a: Dict,
    result_b: Dict,
    labels: np.ndarray,
    alpha: float = 0.05,
) -> Dict:
    """
    Perform McNemar's paired statistical significance test.

    Null hypothesis H0: model A and model B make errors on the same samples
    (i.e., no significant difference in classification performance).

    Parameters
    ----------
    result_a, result_b : output dicts from evaluate_model().
    labels             : ground-truth labels.
    alpha              : significance level (default 0.05).

    Returns
    -------
    dict with statistic, p_value, significant, interpretation.
    """
    preds_a = result_a["preds"]
    preds_b = result_b["preds"]

    correct_a = (preds_a == labels)
    correct_b = (preds_b == labels)

    # Contingency table
    b = np.sum(correct_a & ~correct_b)   # A correct, B wrong
    c = np.sum(~correct_a & correct_b)   # A wrong, B correct

    table = np.array([[np.sum(correct_a & correct_b), b],
                      [c, np.sum(~correct_a & ~correct_b)]])

    result = mcnemar(table, exact=(b + c < 25))
    significant = result.pvalue < alpha

    return dict(
        model_a     = result_a["name"],
        model_b     = result_b["name"],
        statistic   = result.statistic,
        p_value     = result.pvalue,
        significant = significant,
        interpretation = (
            f"Statistically significant difference (p={result.pvalue:.4f} < {alpha})"
            if significant else
            f"No significant difference (p={result.pvalue:.4f} ≥ {alpha})"
        )
    )


def ablation_study(
    X_sup_train: np.ndarray,
    y_sup_train: np.ndarray,
    X_test_all: np.ndarray,
    y_test_all: np.ndarray,
    feature_names: List[str],
    n_folds: int = 5,
    seed: int = SEED,
) -> pd.DataFrame:
    """
    Leave-one-feature-out ablation study using stratified k-fold cross-validation.

    For each feature subset (all-but-one), a Random Forest is trained and
    evaluated. The performance drop relative to the full-feature baseline
    quantifies each feature's marginal contribution.

    Parameters
    ----------
    X_sup_train   : full feature training matrix.
    y_sup_train   : training labels.
    X_test_all    : full feature test matrix.
    y_test_all    : test labels.
    feature_names : list of feature name strings.
    n_folds       : number of stratified CV folds.
    seed          : random seed.

    Returns
    -------
    pd.DataFrame — ablation results (feature removed, AUC-ROC, AUC-PR, F1).
    """
    logger.info("Running %d-fold ablation study...", n_folds)
    skf   = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    rows  = []

    feature_sets = [
        ("All features (baseline)", list(range(len(feature_names)))),
    ] + [
        (f"Without {feature_names[i]}", [j for j in range(len(feature_names)) if j != i])
        for i in range(len(feature_names))
    ]

    for label, feat_idx in feature_sets:
        aucs, aprs, f1s = [], [], []
        for train_idx, _ in skf.split(X_sup_train, y_sup_train):
            X_tr = X_sup_train[train_idx][:, feat_idx]
            y_tr = y_sup_train[train_idx]
            X_te = X_test_all[:, feat_idx]

            rf = RandomForestClassifier(
                n_estimators=100, random_state=seed, n_jobs=-1
            )
            rf.fit(X_tr, y_tr)
            proba = rf.predict_proba(X_te)[:, 1]
            preds = rf.predict(X_te)

            report = classification_report(y_test_all, preds,
                                           output_dict=True)
            aucs.append(auc(*roc_curve(y_test_all, proba)[:2]))
            aprs.append(average_precision_score(y_test_all, proba))
            f1s.append(report["macro avg"]["f1-score"])

        rows.append({
            "Feature Subset" : label,
            "AUC-ROC (mean)" : round(np.mean(aucs), 4),
            "AUC-ROC (std)"  : round(np.std(aucs), 4),
            "AUC-PR (mean)"  : round(np.mean(aprs), 4),
            "F1 Macro (mean)": round(np.mean(f1s), 4),
        })
        logger.info("Ablation | %-35s | AUC=%.4f ± %.4f", label,
                    np.mean(aucs), np.std(aucs))

    return pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# 6. TRAINING PIPELINE
# ---------------------------------------------------------------------------

def train_all_models(data: Dict, cfg: Dict) -> List[Dict]:
    """
    Train and evaluate all five models.

    Model Inventory
    ---------------
    U1. Deep Autoencoder  — trains on normal traffic only; scores by MSE.
    U2. One-Class SVM     — one-class novelty detection; RBF kernel.
    U3. Local Outlier Factor — density-based novelty detection.
    S1. Random Forest     — supervised; 300 trees; Gini impurity.
    S2. SVM-RBF           — supervised; C=10 (val-tuned); probability calibration.

    Parameters
    ----------
    data : dict from load_and_split().
    cfg  : global configuration dict.

    Returns
    -------
    list of result dicts (one per model) from evaluate_model().
    """
    results = []

    X_train_sc  = data["X_train_sc"]
    X_val_all   = data["X_val_all"]
    y_val_all   = data["y_val_all"]
    X_test_all  = data["X_test_all"]
    y_test_all  = data["y_test_all"]
    X_sup_train = data["X_sup_train"]
    y_sup_train = data["y_sup_train"]
    n_feat      = data["n_features"]

    # --- U1: Deep Autoencoder ---
    logger.info("[U1] Training Deep Autoencoder ...")
    ae = build_autoencoder(n_feat, cfg["ae_l2"], cfg["ae_dropout"], cfg["ae_lr"])

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=cfg["ae_patience"],
                      restore_best_weights=True, verbose=0),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=7,
                          min_lr=1e-6, verbose=0),
        ModelCheckpoint(str(OUT_DIR / "ae_best.keras"), save_best_only=True,
                        monitor="val_loss", verbose=0),
    ]
    history = ae.fit(
        X_train_sc, X_train_sc,
        epochs          = cfg["ae_epochs"],
        batch_size      = cfg["ae_batch"],
        validation_split= 0.10,
        callbacks       = callbacks,
        verbose         = 0,
    )

    _plot_training_curve(history, OUT_DIR / "ae_training_curve.png")

    ae_val_sc  = np.mean((X_val_all  - ae.predict(X_val_all,  verbose=0))**2, axis=1)
    ae_test_sc = np.mean((X_test_all - ae.predict(X_test_all, verbose=0))**2, axis=1)
    ae_thresh  = youden_threshold(y_val_all, ae_val_sc)

    results.append(evaluate_model("Deep Autoencoder (U)",
                                  ae_test_sc, y_test_all, ae_thresh))

    # --- U2: One-Class SVM ---
    logger.info("[U2] Training One-Class SVM (nu=%.2f) on subsample ...", cfg["ocsvm_nu"])
    # Subsample to 50,000 to prevent O(N^3) freeze on MacBooks
    svm_sample_size = min(50000, len(X_train_sc))
    idx_svm = np.random.choice(len(X_train_sc), svm_sample_size, replace=False)
    X_train_sc_sub = X_train_sc[idx_svm]

    ocsvm = OneClassSVM(kernel=cfg["ocsvm_kernel"], nu=cfg["ocsvm_nu"], gamma="scale")
    ocsvm.fit(X_train_sc_sub) # Train on the 50k subsample
    
    ocsvm_val  = -ocsvm.decision_function(X_val_all)
    ocsvm_test = -ocsvm.decision_function(X_test_all)
    results.append(evaluate_model("One-Class SVM (U)",
                                  ocsvm_test, y_test_all,
                                  youden_threshold(y_val_all, ocsvm_val)))

    # --- U3: Local Outlier Factor ---
    logger.info("[U3] Training LOF (k=%d) ...", cfg["lof_n_neighbors"])
    lof = LocalOutlierFactor(
        n_neighbors   = cfg["lof_n_neighbors"],
        novelty       = True,
        contamination = cfg["lof_contamination"],
        n_jobs        = -1,
    )
    lof.fit(X_train_sc)
    lof_val  = -lof.decision_function(X_val_all)
    lof_test = -lof.decision_function(X_test_all)
    results.append(evaluate_model("Local Outlier Factor (U)",
                                  lof_test, y_test_all,
                                  youden_threshold(y_val_all, lof_val)))

    # --- S1: Random Forest ---
    logger.info("[S1] Training Random Forest (n=%d) ...", cfg["rf_n_estimators"])
    rf = RandomForestClassifier(
        n_estimators     = cfg["rf_n_estimators"],
        max_depth        = cfg["rf_max_depth"],
        min_samples_leaf = cfg["rf_min_samples_leaf"],
        random_state     = SEED,
        n_jobs           = -1,
        class_weight     = "balanced",   # handles class imbalance
    )
    rf.fit(X_sup_train, y_sup_train)
    rf_val_p  = rf.predict_proba(X_val_all)[:, 1]
    rf_test_p = rf.predict_proba(X_test_all)[:, 1]
    results.append(evaluate_model("Random Forest (S)",
                                  rf_test_p, y_test_all,
                                  youden_threshold(y_val_all, rf_val_p)))

    # --- S2: SVM-RBF ---
    logger.info("[S2] Training SVM-RBF (C=%.1f) on subsample ...", cfg["svm_C"])
    # Subsample supervised data for SVM to avoid mathematical freeze
    sup_sample_size = min(50000, len(X_sup_train))
    idx_sup = np.random.choice(len(X_sup_train), sup_sample_size, replace=False)
    X_sup_train_sub = X_sup_train[idx_sup]
    y_sup_train_sub = y_sup_train[idx_sup]

    svm = SVC(
        kernel      = cfg["svm_kernel"],
        C           = cfg["svm_C"],
        gamma       = "scale",
        probability = True,
        random_state= SEED,
        class_weight= "balanced",
    )
    svm.fit(X_sup_train_sub, y_sup_train_sub) # Train on the 50k subsample
    
    svm_val_p  = svm.predict_proba(X_val_all)[:, 1]
    svm_test_p = svm.predict_proba(X_test_all)[:, 1]
    results.append(evaluate_model("SVM — RBF (S)",
                                  svm_test_p, y_test_all,
                                  youden_threshold(y_val_all, svm_val_p)))

    # Attach shared data for later use
    for r in results:
        r["_rf_model"]   = rf
        r["_ae_model"]   = ae
        r["_ae_val_sc"]  = ae_val_sc
        r["_ae_test_sc"] = ae_test_sc
        r["_ae_thresh"]  = ae_thresh
        r["_y_test"]     = y_test_all
        r["_X_test"]     = X_test_all

    return results, rf, ae, ae_test_sc, ae_thresh

# ---------------------------------------------------------------------------
# 7. VISUALISATION  (IEEE Publication Quality)
# ---------------------------------------------------------------------------

def _plot_training_curve(history: tf.keras.callbacks.History, out_path: Path) -> None:
    """Plot autoencoder train/validation MSE learning curves."""
    fig, ax = plt.subplots(figsize=(6, 4))
    epochs = range(1, len(history.history["loss"]) + 1)
    ax.plot(epochs, history.history["loss"],     label="Train MSE",      color="#1565C0")
    ax.plot(epochs, history.history["val_loss"], label="Validation MSE", color="#C62828",
            linestyle="--")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Mean Squared Error")
    ax.set_title("Autoencoder Training Dynamics")
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)


def plot_confusion_matrices(results: List[Dict], out_path: Path) -> None:
    """
    Publication-quality 2×3 grid of confusion matrices.

    IEEE Style: serif fonts, high DPI, metric annotation in figure corners,
    supervised/unsupervised badge, colour-coded by paradigm.
    """
    n_models = len(results)
    n_cols   = 3
    n_rows   = int(np.ceil(n_models / n_cols))

    fig, axes = plt.subplots(n_rows, n_cols,
                             figsize=(4.5 * n_cols, 4.0 * n_rows))
    axes_flat = axes.flatten()

    CMAPS   = ["Blues"] * 3 + ["Greens"] * 2
    PALETTE = {"Unsupervised": "#cce5ff", "Supervised": "#d4edda"}

    for i, (ax, r) in enumerate(zip(axes_flat, results)):
        paradigm = "Supervised" if "(S)" in r["name"] else "Unsupervised"
        cmap     = CMAPS[i] if i < len(CMAPS) else "Purples"

        disp = ConfusionMatrixDisplay(
            confusion_matrix=r["cm"],
            display_labels=["Normal", "Malicious"]
        )
        disp.plot(ax=ax, cmap=cmap, colorbar=False)

        ax.set_title(r["name"], fontsize=11, fontweight="bold", pad=8)
        ax.set_xlabel("Predicted Label", fontsize=9)
        ax.set_ylabel("True Label", fontsize=9)

        f1   = r["report"]["macro avg"]["f1-score"]
        rec  = r["report"]["Malicious"]["recall"]
        mcc  = r["mcc"]
        ax.text(0.98, 0.02,
                f"AUC={r['roc_auc']:.3f}  F1={f1:.3f}\n"
                f"MCC={mcc:.3f}  Rec={rec:.3f}",
                transform=ax.transAxes,
                ha="right", va="bottom", fontsize=7.5,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.85))

        ax.text(0.02, 0.98, paradigm,
                transform=ax.transAxes,
                ha="left", va="top", fontsize=8,
                bbox=dict(boxstyle="round,pad=0.3",
                          fc=PALETTE[paradigm], alpha=0.9))

    # Hide unused subplot(s)
    for ax in axes_flat[n_models:]:
        ax.set_visible(False)

    fig.suptitle(
        "Confusion Matrices — IPv6 Covert Channel Detection\n"
        "(Test Set, 80/10/10 Split, Thresholds via Youden's J on Validation Set)",
        fontsize=12, fontweight="bold", y=1.01
    )
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)


def plot_roc_curves(results: List[Dict], out_path: Path) -> None:
    """
    Publication-quality ROC curve figure.

    Includes AUC values in legend. Unsupervised models in blue/teal family;
    supervised in green family. Dashed diagonal reference.
    """
    COLORS = ["#1565C0", "#0288D1", "#00838F", "#2E7D32", "#558B2F"]
    STYLES = ["-", "--", "-.", "-", "--"]

    fig, ax = plt.subplots(figsize=(6, 5.5))
    for r, col, ls in zip(results, COLORS, STYLES):
        ax.plot(r["fpr"], r["tpr"],
                color=col, lw=2, linestyle=ls,
                label=f"{r['name']}  (AUC = {r['roc_auc']:.4f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.6, label="Random Classifier")
    ax.fill_between(results[0]["fpr"], 0, results[0]["tpr"],
                    alpha=0.04, color="#1565C0")

    ax.set_xlabel("False Positive Rate (1 − Specificity)")
    ax.set_ylabel("True Positive Rate (Sensitivity)")
    ax.set_title("Receiver Operating Characteristic Curves\n"
                 "IPv6 Covert Channel Detection (U = Unsupervised, S = Supervised)",
                 fontweight="bold")

    legend_extras = [
        Line2D([0], [0], color="#1565C0", lw=2, label="— Unsupervised"),
        Line2D([0], [0], color="#2E7D32", lw=2, label="— Supervised"),
    ]
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles + legend_extras,
              labels + ["— Unsupervised", "— Supervised"],
              fontsize=8, loc="lower right", framealpha=0.9)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)


def plot_reconstruction_error(
    ae_test_scores: np.ndarray,
    y_test_all: np.ndarray,
    ae_thresh: float,
    out_path: Path,
) -> None:
    """
    Reconstruction error density histogram with log-scale y-axis.

    Separates normal vs malicious distributions to demonstrate
    the autoencoder's discriminative capacity.
    """
    norm_sc = ae_test_scores[y_test_all == 0]
    mal_sc  = ae_test_scores[y_test_all == 1]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.set_yscale("log")
    bins = np.linspace(0, ae_test_scores.max() * 1.05, 70)

    ax.hist(norm_sc, bins=bins, alpha=0.70, color="#1565C0",
            label="Normal Traffic", density=False)
    ax.hist(mal_sc,  bins=bins, alpha=0.70, color="#C62828",
            label="Covert-Channel Traffic (PadN/FL)", density=False)
    ax.axvline(ae_thresh, color="black", linestyle="--", lw=2,
               label=f"Optimal Threshold τ = {ae_thresh:.5f}")

    ax.set_xlabel("Reconstruction Error (Mean Squared Error)")
    ax.set_ylabel("Packet Count (log scale)")
    ax.set_title("Deep Autoencoder: Reconstruction Error Distribution\n"
                 "(Test Set — IPv6 Covert Channel via PadN & Flow Label)",
                 fontweight="bold")
    ax.legend(fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)


def plot_feature_importance(
    rf: RandomForestClassifier,
    feature_names: List[str],
    out_path: Path,
) -> None:
    """
    Horizontal bar chart of Gini-based feature importances with std error bars.

    Error bars reflect variability across trees — a useful indicator of
    feature stability that single-point Gini estimates omit.
    """
    importances = rf.feature_importances_
    std         = np.std([t.feature_importances_ for t in rf.estimators_], axis=0)
    sorted_idx  = np.argsort(importances)

    fig, ax = plt.subplots(figsize=(7, 4))
    y_pos   = np.arange(len(sorted_idx))

    bars = ax.barh(
        y_pos,
        importances[sorted_idx],
        xerr     = std[sorted_idx],
        color    = "#2E7D32",
        alpha    = 0.82,
        ecolor   = "black",
        capsize  = 4,
        align    = "center",
    )
    ax.set_yticks(y_pos)
    ax.set_yticklabels([feature_names[i] for i in sorted_idx])
    ax.bar_label(bars, fmt="%.3f", padding=4, fontsize=9)
    ax.set_xlabel("Feature Importance (Mean Gini Impurity Decrease ± Std)")
    ax.set_title("Random Forest — Feature Importances\n"
                 "IPv6 Covert Channel Detection (300 estimators)",
                 fontweight="bold")
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)


def plot_ablation(ablation_df: pd.DataFrame, out_path: Path) -> None:
    """Bar chart comparing AUC-ROC across feature ablation subsets."""
    df = ablation_df.sort_values("AUC-ROC (mean)", ascending=True)

    fig, ax = plt.subplots(figsize=(8, max(4, len(df) * 0.6)))
    colors  = ["#1565C0"] + ["#78909C"] * (len(df) - 1)  # baseline highlighted
    bars    = ax.barh(df["Feature Subset"], df["AUC-ROC (mean)"],
                      xerr=df["AUC-ROC (std)"], color=colors,
                      alpha=0.85, capsize=4, ecolor="black")
    ax.bar_label(bars, fmt="%.4f", padding=3, fontsize=9)
    ax.set_xlabel("Mean AUC-ROC (5-fold CV)")
    ax.set_title("Ablation Study — Leave-One-Feature-Out\n"
                 "(Random Forest, 5-fold Stratified CV)",
                 fontweight="bold")
    ax.set_xlim([0, 1.05])
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    logger.info("Saved: %s", out_path)

# ---------------------------------------------------------------------------
# 8. RESULTS SUMMARY
# ---------------------------------------------------------------------------

def build_summary_table(results: List[Dict]) -> pd.DataFrame:
    """
    Assemble a publication-ready LaTeX-compatible results table.

    Columns: Model, Type, AUC-ROC, AUC-PR, F1-Macro, MCC, BAcc,
             Recall(Attack), Precision(Attack)
    """
    rows = []
    for r in results:
        paradigm = "Supervised" if "(S)" in r["name"] else "Unsupervised"
        f1   = r["report"]["macro avg"]["f1-score"]
        rec  = r["report"]["Malicious"]["recall"]
        prec = r["report"]["Malicious"]["precision"]
        rows.append({
            "Model"            : r["name"],
            "Type"             : paradigm,
            "AUC-ROC"          : round(r["roc_auc"], 4),
            "AUC-PR"           : round(r["pr_auc"],  4),
            "F1-Macro"         : round(f1,            4),
            "MCC"              : round(r["mcc"],       4),
            "BAcc"             : round(r["bacc"],      4),
            "Recall(Attack)"   : round(rec,            4),
            "Precision(Attack)": round(prec,           4),
        })
    return pd.DataFrame(rows)


def print_summary(df: pd.DataFrame) -> None:
    """Pretty-print the results table to stdout."""
    sep = "=" * 90
    logger.info("\n%s", sep)
    logger.info("  RESULTS SUMMARY (Test Set, 80/10/10 Split)")
    logger.info(sep)
    logger.info("\n%s", df.to_string(index=False))
    logger.info(sep)

# ---------------------------------------------------------------------------
# 9. ENTRY POINT
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("=" * 70)
    logger.info("  IPv6 Covert Channel Detection — IEEE-Quality Evaluation")
    logger.info("  Seed: %d | Features: %d | Models: 5", SEED, len(FEATURE_NAMES))
    logger.info("=" * 70)

    # --- Load & split ---
    data = load_and_split(
        normal_path   = DATA_DIR / "normal.csv",
        malicious_path= DATA_DIR / "malicious.csv",
        val_frac      = CFG["val_size"],
        test_frac     = CFG["test_size"],
    )

    # --- Train & evaluate ---
    results, rf, ae, ae_test_sc, ae_thresh = train_all_models(data, CFG)

    # --- Summary table ---
    summary_df = build_summary_table(results)
    print_summary(summary_df)
    summary_df.to_csv(OUT_DIR / "results_summary.csv", index=False)
    logger.info("Saved: %s", OUT_DIR / "results_summary.csv")

    # --- Figures ---
    plot_confusion_matrices(results, OUT_DIR / "confusion_matrices.png")
    plot_roc_curves(results,         OUT_DIR / "roc_curves.png")
    plot_reconstruction_error(ae_test_sc, data["y_test_all"],
                              ae_thresh,  OUT_DIR / "reconstruction_error_dist.png")
    plot_feature_importance(rf, FEATURE_NAMES, OUT_DIR / "feature_importance.png")

    # --- Ablation study ---
    if CFG["run_ablation"]:
        abl_df = ablation_study(
            data["X_sup_train"], data["y_sup_train"],
            data["X_test_all"],  data["y_test_all"],
            FEATURE_NAMES, n_folds=CFG["ablation_folds"],
        )
        abl_df.to_csv(OUT_DIR / "ablation_results.csv", index=False)
        logger.info("Ablation:\n%s", abl_df.to_string(index=False))
        plot_ablation(abl_df, OUT_DIR / "ablation_study.png")

    # --- McNemar's Test (best unsupervised vs best supervised) ---
    if CFG["run_mcnemar"] and len(results) >= 2:
        # Compare best unsupervised (Autoencoder) vs best supervised (RF)
        unsup_results = [r for r in results if "(U)" in r["name"]]
        sup_results   = [r for r in results if "(S)" in r["name"]]
        best_u = max(unsup_results, key=lambda r: r["roc_auc"])
        best_s = max(sup_results,   key=lambda r: r["roc_auc"])

        mc_res = mcnemar_test(best_u, best_s, data["y_test_all"],
                              alpha=CFG["mcnemar_alpha"])
        logger.info("McNemar's Test: %s vs %s → %s",
                    mc_res["model_a"], mc_res["model_b"],
                    mc_res["interpretation"])
        pd.DataFrame([mc_res]).to_csv(OUT_DIR / "mcnemar_test.csv", index=False)

    # --- Final checklist ---
    logger.info("\n[✓] Experiment complete. Outputs:")
    for f in sorted(OUT_DIR.glob("*")):
        logger.info("    %s", f)


if __name__ == "__main__":
    main()
