import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.metrics import roc_curve, auc, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import random

# ===============================
# 1. Reproducibility
# ===============================
np.random.seed(42)
tf.random.set_seed(42)
random.seed(42)

print("[*] Loading datasets...")
normal_data = pd.read_csv("normal.csv")
malicious_data = pd.read_csv("malicious.csv")

X_normal = normal_data[['Flow_Label_Value', 'PadN_Length']].values
X_malicious = malicious_data[['Flow_Label_Value', 'PadN_Length']].values

# ===============================
# 2. Protocol-aware normalization
# ===============================
print("[*] Normalizing data (Protocol-based scaling)...")

# IPv6 constraints:
# Flow Label: 20-bit (max = 1048575)
# PadN option length: max = 255
scale_factors = np.array([1048575.0, 255.0])

X_normal_scaled = X_normal / scale_factors
X_malicious_scaled = X_malicious / scale_factors

# ===============================
# 3. Build Deep Autoencoder
# ===============================
print("[*] Building Deep Autoencoder...")

model = Sequential([
    Input(shape=(2,)),
    Dense(32, activation='relu'),
    Dense(16, activation='relu'),
    Dense(8, activation='relu'),   # Bottleneck
    Dense(16, activation='relu'),
    Dense(32, activation='relu'),
    Dense(2, activation='linear')
])

model.compile(optimizer='adam', loss='mse')

# Early stopping for better generalization
early_stop = EarlyStopping(
    monitor='val_loss',
    patience=5,
    restore_best_weights=True
)

print("[*] Training on Normal Traffic (Baseline Learning)...")
model.fit(
    X_normal_scaled,
    X_normal_scaled,
    epochs=50,
    batch_size=32,
    validation_split=0.1,
    callbacks=[early_stop],
    verbose=1
)

# ===============================
# 4. Compute Reconstruction Errors
# ===============================
print("[*] Evaluating Traffic...")

pred_normal = model.predict(X_normal_scaled)
pred_malicious = model.predict(X_malicious_scaled)

mse_normal = np.mean(np.power(X_normal_scaled - pred_normal, 2), axis=1)
mse_malicious = np.mean(np.power(X_malicious_scaled - pred_malicious, 2), axis=1)

# Combine for evaluation
errors = np.concatenate([mse_normal, mse_malicious])
labels = np.concatenate([
    np.zeros(len(mse_normal)),   # 0 = Normal
    np.ones(len(mse_malicious))  # 1 = Attack
])

# ===============================
# 5. ROC Curve + AUC
# ===============================
fpr, tpr, thresholds = roc_curve(labels, errors)
roc_auc = auc(fpr, tpr)

# Optimal threshold (Youden’s J statistic)
optimal_idx = np.argmax(tpr - fpr)
optimal_threshold = thresholds[optimal_idx]

print(f"[+] AUC Score: {roc_auc:.4f}")
print(f"[+] Optimal Threshold (ROC-based): {optimal_threshold:.6f}")

# ===============================
# 6. Classification Metrics
# ===============================
predictions = (errors > optimal_threshold).astype(int)

cm = confusion_matrix(labels, predictions)
print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(labels, predictions, digits=4))

# ===============================
# 7. Histogram Visualization
# ===============================
print("[*] Generating Reconstruction Error Distribution Graph...")

plt.figure(figsize=(10, 6))
plt.yscale('log')

all_data_max = max(errors)
bins = np.linspace(0, all_data_max, 50)

plt.hist([mse_normal, mse_malicious],
         bins=bins,
         label=['Normal Traffic', 'Covert PadN Traffic'])

plt.axvline(optimal_threshold,
            color='black',
            linestyle='dashed',
            linewidth=2,
            label='Detection Threshold (ROC-Optimized)')

plt.title("Reconstruction Error Distribution for IPv6 Covert Channel Detection")
plt.xlabel("Reconstruction Error (Mean Squared Error)")
plt.ylabel("Number of Packets (Log Scale)")
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("reconstruction_error_distribution.png")
plt.show()

# ===============================
# 8. ROC Curve Visualization
# ===============================
print("[*] Generating ROC Curve...")

plt.figure(figsize=(6, 6))
plt.plot(fpr, tpr)
plt.plot([0, 1], [0, 1], linestyle='--')
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title(f"ROC Curve (AUC = {roc_auc:.4f})")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("roc_curve.png")
plt.show()