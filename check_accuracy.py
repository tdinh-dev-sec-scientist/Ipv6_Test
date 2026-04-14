import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("      COVERT CHANNEL ACCURACY CHECKER    ")
print("=========================================")

# Load the output from Script 1
df = pd.read_csv("Test/predictions_output.csv")

# Extract the true answers and your script's guesses
true_labels = df['True_Label']
predicted_labels = df['Predicted_Label']

# Calculate Metrics
accuracy = accuracy_score(true_labels, predicted_labels)
cm = confusion_matrix(true_labels, predicted_labels)

print(f"\n[*] Overall Accuracy: {accuracy * 100:.2f}%")

print("\n[*] Confusion Matrix:")
print(f"    True Normal predicted as Normal (Good): {cm[0][0]}")
print(f"    True Normal predicted as Malicious (False Alarm): {cm[0][1]}")
print(f"    True Malicious predicted as Normal (Missed Attack): {cm[1][0]}")
print(f"    True Malicious predicted as Malicious (Caught it!): {cm[1][1]}")

print("\n[*] Detailed Report:")
print(classification_report(true_labels, predicted_labels, target_names=["Normal", "Malicious"]))