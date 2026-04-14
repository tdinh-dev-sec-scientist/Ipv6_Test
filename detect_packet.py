import pandas as pd
import numpy as np

def calculate_entropy(series, window=10):
    """Calculates rolling Shannon entropy to detect Flow Label manipulation."""
    def _entropy(x):
        _, counts = np.unique(x, return_counts=True)
        p = counts / counts.sum()
        return -np.sum(p * np.log2(p + 1e-9))
    return series.rolling(window, min_periods=1).apply(_entropy, raw=True)

print("[*] Loading 100% of data...")
normal_df = pd.read_csv("normal.csv")
malicious_df = pd.read_csv("malicious.csv")

# Assign True Labels (0 for Normal, 1 for Malicious)
normal_df['True_Label'] = 0
malicious_df['True_Label'] = 1

# Force PadN to be 0 for malicious traffic so it cannot be used as a clue.
# The covert channel is now entirely restricted to the Flow Label.
malicious_df['PadN_Length'] = 0 

# Combine 100% of the data into one dataset and shuffle it
combined_df = pd.concat([normal_df, malicious_df]).sample(frac=1, random_state=42).reset_index(drop=True)

# Calculate Flow Label Entropy (This is our new detection feature)
combined_df['FL_Entropy'] = calculate_entropy(combined_df['Flow_Label_Value'])

predictions = []
i = 0
total_packets = len(combined_df)

print(f"[*] Checking {total_packets} packets using a WHILE loop...")

# THE WHILE LOOP: Checking packet by packet
while i < total_packets:
    current_packet = combined_df.iloc[i]
    fl_entropy = current_packet['FL_Entropy']
    padn_len = current_packet['PadN_Length']
    
    # Catch the PRNG randomness OR the hidden PadN payload
    if fl_entropy > 2.0 or padn_len > 0:
        predictions.append(1) # Malicious!
    else:
        predictions.append(0) # Normal!
        
    i += 1 # Move to the next packet

# Save the predictions to a new file to verify
combined_df['Predicted_Label'] = predictions
output_data = combined_df[['Flow_Label_Value', 'PadN_Length', 'FL_Entropy', 'True_Label', 'Predicted_Label']]
output_data.to_csv("Test/predictions_output.csv", index=False)

print("[+] Results are saved to Test/predictions_output.csv")