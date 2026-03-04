from scapy.all import *
import csv
import sys

def extract_features_from_pcap(pcap_filename, output_csv):
    print(f"[*] Reading packet capture file: {pcap_filename}")
    try:
        packets = rdpcap(pcap_filename)
    except FileNotFoundError:
        print(f"[!] Error: File {pcap_filename} not found.")
        sys.exit(1)

    features = []
    
    print("[*] Extracting Flow Label and PadN features...")
    for pkt in packets:
        if pkt.haslayer(IPv6):
            # 1. Extract Flow Label (integer value)
            flow_label = pkt[IPv6].fl
            
            # 2. Extract PadN Length (0 if no PadN exists)
            padn_length = 0
            if pkt.haslayer(IPv6ExtHdrDestOpt):
                for opt in pkt[IPv6ExtHdrDestOpt].options:
                    if isinstance(opt, PadN):
                        # Calculate how many bytes are in the padding
                        padn_length = len(opt.optdata) if opt.optdata else 0
            
            # 3. Save as a feature row: [Flow_Label, PadN_Length]
            features.append([flow_label, padn_length])
            
    # Write the extracted mathematical features to a CSV file for the Deep Learning model
    print(f"[*] Writing {len(features)} rows to {output_csv}...")
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Flow_Label_Value", "PadN_Length"]) # Header
        writer.writerows(features)
        
    print("[+] Feature extraction complete. Data is ready for LSTM Autoencoder.")

if __name__ == "__main__":
    extract_features_from_pcap("normal.pcap", "normal.csv")
    extract_features_from_pcap("malicious.pcap", "malicious.csv")
    