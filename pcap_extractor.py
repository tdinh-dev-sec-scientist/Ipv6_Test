from scapy.all import PcapReader, IPv6, IPv6ExtHdrDestOpt, PadN
import csv

def extract_features_pro(pcap_filename, output_csv):
    print(f"[*] Processing LARGE file: {pcap_filename}...")
    count = 0
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Flow_Label_Value", "PadN_Length"]) # Header
        
        with PcapReader(pcap_filename) as pcap_reader:
            for pkt in pcap_reader:
                if pkt.haslayer(IPv6):
                    # 1. Extract Flow Label
                    flow_label = pkt[IPv6].fl
                    
                    # 2. Extract PadN Length
                    pad_len = 0
                    if pkt.haslayer(IPv6ExtHdrDestOpt):
                        for opt in pkt[IPv6ExtHdrDestOpt].options:
                            if isinstance(opt, PadN):
                                pad_len = len(opt.optdata) if opt.optdata else 0
                    
                    # 3. directly write in CSV to free m
                    writer.writerow([flow_label, pad_len])
                    
                    count += 1
                    if count % 100000 == 0:
                        print(f"    [>] Processed {count} packets...")

    print(f"[+] Done! Extracted {count} rows to {output_csv}.")

if __name__ == "__main__":
    # Xử lý từng file một
    extract_features_pro("normal.pcap", "normal.csv")
    extract_features_pro("malicious.pcap", "malicious.csv")