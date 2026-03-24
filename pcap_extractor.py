import csv
from scapy.all import PcapReader, IPv6, IPv6ExtHdrDestOpt
# Note: We'll handle PadN by its type code (1) for maximum reliability

def extract_features_pro(pcap_filename, output_csv):
    print(f"[*] Processing: {pcap_filename}...")
    count = 0
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Flow_Label_Value", "PadN_Length"]) # Header
        
        try:
            with PcapReader(pcap_filename) as pcap_reader:
                for pkt in pcap_reader:
                    if IPv6 in pkt:
                        # 1. Extract Flow Label
                        flow_label = pkt[IPv6].fl
                        
                        # 2. Extract PadN Length
                        pad_len = 0
                        if pkt.haslayer(IPv6ExtHdrDestOpt):
                            options = pkt[IPv6ExtHdrDestOpt].options
                            for opt in options:
                                # Scapy options are usually (type, value)
                                # Type 1 is PadN, Type 0 is Pad1
                                if isinstance(opt, tuple):
                                    opt_type = opt[0]
                                    if opt_type == 1: # PadN
                                        pad_len = len(opt[1])
                                elif hasattr(opt, 'otype') and opt.otype == 1:
                                    pad_len = len(opt.optdata) if hasattr(opt, 'optdata') else 0
                        
                        # 3. Write directly to disk
                        writer.writerow([flow_label, pad_len])
                        
                        count += 1
                        # Update every 10k so you see progress on your Intel Mac
                        if count % 10000 == 0:
                            print(f"    [>] Processed {count} packets...")
                            
        except Exception as e:
            print(f"\n[!] Error at packet {count}: {e}")

    print(f"[+] Success! {count} rows saved to {output_csv}.")

if __name__ == "__main__":
    # Process your 211k real-life capture
    extract_features_pro("normal.pcap", "normal.csv")
    
    # Process your V7 malicious capture
    extract_features_pro("malicious.pcap", "malicious.csv")