from scapy.all import IPv6, TCP, send, wrpcap
import random
import time


def generate_clean_traffic(count=10000):
    print(f"[*] Generating {count} CLEAN IPv6 packets...")
    packets = []
    
    for i in range(count):
        fl_val = random.randint(0, 1048575)
        
        pkt = IPv6(dst="::1", fl=fl_val) / TCP(dport=80, flags="S")
        packets.append(pkt)
        
        if i % 1000 == 0:
            print(f"    [>] Generated {i} packets...")

    wrpcap("normal.pcap", packets)
    print("[+] Created normal.pcap successfully!")

if __name__ == "__main__":
    generate_clean_traffic(20000) 