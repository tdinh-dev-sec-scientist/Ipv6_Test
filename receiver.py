from scapy.all import *
import sys
import random

# --- V7 ACADEMIC CONFIGURATION ---
INTERFACE = "lo0"          # Use lo if using Linux
ENCRYPTION_KEY = 0x55      
TARGET_IP = "::1"          
SEED_VAL = 1114
SYNC_ID = 0xFFFFF          # Maximum 20-bit Flow Label value used as a Burst-Sync trigger

random.seed(SEED_VAL)
cmd_buffer = ""

def process_packet(pkt):
    global cmd_buffer
    
    # 1. Broad filter: Catch IPv6 packets carrying TCP to port 443
    if pkt.haslayer(IPv6) and pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        
        flow_label = pkt[IPv6].fl
        
        # 2. Catch the Burst-Sync signal to reset the PRNG
        if flow_label == SYNC_ID:
            random.seed(SEED_VAL)
            cmd_buffer = ""
            return
            
        # 3. Cryptographic Authenticator: Check if Flow Label matches our PRNG sequence
        prng_state = random.getstate()
        expected_magic = random.randint(0, 0xFFFFE) # Reserve FFFFF for SYNC
        
        if flow_label == expected_magic:
            # 4. If authenticated, inspect the Extension Header for the payload
            if pkt.haslayer(IPv6ExtHdrDestOpt):
                for opt in pkt[IPv6ExtHdrDestOpt].options:
                    if isinstance(opt, PadN):
                        covert_data = opt.optdata
                        
                        if covert_data:
                            # 5. Extract and Decrypt the distributed payload
                            encrypted_byte = covert_data[0] if isinstance(covert_data, bytes) else covert_data
                            if type(encrypted_byte) is str:
                                encrypted_byte = ord(encrypted_byte)
                                
                            decrypted_char = chr(encrypted_byte ^ ENCRYPTION_KEY)
                            
                            if decrypted_char == ";":
                                # End of transmission signal
                                print(f"\n[+] Transmission received successfully: {cmd_buffer}")
                                cmd_buffer = ""
                            else:
                                cmd_buffer += decrypted_char
                                sys.stdout.write(decrypted_char)
                                sys.stdout.flush()
                                
                            break # Ignore Scapy's automatic 8-byte alignment padding
        else:
            # Not our packet, rollback the PRNG state to prevent desynchronization
            random.setstate(prng_state)

if __name__ == "__main__":
    print("==================================================")
    print(" Academic Receiver: Distributed Steganography  ")
    print(" Tracking Flow Labels & PadN Extension Headers    ")
    print("==================================================")
    print(f"[*] Active on {INTERFACE} - Sniffing for stealth TCP SYN traffic...\n")
    
    sniff(filter="ip6", prn=process_packet, store=0, iface=INTERFACE)
