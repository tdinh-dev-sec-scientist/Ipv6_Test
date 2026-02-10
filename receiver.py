from scapy.all import *
import os
# Basic Covert Channel Receiver
def process_packet(pkt):
    # Check if it's an IPv6 packet with a Flow Label
    if pkt.haslayer(IPv6):
        # Extract 16-bit data from the Flow Label
        val = pkt[IPv6].fl
        if val == 0: return # Skip packets without labels
        
        try:
            # Convert back to characters, because we encoded 2 chars into a 16-bit integer, we can decode it back to get the original message chunk
            chunk = val.to_bytes(2, 'big').decode()
            print(f"Received Chunk: {chunk}")
            
            # TRIGGER OS API: If the message matches a command, execute it
            # Example: If we receive a packet with 'calc' (0x63616C63), open calculator
            if "cl" in chunk: # Simplified trigger for the demo
                print("Triggering OS API: Launching System Notification...")
                os.system("echo 'Covert Command Received' | wall") # Mac/Linux API call
        except:
            pass

if __name__ == "__main__":
    print("Ghost-Receiver listening for covert signals...")
    # Listen on loopback for testing, change iface for real network, iface will be 'lo' if using Linux.
    sniff(filter="ip6 and icmp6", prn=process_packet, store=0, iface="lo0") 