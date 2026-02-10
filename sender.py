from scapy.all import *
import time 
# Basix Covert Channel Sender
def send_covert_msg(target_ip, message):
    # Ensure message has even number of chars for 16-bit chunks
    if len(message) % 2!= 0: message += " "
    
    # Split into 2-character (16-bit) chunks
    chunks = [message[i:i+2] for i in range(0, len(message), 2)]
    
    print(f"Sending '{message}' in {len(chunks)} packets...")
    
    for chunk in chunks:
        # Convert 2 chars to a 16-bit integer (because flow label only contains integers)
        val = int.from_bytes(chunk.encode(), 'big')
        
        # Inject into Flow Label (20-bit field, so 16 bits are gonna fit) 
        pkt = IPv6(dst=target_ip, fl=val) / ICMPv6EchoRequest() # Using ICMPv6 Echo Request to make it look like normal traffic ( legitimate ping )
        send(pkt, verbose=False)
        time.sleep(0.1) # Small delay to avoid flooding

if __name__ == "__main__":
    send_covert_msg("::1", "hello world") # Hello World is 11 chars, so it will be split into 6 packets (he, ll, o , wo, rl, d )