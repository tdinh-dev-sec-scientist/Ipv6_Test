from scapy.all import *

# Define the target and the secret data
target_ip = "::1"
secret_msg = b"SECRET MESSAGE"
# The Flow Label is a 20-bit field (max value 0xFFFFF)
# I use this because it's 'supposed' to be
# pseudo-random, making secret data look like normal traffic.
secret_flow_label = 0xABCDE

# Craft the base IPv6 Header
# 'fl' sets the 20-bit Flow Label field
ipv6_header = IPv6(dst=target_ip, fl=secret_flow_label)

# Add an Extension Header (Destination Options)
# 'PadN' to hide additional bytes of data
extension_header = IPv6ExtHdrDestOpt(options= [PadN(optdata=secret_msg)])

#Combine with a standard ICMPv6 Echo Request (Ping)
packet = ipv6_header / extension_header / ICMPv6EchoRequest()

# Display the packet structure to verify the fields
packet.show()

# Send the packet onto the network
send(packet)