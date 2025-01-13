from scapy.all import sniff

# Function to handle each captured packet
def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets from the default interface
sniff(count=10, prn=packet_callback)