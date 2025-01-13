from scapy.all import IP, ICMP, send

# Craft an ICMP packet
packet = IP(dst="8.8.8.8")/ICMP()

# Send the packet
import pdb;pdb.set_trace()
send(packet)
