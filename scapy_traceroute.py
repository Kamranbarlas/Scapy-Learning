from scapy.all import traceroute

# Perform traceroute to a target
traceroute(["8.8.8.8"], maxttl=20)
