# from scapy.all import ARP, Ether, srp

# # Define the target IP range
# target_ip = "192.168.200.0/24" 

# # Create ARP request
# arp = ARP(pdst=target_ip)
# ether = Ether(dst="00:90:27:e1:c7:3b")
# packet = ether/arp

# # Send packet and get response
# result = srp(packet, timeout=5, verbose=False)[0]

# # Extract IPs and MACs from responses
# devices = []
# for sent, received in result:
#     devices.append({'ip': received.psrc, 'mac': received.hwsrc})

# # Print discovered devices
# for device in devices:
#     print(f"IP: {device['ip']}, MAC: {device['mac']}")


# from scapy.all import ARP, Ether, srp

# target_ip = "192.168.200.0/24"
# arp = ARP(pdst=target_ip)
# ether = Ether(dst="00:90:27:e1:c7:3b")
# packet = ether/arp

# result = srp(packet, timeout=2, verbose=False)[0]

# for sent, received in result:
#     print(received.summary())


from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import argparse

# Function to perform ARP-based host discovery
def discover_hosts(ip_range):
    print(f"[+] Discovering hosts in range: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp

    # Send the ARP request and capture responses
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Function to perform port scanning on a host
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            # Send RST to close the open connection
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
    return open_ports

# Main function
def main():
    parser = argparse.ArgumentParser(description="Scapy-based Nmap-like Scanner")
    parser.add_argument("ip_range", help="Target IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", type=str, default="22,80,443", help="Comma-separated list of ports to scan (default: 22,80,443)")

    args = parser.parse_args()
    ip_range = args.ip_range
    ports = [int(port) for port in args.ports.split(",")]

    # Step 1: Discover active hosts
    devices = discover_hosts(ip_range)
    if not devices:
        print("[-] No active hosts discovered.")
        return

    print(f"[+] Found {len(devices)} active host(s):")
    for device in devices:
        print(f"    IP: {device['ip']}, MAC: {device['mac']}")

    # Step 2: Scan ports on discovered hosts
    for device in devices:
        print(f"\n[+] Scanning ports on {device['ip']}...")
        open_ports = scan_ports(device['ip'], ports)
        if open_ports:
            print(f"    Open ports: {', '.join(map(str, open_ports))}")
        else:
            print("    No open ports found.")

if __name__ == "__main__":
    main()
