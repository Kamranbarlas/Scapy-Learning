import nmap
import argparse

# Function to discover hosts in the network
def discover_hosts(ip_range):
    nm = nmap.PortScanner()
    print(f"[+] Discovering hosts in range: {ip_range}")
    
    # Perform ping sweep
    nm.scan(hosts=ip_range, arguments='-sn', timeout=5)
    
    devices = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            devices.append({
                'ip': host,
                'mac': nm[host]['addresses'].get('mac', 'Unknown')
            })
    return devices

# Function to perform port scanning
def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    print(f"[+] Scanning ports on {ip}...")
    
    # Specify ports to scan
    ports_range = ','.join(map(str, ports))
    nm.scan(hosts=ip, ports=ports_range, arguments='-sS', timeout=5)

    open_ports = []
    for port in ports:
        if str(port) in nm[ip]['tcp'] and nm[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

# Main function
def main():
    parser = argparse.ArgumentParser(description="Nmap-like Scanner using python-nmap")
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
        open_ports = scan_ports(device['ip'], ports)
        if open_ports:
            print(f"    Open ports on {device['ip']}: {', '.join(map(str, open_ports))}")
        else:
            print(f"    No open ports found on {device['ip']}.")

if __name__ == "__main__":
    main()
