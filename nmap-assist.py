import scapy.all as scapy
import socket
import os
import concurrent.futures
import re
import subprocess
import requests
from colorama import Fore, Style, init

# Initialize colorama for Windows
init(autoreset=True)

def get_local_network():
    """Automatically detect the local network range."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network_prefix = ".".join(local_ip.split(".")[:3]) + ".0/24"
    return network_prefix

def scan_network(network_range):
    """Fast ARP scan to detect active devices."""
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = [{"ip": ans[1].psrc, "mac": ans[1].hwsrc} for ans in answered_list]
    return devices

def ping_host(ip):
    """Ping a single IP address."""
    response = os.system(f"ping -n 1 -w 300 {ip} >nul 2>&1")
    return ip if response == 0 else None

def ping_sweep(network_prefix):
    """Fast ping scan using multithreading."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        ips = [f"{network_prefix}.{i}" for i in range(1, 255)]
        results = list(executor.map(ping_host, ips))
    
    return [{"ip": ip, "mac": "Unknown"} for ip in results if ip]

def get_vlan(ip):
    """Find VLAN by checking the first three octets of the IP address."""
    vlan_mapping = {
        "192.168.1": "VLAN 10 - Office",
        "192.168.2": "VLAN 20 - Guests",
        "192.168.3": "VLAN 30 - Servers",
    }
    ip_prefix = ".".join(ip.split(".")[:3])
    return vlan_mapping.get(ip_prefix, "Unknown VLAN")

def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup to get hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_mac_vendor(mac_address):
    """Find the vendor of a MAC address using an online API."""
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown Vendor"

def run_nmap_scan(ip):
    """Run Nmap with -sV for service detection and format the output."""
    print(f"\n{Fore.CYAN}Scanning {ip} for open ports, OS, and services...{Style.RESET_ALL}\n")
    try:
        nmap_output = subprocess.run(["nmap", "-O", "-sV", ip], capture_output=True, text=True).stdout
    except Exception as e:
        print(f"{Fore.RED}Error running Nmap: {e}{Style.RESET_ALL}")
        return

    # Extract OS details
    os_match = re.search(r"OS details: (.+)", nmap_output)
    os_detected = os_match.group(1) if os_match else f"{Fore.RED}Unknown{Style.RESET_ALL}"

    # Extract open ports and services
    ports = re.findall(r"(\d+/tcp)\s+open\s+([\w-]+)\s+([\w\d\.-]+)?", nmap_output)

    # Extract network distance
    distance_match = re.search(r"Network Distance: (\d+) hops", nmap_output)
    network_distance = distance_match.group(1) if distance_match else f"{Fore.RED}Unknown{Style.RESET_ALL}"

    # Find VLAN info
    vlan_info = get_vlan(ip)

    # Get hostname (reverse DNS)
    hostname = reverse_dns_lookup(ip)

    # Display results in a clean format with colors
    print(f"{Fore.GREEN}[+] IP Address    : {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Hostname      : {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] OS Detected   : {Fore.YELLOW}{os_detected}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] VLAN          : {Fore.BLUE}{vlan_info}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Network Distance : {Fore.YELLOW}{network_distance} hops{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Open Ports:{Style.RESET_ALL}")
    for port, service, version in ports:
        version_info = f"({version})" if version else ""
        print(f"    {Fore.YELLOW}- {port} : {service} {version_info}{Style.RESET_ALL}")

# User selects scanning method
print(f"{Fore.CYAN}Select Network Scan Method:{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[1] Auto-detect and scan the local network{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[2] Enter network range manually (e.g., 192.168.1.0/24){Style.RESET_ALL}")
print(f"{Fore.YELLOW}[3] Scan a single IP immediately{Style.RESET_ALL}")
choice = input("Enter option (1, 2, or 3): ").strip()

if choice == "1":
    network_range = get_local_network()
    print(f"\n{Fore.CYAN}Scanning network: {network_range} ...{Style.RESET_ALL}")
    devices = scan_network(network_range)

elif choice == "2":
    network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
    print(f"\n{Fore.CYAN}Scanning network: {network_range} ...{Style.RESET_ALL}")
    devices = scan_network(network_range)

elif choice == "3":
    single_ip = input("Enter the IP address to scan: ").strip()
    run_nmap_scan(single_ip)
    exit()

else:
    print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
    exit()

# If scanning a network, process results
if not devices:
    print(f"\n{Fore.YELLOW}No devices detected using ARP scan. Trying fast ping sweep...{Style.RESET_ALL}")
    network_prefix = ".".join(network_range.split(".")[:3])
    devices = ping_sweep(network_prefix)

# Display results
if devices:
    print(f"\n{Fore.GREEN}Detected Devices:{Style.RESET_ALL}")
    for idx, device in enumerate(devices, 1):
        vlan_info = get_vlan(device["ip"])
        hostname = reverse_dns_lookup(device["ip"])
        mac_vendor = get_mac_vendor(device["mac"])
        print(f"{Fore.CYAN}Client [{idx}]:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}IP       : {Fore.YELLOW}{device['ip']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}MAC      : {Fore.YELLOW}{device['mac']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Vendor   : {Fore.CYAN}{mac_vendor}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Hostname : {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}VLAN     : {Fore.BLUE}{vlan_info}{Style.RESET_ALL}")
    
    # Allow user to see more info on a client
    selected = input(f"\n{Fore.CYAN}Enter client number to get more details (or press Enter to exit): {Style.RESET_ALL}").strip()
    if selected.isdigit():
        selected = int(selected)
        if 1 <= selected <= len(devices):
            client_ip = devices[selected - 1]["ip"]
            run_nmap_scan(client_ip)  # Run detailed scan
        else:
            print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
else:
    print(f"\n{Fore.RED}No active devices found.{Style.RESET_ALL}")
