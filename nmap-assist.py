import scapy.all as scapy
import socket
import os
import ctypes
import re
import subprocess
import requests
from colorama import Fore, Style, init

# Initialize colorama for Windows
init(autoreset=True)

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_local_networks():
    """
    Automatically detect all local network ranges from all available network interfaces.
    Returns a list of network ranges (e.g., ['192.168.1.0/24', '10.0.5.0/24']).
    """
    networks = set()
    try:
        # This method gets all IP addresses associated with the local hostname,
        # which is effective for finding IPs on all interfaces.
        _, _, ipaddrlist = socket.gethostbyname_ex(socket.gethostname())
        for ip in ipaddrlist:
            # Ignore loopback address
            if not ip.startswith("127."):
                network_prefix = ".".join(ip.split(".")[:3]) + ".0/24"
                networks.add(network_prefix)
    except socket.gaierror:
        print(f"{Fore.YELLOW}Could not resolve hostname to get all IPs. Falling back to an alternative method.{Style.RESET_ALL}")

    # Fallback method if the primary one fails
    if not networks:
        try:
            # Create a dummy socket to determine the primary outbound IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(('8.8.8.8', 80))  # Connect to a public DNS server
            local_ip = s.getsockname()[0]
            s.close()
            # Ignore loopback address
            if not local_ip.startswith("127."):
                network_prefix = ".".join(local_ip.split(".")[:3]) + ".0/24"
                networks.add(network_prefix)
        except Exception:
            print(f"{Fore.RED}Failed to automatically determine any network. Please enter it manually.{Style.RESET_ALL}")

    return list(networks)

def scan_network(network_range):
    """Fast ARP scan to detect active devices."""
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = [{"ip": ans[1].psrc, "mac": ans[1].hwsrc} for ans in answered_list]
    return devices

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
    if not mac_address or mac_address == "Unknown":
        return "N/A"
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown Vendor"

def run_nmap_scan(ip):
    """Run a faster Nmap scan for service and OS detection, and format the output."""
    print(f"\n{Fore.CYAN}Scanning {ip} for open ports, services, and OS...{Style.RESET_ALL}")
    
    scan_type = "-sS"  # Default to fast SYN scan
    if not is_admin():
        print(f"{Fore.YELLOW}Warning: Not running as admin. Nmap will fall back to a slower TCP connect scan.{Style.RESET_ALL}")
        # Nmap automatically falls back from -sS to -sT if it lacks privileges, so no command change is needed,
        # but the warning is important for the user.

    print(f"{Fore.YELLOW}Note: OS detection is enabled. This will make the scan slower.{Style.RESET_ALL}\n")
    try:
        # Optimized scan: -O for OS detection, -sS (fastest, needs admin), --version-light, -T4, -n (no DNS)
        nmap_command = ["nmap", scan_type, "-O", "--version-light", "-T4", "-n", "--max-retries", "1", ip]
        nmap_output = subprocess.run(
            nmap_command, 
            capture_output=True, text=True, check=True
        ).stdout
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Nmap is not installed or not in your system's PATH.{Style.RESET_ALL}")
        return
    except subprocess.CalledProcessError as e:
        # Provide more specific feedback if Nmap fails due to privileges
        if "requires root privileges" in e.stderr or "TCP/IP fingerprinting" in e.stderr:
             print(f"{Fore.RED}Nmap scan failed. This type of scan requires Administrator/root privileges.{Style.RESET_ALL}")
        else:
             print(f"{Fore.RED}Error running Nmap scan on {ip}:{Style.RESET_ALL}\n{e.stderr}")
        return
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred during Nmap scan: {e}{Style.RESET_ALL}")
        return

    os_match = re.search(r"OS details: (.+)", nmap_output)
    os_detected = os_match.group(1) if os_match else f"{Fore.YELLOW}Could not be determined{Style.RESET_ALL}"

    ports = re.findall(r"(\d+/tcp)\s+open\s+([\w\-\.]+)\s+(.*)", nmap_output)
    
    distance_match = re.search(r"Network Distance: (\d+) hops?", nmap_output)
    network_distance = distance_match.group(1) if distance_match else f"{Fore.YELLOW}Unknown{Style.RESET_ALL}"

    vlan_info = get_vlan(ip)
    hostname = reverse_dns_lookup(ip)

    print(f"{Fore.GREEN}[+] IP Address     : {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Hostname       : {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] OS Detected    : {Fore.YELLOW}{os_detected}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] VLAN           : {Fore.BLUE}{vlan_info}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Network Distance: {Fore.YELLOW}{network_distance} hops{Style.RESET_ALL}")
    if ports:
        print(f"{Fore.GREEN}[+] Open Ports:{Style.RESET_ALL}")
        for port, service, version in ports:
            version_info = version.strip()
            print(f"    {Fore.YELLOW}  - {port:<10} : {service} {version_info}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Open Ports     : {Fore.YELLOW}No open TCP ports found.{Style.RESET_ALL}")

# --- Main Execution ---

print(f"{Fore.CYAN}Select Network Scan Method:{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[1] Auto-detect and scan all local networks{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[2] Enter network range manually (e.g., 192.168.1.0/24){Style.RESET_ALL}")
print(f"{Fore.YELLOW}[3] Scan a single IP immediately{Style.RESET_ALL}")
choice = input("Enter option (1, 2, or 3): ").strip()

networks_to_scan = []
if choice == "1":
    networks_to_scan = get_local_networks()
    if not networks_to_scan:
        print(f"{Fore.RED}Could not detect any local networks to scan. Exiting.{Style.RESET_ALL}")
        exit()
    print(f"\n{Fore.CYAN}Detected networks to scan: {', '.join(networks_to_scan)}{Style.RESET_ALL}")

elif choice == "2":
    network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
    networks_to_scan.append(network_range)

elif choice == "3":
    single_ip = input("Enter the IP address to scan: ").strip()
    run_nmap_scan(single_ip)
    exit()

else:
    print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
    exit()

if not networks_to_scan:
    print(f"\n{Fore.YELLOW}No valid networks to scan. Exiting.{Style.RESET_ALL}")
    exit()

# --- Start Scanning Process (ARP Scan Only) ---
all_devices_dict = {}
host_ips = set()
try:
    _, _, host_ips_list = socket.gethostbyname_ex(socket.gethostname())
    host_ips.update(host_ips_list)
except socket.gaierror:
    print(f"{Fore.YELLOW}Warning: Could not get host's own IPs. The host might be listed in scan results.{Style.RESET_ALL}")

# Check for admin rights for scapy, as it's often needed for ARP scans
if not is_admin():
    print(f"\n{Fore.YELLOW}Warning: Script not run as admin. ARP scan may be incomplete.{Style.RESET_ALL}")

for network_range in networks_to_scan:
    print(f"\n{Fore.MAGENTA}--- Scanning Network: {network_range} ---{Style.RESET_ALL}")
    
    # ARP Scan (The only discovery method)
    print(f"{Fore.CYAN}Running ARP scan to discover devices...{Style.RESET_ALL}")
    try:
        devices_found_arp = scan_network(network_range)
        count = 0
        for device in devices_found_arp:
            if device['ip'] not in all_devices_dict:
                all_devices_dict[device['ip']] = device
                count += 1
        print(f"{Fore.GREEN}ARP scan found {count} new device(s).{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}ARP scan on {network_range} failed. This can happen without admin rights. Error: {e}{Style.RESET_ALL}")

# Convert dict to list WITHOUT filtering
final_devices = list(all_devices_dict.values())

# 3. Display results
if final_devices:
    try:
        final_devices.sort(key=lambda d: socket.inet_aton(d['ip']))
    except socket.error:
        print(f"{Fore.YELLOW}Warning: Could not sort IP addresses.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}--- Detected Devices ({len(final_devices)} total across all networks) ---{Style.RESET_ALL}")
    for idx, device in enumerate(final_devices, 1):
        vlan_info = get_vlan(device["ip"])
        hostname = reverse_dns_lookup(device["ip"])
        mac_vendor = get_mac_vendor(device["mac"])
        
        # Add a marker if the device is the host machine
        is_host_marker = f" {Fore.MAGENTA}(This is you){Style.RESET_ALL}" if device['ip'] in host_ips else ""
        
        print(f"{Fore.CYAN}Client [{idx}]{is_host_marker}:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}IP       : {Fore.YELLOW}{device['ip']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}MAC      : {Fore.YELLOW}{device['mac']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Vendor   : {Fore.CYAN}{mac_vendor}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Hostname : {Fore.YELLOW}{hostname}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}VLAN     : {Fore.BLUE}{vlan_info}{Style.RESET_ALL}")
    
    while True:
        selected_input = input(f"\n{Fore.CYAN}Enter client number for a detailed Nmap scan (or press Enter to exit): {Style.RESET_ALL}").strip()
        if not selected_input:
            break
        if selected_input.isdigit():
            selected_idx = int(selected_input)
            if 1 <= selected_idx <= len(final_devices):
                client_ip = final_devices[selected_idx - 1]["ip"]
                run_nmap_scan(client_ip)
            else:
                print(f"{Fore.RED}Invalid selection. Please enter a number between 1 and {len(final_devices)}.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
else:
    print(f"\n{Fore.RED}No active devices found on the scanned networks.{Style.RESET_ALL}")
