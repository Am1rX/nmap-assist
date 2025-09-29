# Network Scanner (ntscan)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A comprehensive network scanning tool that combines ARP scanning, ping sweeps, and detailed Nmap scanning capabilities to discover and analyze devices on your network.

## Features

- 🔍 Auto-detect and scan local networks
- 🌐 Manual network range scanning
- 📍 Single IP detailed scanning
- ⚡ Fast device discovery using ARP and ping sweeps
- 🔎 Detailed port and service detection using Nmap
- 📱 MAC vendor identification
- 🏷️ VLAN detection
- 🖥️ OS detection
- 🔄 Reverse DNS lookups

## Requirements

### Python Dependencies
Install the required Python packages using:
```bash
pip install -r requirements.txt
```

### System Requirements
- Python 3.6 or higher
- Nmap (must be installed separately)
- Administrator/root privileges (required for ARP scanning)

### Installing Nmap
- **Windows**: Download and install from [Nmap's official website](https://nmap.org/download.html)
- **Linux**: `sudo apt-get install nmap` (Ubuntu/Debian) or `sudo yum install nmap` (CentOS/RHEL)
- **macOS**: `brew install nmap` (using Homebrew)

## Usage

1. Run the script:
```bash
python nmap-assist.py
```

2. Choose from three scanning options:
   - [1] Auto-detect and scan the local network
   - [2] Enter network range manually (e.g., 192.168.1.0/24)
   - [3] Scan a single IP immediately

3. View results including:
   - IP addresses
   - MAC addresses
   - Vendor information
   - Hostnames
   - VLAN information
   - Open ports
   - Running services
   - OS detection

## Security Note

This tool is intended for network administrators and security professionals to scan networks they own or have permission to test. Unauthorized scanning of networks may be illegal in your jurisdiction.

## Features in Detail

### Network Discovery
- ARP scanning for fast device discovery
- Fallback to ping sweep if ARP scan fails
- Multi-threaded scanning for improved performance

### Device Information
- Hostname resolution through reverse DNS
- MAC address vendor lookup
- VLAN detection and categorization
- Network distance measurement

### Service Detection
- Port scanning
- Service version detection
- Operating system fingerprinting
- Detailed service information

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is open source and available under the MIT License.

## 📝 Author

Created with ❤️ by **AMIRX**
